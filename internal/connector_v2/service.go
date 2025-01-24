package connectorv2

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/gob"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/device/connector_server"
	"github.com/borderzero/border0-cli/internal/device/handlers"
	"github.com/borderzero/border0-cli/internal/device/utils/debouncer"
	"github.com/borderzero/border0-cli/internal/device/utils/ipfw"
	"github.com/borderzero/border0-cli/internal/device/utils/nat"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-cli/internal/device/wg/endpoint"
	"github.com/borderzero/border0-cli/internal/device/wgmgr"
	"github.com/borderzero/border0-cli/internal/httpproxylib"
	"github.com/borderzero/border0-cli/internal/sqlauthproxy"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/connector_v2/cmds"
	"github.com/borderzero/border0-cli/internal/connector_v2/config"
	"github.com/borderzero/border0-cli/internal/connector_v2/errors"
	"github.com/borderzero/border0-cli/internal/connector_v2/logger"
	"github.com/borderzero/border0-cli/internal/connector_v2/plugin"
	"github.com/borderzero/border0-cli/internal/connector_v2/upstreamdata"
	"github.com/borderzero/border0-cli/internal/connector_v2/util"
	device_config "github.com/borderzero/border0-cli/internal/device/config"
	deviceServer "github.com/borderzero/border0-cli/internal/device/server"
	device_state "github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/k8sapilib"
	"github.com/borderzero/border0-cli/internal/ssh"
	sshConfig "github.com/borderzero/border0-cli/internal/ssh/config"
	"github.com/borderzero/border0-cli/internal/ssh/server"

	b0Util "github.com/borderzero/border0-cli/internal/util"
	"github.com/borderzero/border0-cli/internal/util/refresher"
	"github.com/borderzero/border0-cli/internal/vpnlib"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/types/connector"
	"github.com/borderzero/border0-go/types/service"
	"github.com/borderzero/border0-proto/common"
	pb "github.com/borderzero/border0-proto/connector"
	backoff "github.com/cenkalti/backoff/v4"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	gossh "golang.org/x/crypto/ssh"
)

const (
	defaultWgPort = 32442

	backoffMaxInterval = 1 * time.Hour
	serviceConfigPath  = "/etc/border0/"
	sshHostKeyFile     = "ssh_host_ecdsa_key"

	initOpConstBackoffInterval      = 500 * time.Millisecond
	initOpConstBackoffRetries       = 2 // 3 attempts total
	wgmrWaitTimeout                 = 10 * time.Second
	inboundMessageChannelBufferSize = 50

	stateFileName = "device.state.yaml"

	cleanupIdAnnounceGoingAway  = "announce_going_away"
	cleanupIdCloseStatsListener = "close_stats_listener"
	cleanupIdCleanupNatRules    = "cleanup_nat_rules"
)

type ConnectorService struct {
	config                   *config.Configuration
	logger                   *zap.Logger
	backoff                  *backoff.ExponentialBackOff
	version                  string
	context                  context.Context
	stream                   pb.ConnectorService_ControlStreamClient
	heartbeatInterval        int
	state                    state
	requests                 sync.Map
	organization             *models.Organization
	discoveryResultChan      chan *plugin.PluginDiscoveryResults
	sshPrivateHostKey        *gossh.Signer
	sshPrivateHostKeyLock    sync.Mutex
	connectorCertificateLock sync.Mutex
	connectorCertificate     *tls.Certificate
	privateNetworkEnabled    bool
	deviceState              device_state.State
	wgmr                     wgmgr.WireGuardManager
	peerMap                  endpoint.Mapping
	cleanups                 map[string]func()
	natMgr                   nat.NATManager
	wgmrReady                bool
}

func NewConnectorService(
	l *zap.Logger,
	version string,
	config *config.Configuration,
) *ConnectorService {
	natMgr, err := nat.NewManager(l)
	if err != nil {
		l.Error("failed to create NAT manager", zap.Error(err))
	}

	cs := &ConnectorService{
		config:              config,
		version:             version,
		heartbeatInterval:   10,
		state:               newState(),
		discoveryResultChan: make(chan *plugin.PluginDiscoveryResults, 100),
		cleanups:            make(map[string]func()),
		natMgr:              natMgr,
	}

	cs.logger = logger.NewConnectorLogger(l, cs.sendControlStreamRequest)

	state, err := device_state.Load(cs.logger, filepath.Join(filepath.Dir(config.ConfigPath), stateFileName))
	if err == nil {
		cs.deviceState = state
	} else {
		cs.logger.Error("failed to load device state file", zap.Error(err))
	}

	return cs
}

func (c *ConnectorService) cleanupNatRules() {
	_, _, devicesCIDRv4, devicesCIDRv6, _, _ := c.deviceState.GetNetworkIPs()
	ifaces := c.deviceState.GetManagedInterfaces()

	for _, iface := range ifaces {
		if err := c.natMgr.CleanupIPv4NAT(devicesCIDRv4, iface); err != nil {
			c.logger.Warn("failed to cleanup NAT rules for IPv4", zap.Error(err))
		}
		if err := c.natMgr.CleanupIPv6NAT(devicesCIDRv6, iface); err != nil {
			c.logger.Warn("failed to cleanup NAT rules for IPv6", zap.Error(err))
		}
	}
}

func (c *ConnectorService) Start(outerCtx context.Context) {
	c.logger.Info("starting the connector service")

	// NOTE(@adrianosela): We don't use the outer context as the parent
	// context of the inner context because cleanup requires the GRPC
	// control stream to still be usable.
	// We *MUST* use a fresh context here.
	innerCtx, stop := context.WithCancel(context.Background())
	defer stop()

	defer func() {
		for _, cleanup := range c.cleanups {
			cleanup()
		}

		// allow some time for cleanup to settle... In particular, we have
		// seen that if a cleanup sends a GRPC message, this may not be
		// received correctly server side if we exit here without this delay.
		time.Sleep(time.Millisecond * 250)
	}()

	c.context = innerCtx
	go c.StartControlStream(stop)
	go c.handleDiscoveryResult(innerCtx)

	// We block here until either the outer context is cancelled e.g. SIGINT/SIGTERM/SIGSTOP
	// or the inner context is cancelled e.g. fatal logic error, server requested shutdown, etc.
	// Cleanups will be executed immediately after the end of the function, followed by stop()
	// which will stop the control stream and discovery result routines if they are still running.
	select {
	case <-outerCtx.Done():
		c.logger.Info("top level context cancelled... shutting down connector...", zap.Error(outerCtx.Err()))
	case <-innerCtx.Done():
		c.logger.Info("connector service context cancelled (shutdown likely requested by Border0 API)... shutting down connector...", zap.Error(innerCtx.Err()))
	}
}

func (c *ConnectorService) StartControlStream(stop context.CancelFunc) {
	defer stop()

	c.backoff = backoff.NewExponentialBackOff()
	c.backoff.MaxElapsedTime = 0
	c.backoff.MaxInterval = backoffMaxInterval

	if err := backoff.Retry(c.controlStream, c.backoff); err != nil {
		c.logger.Error("error in control stream", zap.Error(err))
	}
}

func (c *ConnectorService) heartbeat(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(c.heartbeatInterval) * time.Second):
			if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{RequestType: &pb.ControlStreamRequest_Heartbeat{Heartbeat: &common.HeartbeatMessage{}}}); err != nil {
				c.logger.Error("failed to send heartbeat", zap.Error(err))
			}
		}
	}
}

func (c *ConnectorService) handleResponse(requestID string, response *pb.ControlStreamResponse, loggerFields ...zapcore.Field) {
	loggerFields = append(loggerFields, zap.String("request_id", requestID))

	// load request metadata
	v, ok := c.requests.Load(requestID)
	if !ok {
		c.logger.Error("invalid request id", loggerFields...)
		return
	}

	// extract response channel from request metadata
	responseChan, ok := v.(chan *pb.ControlStreamResponse)
	if !ok {
		c.logger.Error("failed to cast response channel", loggerFields...)
		return
	}

	// set up protection against writing to closed channel
	defer func() {
		if r := recover(); r != nil {
			c.logger.Warn(
				"recovered from api response processing failure",
				append(
					loggerFields,
					zap.String("hint", "api response likely took too long and is no longer being waited for"),
					zap.Any("msg", r),
				)...,
			)
		}
	}()

	select {
	case responseChan <- response:
	// there is a small (but nonzero!) chance that the API replied before the response channel (which
	// is unbuffered) could be listened to, so we allow for some additional time before giving up.
	case <-time.After(time.Second * 1):
		c.logger.Error("failed to process response from api (response processing queue is full or not ready)", loggerFields...)
	}
}

func (c *ConnectorService) controlStream() error {
	ctx, cancel := context.WithCancel(c.context)
	defer cancel()

	defer func() {
		c.logger.Debug("control stream closed", zap.Duration("next retry", c.backoff.NextBackOff()))
	}()

	grpcConn, err := c.newConnectorClient()
	if err != nil {
		c.logger.Error("failed to setup connection", zap.Error(err))
		return fmt.Errorf("failed to create connector client: %w", err)
	}

	defer grpcConn.Close()

	stream, err := pb.NewConnectorServiceClient(grpcConn).ControlStream(c.context)
	if err != nil {
		c.logger.Error("failed to setup control stream", zap.Error(err))
		return fmt.Errorf("failed to create control stream: %w", err)
	}

	c.stream = stream

	defer func() { c.stream = nil }()
	go c.heartbeat(ctx)
	go c.uploadConnectorMetadata(ctx)

	fatalErrChan := make(chan error)
	msgChan := make(chan struct {
		response *pb.ControlStreamResponse
		error    error
	}, inboundMessageChannelBufferSize)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				msg, err := stream.Recv()
				msgChan <- struct {
					response *pb.ControlStreamResponse
					error    error
				}{msg, err}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			err := stream.CloseSend()
			if err != nil {
				return backoff.Permanent(fmt.Errorf("failed to close control stream: %w", err))
			}

			return nil
		case err := <-fatalErrChan:
			return err
		case msg := <-msgChan:
			if msg.error != nil {
				statusErr, ok := status.FromError(msg.error)
				if ok && statusErr.Code() == codes.Canceled && statusErr.Message() == "connector deleted" {
					return backoff.Permanent(fmt.Errorf("connector was deleted"))
				}

				c.logger.Error("failed to receive message", zap.Error(msg.error))
				return msg.error
			}

			go func() {
				switch r := msg.response.GetRequestType().(type) {
				case *pb.ControlStreamResponse_ConnectorConfig:
					if err := c.handleConnectorConfig(r.ConnectorConfig); err != nil {
						c.logger.Error("failed to handle connector config", zap.Error(err))
					}
				case *pb.ControlStreamResponse_Init:
					if err := c.handleInit(r.Init); err != nil {
						c.logger.Error("failed to handle init", zap.Error(err))
						fatalErrChan <- fmt.Errorf("failed to handle init: %w", err)
					}
				case *pb.ControlStreamResponse_UpdateConfig:
					switch t := r.UpdateConfig.GetConfigType().(type) {
					case *pb.UpdateConfig_PluginConfig:
						retryFunc := func() error {
							if err := c.handlePluginConfig(r.UpdateConfig.GetAction(), r.UpdateConfig.GetPluginConfig()); err != nil {
								return err
							}
							return nil
						}
						backoffPolicy := backoff.WithMaxRetries(backoff.NewConstantBackOff(initOpConstBackoffInterval), initOpConstBackoffRetries)
						if err := backoff.Retry(retryFunc, backoffPolicy); err != nil {
							c.logger.Error(
								fmt.Sprintf("failed to handle plugin %s (%d attempts)", r.UpdateConfig.GetAction().String(), initOpConstBackoffRetries+1),
								zap.String("plugin_id", r.UpdateConfig.GetPluginConfig().GetId()),
								zap.Error(err),
							)
						}
					case *pb.UpdateConfig_SocketConfig:
						retryFunc := func() error {
							if err := c.handleSocketConfig(r.UpdateConfig.GetAction(), r.UpdateConfig.GetSocketConfig()); err != nil {
								return err
							}
							return nil
						}
						backoffPolicy := backoff.WithMaxRetries(backoff.NewConstantBackOff(initOpConstBackoffInterval), initOpConstBackoffRetries)
						if err := backoff.Retry(retryFunc, backoffPolicy); err != nil {
							c.logger.Error(
								fmt.Sprintf("failed to handle socket %s (%d attempts)", r.UpdateConfig.GetAction().String(), initOpConstBackoffRetries+1),
								zap.String("socket_id", r.UpdateConfig.GetSocketConfig().GetId()),
								zap.Error(err),
							)
						}
					default:
						c.logger.Error("unknown config type", zap.Any("type", t))
					}
				case *pb.ControlStreamResponse_TunnelCertificateSignResponse:
					c.handleResponse(
						r.TunnelCertificateSignResponse.GetRequestId(),
						msg.response,
						zap.String("request_type", "tunnel_certificate_signing_request"),
					)
				case *pb.ControlStreamResponse_SshCertificateSignResponse:
					c.handleResponse(
						r.SshCertificateSignResponse.GetRequestId(),
						msg.response,
						zap.String("request_type", "ssh_certificate_signing_request"),
					)
				case *pb.ControlStreamResponse_Heartbeat:
				case *pb.ControlStreamResponse_Stop:
					c.logger.Info("stopping connector as requested by server")
					fatalErrChan <- backoff.Permanent(nil)
				case *pb.ControlStreamResponse_Disconnect:
					c.logger.Info("disconnecting connector as requested by server")
					err := stream.CloseSend()
					if err != nil {
						fatalErrChan <- fmt.Errorf("failed to close control stream: %w", err)
					}
					fatalErrChan <- fmt.Errorf("connector was disconnected by server")
				case *pb.ControlStreamResponse_Authorize:
					c.handleResponse(
						r.Authorize.GetRequestId(),
						msg.response,
						zap.String("request_type", "authorize_request"),
					)
				case *pb.ControlStreamResponse_CertificateSignResponse:
					c.handleResponse(
						r.CertificateSignResponse.GetRequestId(),
						msg.response,
						zap.String("request_type", "certificate_signing_request"),
					)
				case *pb.ControlStreamResponse_NetworkState:
					if err := c.waitForWireguardManager(); err != nil {
						c.logger.Error("wireguard is not ready", zap.Error(err))
						return
					}
					if err := handlers.HandleNetworkStateMessage(c.logger, c.deviceState, c.wgmr, r.NetworkState); err != nil {
						c.logger.Error("failed to configure wireguard peers", zap.Error(err))
						return
					}
					c.logger.Info("re-configured wireguard peers successfully")
				case *pb.ControlStreamResponse_PeerOnline:
					if err := c.waitForWireguardManager(); err != nil {
						c.logger.Error("wireguard is not ready", zap.Error(err))
						return
					}
					if err := handlers.HandlePeerOnlineMessage(c.logger, c.deviceState, c.wgmr, msg.response.GetPeerOnline()); err != nil {
						c.logger.Error("failed to add wireguard peer", zap.Error(err))
						return
					}
					c.logger.Info("added wireguard peer successfully")
				case *pb.ControlStreamResponse_PeerOffline:
					if err := c.waitForWireguardManager(); err != nil {
						c.logger.Error("wireguard is not ready", zap.Error(err))
						return
					}
					if err := handlers.HandlePeerOfflineMessage(c.logger, c.deviceState, c.peerMap, c.wgmr, msg.response.GetPeerOffline()); err != nil {
						c.logger.Error("failed to remove wireguard peer", zap.Error(err))
						return
					}
					c.logger.Info("removed wireguard peer successfully")
				case *pb.ControlStreamResponse_Session:
					c.handleResponse(
						r.Session.GetRequestId(),
						msg.response,
						zap.String("request_type", "session_request"),
					)
				default:
					c.logger.Error("unknown message type", zap.Any("type", r))
				}
			}()
		}
	}
}

func (c *ConnectorService) waitForWireguardManager() error {
	if c.wgmrReady {
		return nil
	}

	ctx, cancel := context.WithTimeout(c.context, wgmrWaitTimeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if c.wgmrReady {
				return nil
			}
		}
	}
}

func (c *ConnectorService) newConnectorClient() (*grpc.ClientConn, error) {
	ccsOpts := []CredentialOption{
		WithToken(c.config.Token),
		WithInsecureTransport(c.config.ConnectorInsecureTransport),
	}
	if c.config.ConnectorId != "" {
		ccsOpts = append(ccsOpts, WithConnectorId(c.config.ConnectorId))
	}

	if c.deviceState != nil {
		ccsOpts = append(ccsOpts, WithPublicKey(c.deviceState.GetPublicKey().B64()))
	}

	grpcOpts := []grpc.DialOption{
		grpc.WithPerRPCCredentials(NewConnectorControlStreamCredentials(ccsOpts...)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	if c.config.ConnectorInsecureTransport {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	c.logger.Info("connecting to connector server", zap.String("server", c.config.ConnectorServer))

	// TODO: grpc.DialContext is deprecated, use grpc.NewClient instead
	client, err := grpc.DialContext(c.context, c.config.ConnectorServer, grpcOpts...)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (c *ConnectorService) handleConnectorConfig(config *pb.ConnectorConfig) error {
	c.heartbeatInterval = int(config.GetHeartbeatInterval())
	c.privateNetworkEnabled = config.GetPrivateNetworkEnabled()
	return nil
}

func (c *ConnectorService) handleInit(init *pb.Init) error {
	connectorConfig := init.GetConnectorConfig()
	pluginConfig := init.GetPlugins()
	socketConfg := init.GetSockets()

	if connectorConfig == nil {
		return fmt.Errorf("init message is missing required fields")
	}

	c.heartbeatInterval = int(connectorConfig.GetHeartbeatInterval())
	c.privateNetworkEnabled = connectorConfig.GetPrivateNetworkEnabled()

	if c.privateNetworkEnabled && c.wgmr == nil {
		// set the cleanup
		c.cleanups[cleanupIdAnnounceGoingAway] = func() {
			if err := c.announce(false, nil, nil); err != nil {
				c.logger.Error("failed to announce final (un)discoverability message", zap.Error(err))
				return
			}
		}
		config, err := device_config.GetConfiguration()
		if err != nil {
			return fmt.Errorf("failed to load device management configuration: %v", err)
		}

		if err := c.deviceState.
			SetDeviceID(init.GetDeviceId()).
			SetNetworkIPs(
				init.GetSelfIpv4(),
				init.GetSelfIpv6(),
				init.GetNetworkCidrV4(),
				init.GetNetworkCidrV6(),
				init.GetNetworkResourcesCidrV4(),
				init.GetNetworkResourcesCidrV6(),
			).
			Commit(); err != nil {
			c.logger.Error("failed to save network IPs in state file", zap.Error(err))
		}

		wgmr, err := c.initPrivateNetwork(config)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("failed to initialize border0 network: %v", err))
		}
		c.wgmr = wgmr
		c.wgmrReady = true

		// ensure NAT rules
		_, _, devicesCIDRv4, devicesCIDRv6, _, _ := c.deviceState.GetNetworkIPs()
		if err := c.natMgr.SetupIPv4NAT(devicesCIDRv4, config.ManagedNetworkingInterfaceName); err != nil {
			c.logger.Error("failed to set up NAT for IPv4", zap.Error(err))
		}
		if err := c.natMgr.SetupIPv6NAT(devicesCIDRv6, config.ManagedNetworkingInterfaceName); err != nil {
			c.logger.Error("failed to set up NAT for IPv6", zap.Error(err))
		}

		// Add NAT cleanup function if private network is enabled
		c.cleanups[cleanupIdCleanupNatRules] = func() { c.cleanupNatRules() }

		// ensure IP forwarding is enabled
		ipfwmgr := ipfw.NewManager(c.logger)
		if err := ipfwmgr.SetupIPv4Forwarding(); err != nil {
			c.logger.Error("failed to set up IP forwarding for IPv4", zap.Error(err))
		}
		if err := ipfwmgr.SetupIPv6Forwarding(); err != nil {
			c.logger.Error("failed to set up IP forwarding for IPv6", zap.Error(err))
		}

		if err := c.wgmr.Start(); err != nil {
			return backoff.Permanent(fmt.Errorf("failed to start border0 network: %v", err))
		}

		l, err := deviceServer.GetHTTPListener()
		if err == nil {
			c.cleanups[cleanupIdCloseStatsListener] = func() { defer l.Close() }
			go func() {
				cserver := connector_server.New(c.logger, c.wgmr, c.deviceState, c.version)
				if err := cserver.Serve(l); err != nil && err != http.ErrServerClosed {
					c.logger.Error("stats HTTP server error", zap.Error(err))
				}
			}()
		} else {
			c.logger.Error("failed to initialize stats HTTP server over unix socket", zap.Error(err))
		}
	}

	certificates := make(map[string]string)
	if err := util.AsStruct(connectorConfig.Organization.Certificates, &certificates); err != nil {
		return fmt.Errorf("failed to parse organization certificates: %w", err)
	}

	c.organization = &models.Organization{
		Certificates: certificates,
	}

	initMessagePlugins := set.New[string]()

	for _, config := range pluginConfig {
		initMessagePlugins.Add(config.GetId())

		var action pb.Action
		if _, ok := c.state.GetPlugin(config.GetId()); ok {
			action = pb.Action_UPDATE
		} else {
			action = pb.Action_CREATE
		}

		retryFunc := func() error {
			if err := c.handlePluginConfig(action, config); err != nil {
				return fmt.Errorf("failed to handle plugin configuration: %w", err)
			}
			return nil
		}
		backoffPolicy := backoff.WithMaxRetries(backoff.NewConstantBackOff(initOpConstBackoffInterval), initOpConstBackoffRetries)

		if err := backoff.Retry(retryFunc, backoffPolicy); err != nil {
			c.logger.Error(
				fmt.Sprintf("failed to initialize/update plugin during connector initialization (%d attempts)", initOpConstBackoffRetries+1),
				zap.String("plugin_id", config.GetId()),
				zap.Error(err),
			)
		}
	}
	for _, id := range c.state.GetPluginIDs() {
		if !initMessagePlugins.Has(id) {
			retryFunc := func() error {
				if err := c.handlePluginConfig(pb.Action_DELETE, &pb.PluginConfig{Id: id}); err != nil {
					return fmt.Errorf("failed to handle plugin config: %w", err)
				}
				return nil
			}
			backoffPolicy := backoff.WithMaxRetries(backoff.NewConstantBackOff(initOpConstBackoffInterval), initOpConstBackoffRetries)

			if err := backoff.Retry(retryFunc, backoffPolicy); err != nil {
				c.logger.Error(
					fmt.Sprintf("failed to remove plugin during connector initialization (%d attempts)", initOpConstBackoffRetries+1),
					zap.String("plugin_id", id),
					zap.Error(err),
				)
			}
		}
	}

	initMessageSocket := set.New[string]()

	for _, config := range socketConfg {
		initMessageSocket.Add(config.GetId())

		var action pb.Action
		if _, ok := c.state.GetSocket(config.GetId()); ok {
			action = pb.Action_UPDATE
		} else {
			action = pb.Action_CREATE
		}

		retryFunc := func() error {
			if err := c.handleSocketConfig(action, config); err != nil {
				return fmt.Errorf("failed to handle socket configuration: %w", err)
			}
			return nil
		}
		backoffPolicy := backoff.WithMaxRetries(backoff.NewConstantBackOff(initOpConstBackoffInterval), initOpConstBackoffRetries)

		if err := backoff.Retry(retryFunc, backoffPolicy); err != nil {
			c.logger.Error(
				fmt.Sprintf("failed to initialize/update socket during connector initialization (%d attempts)", initOpConstBackoffRetries+1),
				zap.String("plugin_id", config.GetId()),
				zap.Error(err),
			)
		}
	}
	for _, id := range c.state.GetSocketIDs() {
		if !initMessageSocket.Has(id) {
			retryFunc := func() error {
				if err := c.handleSocketConfig(pb.Action_DELETE, &pb.SocketConfig{Id: id}); err != nil {
					return fmt.Errorf("failed to handle socket configuration: %w", err)
				}
				return nil
			}
			backoffPolicy := backoff.WithMaxRetries(backoff.NewConstantBackOff(initOpConstBackoffInterval), initOpConstBackoffRetries)

			if err := backoff.Retry(retryFunc, backoffPolicy); err != nil {
				c.logger.Error(
					fmt.Sprintf("failed to remove socket during connector initialization (%d attempts)", initOpConstBackoffRetries+1),
					zap.String("plugin_id", id),
					zap.Error(err),
				)
			}
		}
	}

	c.backoff.Reset()

	return nil
}

func (c *ConnectorService) initPrivateNetwork(config *device_config.Configuration) (wgmgr.WireGuardManager, error) {
	c.peerMap = endpoint.NewMapping()

	statsmgr := stats.NewManager(c.logger)
	go statsmgr.Push(
		c.context,
		time.Minute, // push once a minute
		func(counters *stats.Delta) error {
			c.logger.Debug(
				"pushing metrics now",
				zap.Uint64("bytes_in", counters.BytesIn),
				zap.Uint64("bytes_out", counters.BytesOut),
				zap.Uint64("packets_in", counters.PacketsIn),
				zap.Uint64("packets_out", counters.PacketsOut),
			)
			return c.sendControlStreamRequest(&pb.ControlStreamRequest{
				RequestType: &pb.ControlStreamRequest_Stats{
					Stats: &common.StatsMessage{
						StatsMessageType: &common.StatsMessage_NetworkDeviceStats{
							NetworkDeviceStats: &common.NetworkDeviceStatsMessage{
								BytesIn:    counters.BytesIn,
								BytesOut:   counters.BytesOut,
								PacketsIn:  counters.PacketsIn,
								PacketsOut: counters.PacketsOut,
							},
						},
					},
				},
			})
		},
	)

	announceChan := debouncer.NewDebouncer(time.Millisecond*500, func(a *wgmgr.DiscoverabilityAnnouncement) {
		if err := c.announce(a.Discoverable, a.UDP4Address, a.UDP6Address); err != nil {
			c.logger.Error("failed to announce discoverability (in debouncer)", zap.Error(err))
		}
	})

	wgPort := defaultWgPort
	if wgPortOverride := strings.TrimSpace(os.Getenv("BORDER0_WG_BIND_PORT")); wgPortOverride != "" {
		wgPortOverrideInt64, err := strconv.ParseInt(wgPortOverride, 10, 16)
		if err != nil {
			c.logger.Error(
				"failed to parse port in BORDER0_WG_BIND_PORT as a 16 bit integer",
				zap.String("BORDER0_WG_BIND_PORT", wgPortOverride),
				zap.Error(err),
			)
		} else {
			wgPort = int(wgPortOverrideInt64)
		}
	}

	return wgmgr.New(
		c.logger,
		c.deviceState,
		statsmgr,
		c.peerMap,
		config.ManagedNetworkingInterfaceName,
		config.RelayURL,
		announceChan,
		true,
		wgPort,
	)
}

func (c *ConnectorService) handlePluginConfig(action pb.Action, config *pb.PluginConfig) error {
	var innerConfig *connector.PluginConfiguration
	if err := util.AsStruct(config.GetConfig(), &innerConfig); err != nil {
		return fmt.Errorf("failed to decode plugin configuration: %v", err)
	}

	switch action {
	case pb.Action_CREATE:
		c.logger.Info("initializing plugin", zap.String("plugin", config.GetId()))

		if _, ok := c.state.GetPlugin(config.GetId()); ok {
			return fmt.Errorf("plugin already exists")
		}

		p, err := plugin.NewPlugin(c.context, c.logger, config.GetId(), config.GetType(), innerConfig)
		if err != nil {
			return fmt.Errorf("failed to register plugin: %w", err)
		}

		go p.Start(c.context, c.discoveryResultChan)

		c.state.SetPlugin(config.GetId(), p)
	case pb.Action_UPDATE:
		c.logger.Info("updating plugin", zap.String("plugin", config.GetId()))

		p, ok := c.state.GetPlugin(config.GetId())
		if !ok {
			return fmt.Errorf("plugin does not exist")
		}

		if err := p.Stop(); err != nil {
			return fmt.Errorf("failed to stop plugin: %w", err)
		}

		p, err := plugin.NewPlugin(c.context, c.logger, config.GetId(), config.GetType(), innerConfig)
		if err != nil {
			return fmt.Errorf("failed to register plugin: %w", err)
		}

		go p.Start(c.context, c.discoveryResultChan)

		c.state.SetPlugin(config.GetId(), p)
	case pb.Action_DELETE:
		c.logger.Info("removing plugin", zap.String("plugin", config.GetId()))

		p, ok := c.state.GetPlugin(config.GetId())
		if !ok {
			return fmt.Errorf("plugin does not exists")
		}

		if err := p.Stop(); err != nil {
			return fmt.Errorf("failed to delete plugin: %w", err)
		}

		c.state.DeletePlugin(config.GetId())
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return nil
}

func (c *ConnectorService) handleSocketConfig(action pb.Action, config *pb.SocketConfig) error {
	switch action {
	case pb.Action_CREATE:
		c.logger.Info("initializing socket", zap.String("socket", config.GetId()))

		if _, ok := c.state.GetSocket(config.GetId()); ok {
			suppressionPeriod := 1 * time.Minute
			if c.backoff.GetElapsedTime() < suppressionPeriod {
				// socket already exists
				// this happends if socket is created and connector is starting at the same time
				return nil
			} else {
				return fmt.Errorf("socket already exists")
			}
		}

		socket, err := c.newSocket(config)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		c.state.SetSocket(config.GetId(), socket)
	case pb.Action_UPDATE:
		c.logger.Info("updating socket", zap.String("socket", config.GetId()))

		socket, ok := c.state.GetSocket(config.GetId())
		if !ok {
			return fmt.Errorf("socket does not exist")
		}

		mustReInit := false

		// for kubernetes sockets, if the socket name changes we must re-init
		// the socket (to force-fetch a new certificate for the new dns name).
		if config.GetType() == service.ServiceTypeKubernetes {
			if config.GetName() != socket.Socket.Name {
				mustReInit = true
			}
		}

		if !mustReInit {
			// for all sockets, we check the existing configuration hash against
			// the newly hashed configuration in order to avoid unnecessarily re
			// initializing the socket (and potentially breaking ongoing conns).
			var connectorSocketConfig service.ConnectorServiceConfiguration
			if err := util.AsStruct(config.GetConfig(), &connectorSocketConfig); err != nil {
				return fmt.Errorf("failed to parse socket config: %w", err)
			}
			newHash, err := hashStruct(connectorSocketConfig)
			if err != nil {
				return fmt.Errorf("failed to hash socket config: %w", err)
			}
			if socket.ConfigHash != newHash {
				mustReInit = true
			}
		}

		if !mustReInit {
			return nil
		}

		if !socket.IsClosed() {
			socket.Close()
		}

		socket, err := c.newSocket(config)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		c.state.SetSocket(config.GetId(), socket)
	case pb.Action_DELETE:
		c.logger.Info("removing socket", zap.String("socket", config.GetId()))

		socket, ok := c.state.GetSocket(config.GetId())
		if !ok {
			return fmt.Errorf("socket does not exists")
		}

		if !socket.IsClosed() {
			socket.Close()
		}

		c.state.DeleteSocket(config.GetId())
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return nil
}

func (c *ConnectorService) newSocket(config *pb.SocketConfig) (*border0.Socket, error) {
	var connectorSocketConfig service.ConnectorServiceConfiguration
	if err := util.AsStruct(config.GetConfig(), &connectorSocketConfig); err != nil {
		return nil, fmt.Errorf("failed to parse socket config: %w", err)
	}

	s := &models.Socket{
		SocketID:                       config.GetId(),
		SocketType:                     config.GetType(),
		Name:                           config.GetName(),
		ConnectorAuthenticationEnabled: connectorSocketConfig.ConnectorAuthenticationEnabled,
		EndToEndEncryptionEnabled:      connectorSocketConfig.EndToEndEncryptionEnabled,
		RecordingEnabled:               connectorSocketConfig.RecordingEnabled,
		PrivateNetworkEnabled:          c.privateNetworkEnabled,
	}

	if s.ConnectorLocalData == nil {
		s.ConnectorLocalData = &models.ConnectorLocalData{}
	}

	if s.ConnectorData == nil {
		s.ConnectorData = &models.ConnectorData{}
	}

	if err := upstreamdata.NewUpstreamDataBuilder(c.logger).Build(s, connectorSocketConfig.Upstream); err != nil {
		return nil, fmt.Errorf("failed to build upstream data: %w", err)
	}

	var certificate *tls.Certificate
	if s.EndToEndEncryptionEnabled {
		var err error
		certificate, err = c.Certificate()
		if err != nil {
			return nil, fmt.Errorf("failed to get connector certificate: %w", err)
		}
	}

	socket, err := border0.NewSocketFromConnectorAPI(c.context, c, *s, c.organization, c.logger.With(zap.String("socket_id", s.SocketID)), certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	if connectorSocketConfig.PrivateNetworkIPv4 != nil {
		ip := net.ParseIP(*connectorSocketConfig.PrivateNetworkIPv4)
		if ip == nil {
			return nil, fmt.Errorf("invalid private network ipv4 address")
		}

		socket.PrivateNetworkIPv4 = ip
	}

	if connectorSocketConfig.PrivateNetworkIPv6 != nil {
		ip := net.ParseIP(*connectorSocketConfig.PrivateNetworkIPv6)
		if ip == nil {
			return nil, fmt.Errorf("invalid private network ipv6 address")
		}

		socket.PrivateNetworkIPv6 = ip
	}

	if socket.ConfigHash, err = hashStruct(connectorSocketConfig); err != nil {
		return nil, fmt.Errorf("failed to hash socket config: %w", err)
	}

	if socket.SocketType != service.ServiceTypeSubnetRoutes && socket.SocketType != service.ServiceTypeExitNode {
		if socket.SocketType == service.ServiceTypeHttp && c.privateNetworkEnabled {
			socket.PrivateNetworkEnabled = false
			socket.Socket.PrivateNetworkEnabled = false
		}

		go c.Listen(socket)
	}

	return socket, nil
}

func (c *ConnectorService) GetUserID() (string, error) {
	token, _ := jwt.Parse(c.config.Token, nil)
	if token == nil {
		return "", fmt.Errorf("failed to parse token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	connectorId, connectorIdPresent := claims["connector_id"]
	if connectorIdPresent {
		connectorIdStr, ok := connectorId.(string)
		if !ok {
			return "", fmt.Errorf("failed to parse token")
		}
		return strings.ReplaceAll(connectorIdStr, "-", ""), nil
	}

	if c.config.ConnectorId != "" {
		return strings.ReplaceAll(c.config.ConnectorId, "-", ""), nil
	}

	return "", fmt.Errorf("failed to get user id")
}

func (c *ConnectorService) connectorIDFromToken() (string, error) {
	token, _ := jwt.Parse(c.config.Token, nil)
	if token == nil {
		return "", fmt.Errorf("failed to parse token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	connectorId, connectorIdPresent := claims["connector_id"]
	if connectorIdPresent {
		connectorIdStr, ok := connectorId.(string)
		if !ok {
			return "", fmt.Errorf("failed to parse token")
		}
		return connectorIdStr, nil
	}

	return "", fmt.Errorf("failed to get connector id")
}

func (c *ConnectorService) orgIDFromToken() (string, error) {
	token, _ := jwt.Parse(c.config.Token, nil)
	if token == nil {
		return "", fmt.Errorf("failed to parse token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	orgId, ok := claims["org_id"]
	if !ok {
		return "", fmt.Errorf("failed to get org id")
	}

	orgIdStr, ok := orgId.(string)
	if !ok {
		return "", fmt.Errorf("failed to parse token")
	}

	return orgIdStr, nil
}

func (c *ConnectorService) SignSSHKey(ctx context.Context, socketID string, publicKey []byte) (string, string, error) {
	requestId := uuid.New().String()
	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_TunnelCertificateSignRequest{
			TunnelCertificateSignRequest: &pb.TunnelCertificateSignRequest{
				RequestId: requestId,
				SocketId:  socketID,
				PublicKey: string(publicKey),
			},
		},
	}); err != nil {
		return "", "", fmt.Errorf("failed to send tunnel certificate sign request: %w", err)
	}

	recChan := make(chan *pb.ControlStreamResponse)
	defer close(recChan)

	c.requests.Store(requestId, recChan)
	defer c.requests.Delete(requestId)

	select {
	case <-time.After(10 * time.Second):
		return "", "", fmt.Errorf("timeout waiting for tunnel certificate sign response")

	case r := <-recChan:
		response := r.GetTunnelCertificateSignResponse()
		if response == nil {
			return "", "", fmt.Errorf("invalid response")
		}

		if response.GetRequestId() == "" {
			return "", "", fmt.Errorf("invalid response")
		}

		return response.GetCertificate(), response.GetHostkey(), nil
	}
}

func (c *ConnectorService) Listen(socket *border0.Socket) {
	logger := c.logger.With(zap.String("socket_id", socket.SocketID))

	var l net.Listener
	var err error

	if socket.PrivateNetworkEnabled {
		if socket.PrivateNetworkIPv4 == nil && socket.PrivateNetworkIPv6 == nil {
			logger.Error("private network listener failed", zap.String("reason", "no private network ip addresses provided"))
			return
		}

		l, err = border0.NewPrivateNetworkListener(logger, c, c.wgmr, c.deviceState, socket)
		if err != nil {
			logger.Error("failed to create private network listener", zap.Error(err))
			return
		}
		socket.SetListener(l)
		defer l.Close()
	} else {
		l, err = socket.Listen()
		if err != nil {
			logger.Error("failed to start listener", zap.Error(err))
			return
		}

		defer l.Close()
	}

	var handlerConfig *sqlauthproxy.Config
	if socket.SocketType == "database" {
		handlerConfig, err = sqlauthproxy.BuildHandlerConfig(logger, *socket.Socket, c, c.deviceState)
		if err != nil {
			logger.Error("failed to create config for socket", zap.Error(err))
			return
		}
	}

	var sshProxyConfig *sshConfig.ProxyConfig
	if socket.SocketType == "ssh" {
		var hostkeySigner *gossh.Signer
		if socket.Socket.IsPrimaryProxy() {
			hostkeySigner, err = c.hostkey()
			if err != nil {
				logger.Error("failed to get hostkey", zap.Error(err))
				return
			}
		}

		sshProxyConfig, err = sshConfig.BuildProxyConfig(logger, *socket.Socket, socket.Socket.AWSRegion, "", hostkeySigner, c.organization, c, c.deviceState)
		if err != nil {
			logger.Error("failed to create config for socket", zap.Error(err))
			return
		}
	}

	var k8sapiProxyConfig *k8sapilib.KubernetesProxyConfig
	if socket.SocketType == service.ServiceTypeKubernetes {
		k8sapiProxyConfig, err = k8sapilib.BuildProxyConfig(socket.GetContext(), logger, c, socket, c.getCertRefreshFuncForSocket(socket, 0.666))
		if err != nil {
			logger.Error("failed to build kubernetes api proxy config for socket", zap.Error(err))
			return
		}
	}

	var httpProxyConfig *httpproxylib.HttpProxyConfig
	if socket.SocketType == service.ServiceTypeHttp {
		httpProxyConfig, err = httpproxylib.BuildConfig(socket.GetContext(), logger, c, socket)
		if err != nil {
			logger.Error("failed to build http proxy config for socket", zap.Error(err))
			return
		}
	}

	switch {
	case socket.Socket.SSHServer && socket.SocketType == "ssh" && !socket.Socket.IsPrimaryProxy():
		opts := []server.Option{}
		if socket.Socket != nil &&
			socket.Socket.ConnectorLocalData != nil &&
			socket.Socket.ConnectorLocalData.UpstreamUsername != "" {
			opts = append(opts, server.WithUsername(socket.Socket.ConnectorLocalData.UpstreamUsername))
		}

		sshServer, err := server.NewServer(logger, c.organization.Certificates["ssh_public_key"], opts...)
		if err != nil {
			logger.Error("failed to create ssh server", zap.Error(err))
			return
		}
		if err := sshServer.Serve(l); err != nil {
			logger.Error("ssh server failed", zap.Error(err))
		}
	case sshProxyConfig != nil:
		if err := ssh.Proxy(l, *sshProxyConfig); err != nil {
			logger.Error("ssh proxy failed", zap.Error(err))
		}
	case handlerConfig != nil:
		if err := sqlauthproxy.Serve(l, *handlerConfig); err != nil {
			logger.Error("sql proxy failed", zap.Error(err))
		}
	case k8sapiProxyConfig != nil:
		if err := k8sapilib.Serve(l, k8sapiProxyConfig); err != nil {
			logger.Error("kubernetes api proxy failed", zap.Error(err))
		}
	case httpProxyConfig != nil:
		if err := httpproxylib.Serve(l, httpProxyConfig); err != nil {
			logger.Error("http proxy failed", zap.Error(err))
		}
	case socket.SocketType == service.ServiceTypeVpn:
		if c.privateNetworkEnabled {
			logger.Error("vpn socket not supported in private network mode")
			return
		}
		// options defined locally (not in socket config).
		// these may move to socket config gradually.
		localServerOpts := []vpnlib.ServerOption{
			vpnlib.WithServerVerboseLogs(os.Getenv("VPN_VERBOSE_LOGS") == "true"),
		}

		if err := vpnlib.RunServer(
			socket.GetContext(),
			logger,
			l,
			socket.Socket.ConnectorLocalData.DHCPPoolSubnet,
			socket.Socket.ConnectorLocalData.AdvertisedRoutes,
			c,
			*socket.Socket,
			localServerOpts...,
		); err != nil {
			logger.Error("vpn service failed", zap.Error(err))
		}
	default:
		if err := border0.Serve(logger, l, socket.Socket.TargetHostname, socket.Socket.TargetPort, socket.SocketType, c, socket.Socket); err != nil {
			logger.Error("proxy failed", zap.Error(err))
		}
	}
}

func (c *ConnectorService) handleDiscoveryResult(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-c.discoveryResultChan:
			var resources []*structpb.Struct
			for _, r := range result.Result.Resources {
				var pbstruct structpb.Struct
				if err := util.AsPbStruct(r, &pbstruct); err != nil {
					c.logger.Error("failed to convert go struct to pb struct", zap.Error(err))
					continue
				}
				resources = append(resources, &pbstruct)
			}

			if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
				RequestType: &pb.ControlStreamRequest_PluginDiscoveryResults{
					PluginDiscoveryResults: &pb.PluginDiscoveryResults{
						PluginId: result.PluginID,
						Metadata: &pb.PluginDiscoveryResultsMetadata{
							DiscoveryId: result.Result.Metadata.DiscovererId,
							StartedAt:   timestamppb.New(result.Result.Metadata.StartedAt),
							EndedAt:     timestamppb.New(result.Result.Metadata.EndedAt),
						},
						Errors:    result.Result.Errors,
						Warnings:  result.Result.Warnings,
						Resources: resources,
					},
				},
			}); err != nil {
				c.logger.Error("failed to send plugin discovery results", zap.Error(err))
				continue
			}
		}
	}
}

// getCertRefreshFuncForSocket returns the refresher.RefreshFunc for a given socket with a refreshFactor.
//
// The refreshFactor is a float64 value between 0.01 and 0.99 that dictates at what percentage of the certificate's
// lifetime it should be refreshed. For example, a refreshFactor of 0.666 means that the certificate will be
// refreshed when 66.6% of its lifetime has elapsed, i.e. with 33.4% of the lifetime remaining e.g. so if a
// certificate's total lifetime is 90 days, it will be refreshed around the 60th day.
func (c *ConnectorService) getCertRefreshFuncForSocket(socket *border0.Socket, refreshFactor float64) refresher.RefreshFunc {
	if refreshFactor < 0.01 {
		c.logger.Info("certificate refresh factor < 0.01, setting to 0.01 - this definitely a bug, contact support@border0.com", zap.Float64("original_value", refreshFactor))
		refreshFactor = 0.01
	}
	if refreshFactor > 0.99 {
		c.logger.Info("certificate refresh factor > 0.99, setting to 0.99 - this definitely a bug, contact support@border0.com", zap.Float64("original_value", refreshFactor))
		refreshFactor = 0.99
	}
	return func() (*tls.Certificate, time.Time, error) {
		orgID, err := c.orgIDFromToken()
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to get org id from token: %v", err)
		}

		// try to get an existing certificate from the file system if available
		tlsCert, err := b0Util.GetSocketTLSCertificate(orgID, socket.SocketID)
		if err != nil {
			c.logger.Info(
				"no existing TLS certificate found for socket in the filesystem, fetching a new one",
				zap.String("socket_id", socket.SocketID),
				zap.Error(err),
			)
		}
		if tlsCert != nil && len(tlsCert.Certificate) > 0 {
			leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
			if err == nil {
				elapsedLifetime := time.Since(leaf.NotBefore)
				totalLifetime := leaf.NotAfter.Sub(leaf.NotBefore)

				elapsedLifetimeRefreshThresholdSeconds := float64(totalLifetime.Seconds() * refreshFactor)
				elapsedLifetimeRefreshThreshold := time.Duration(elapsedLifetimeRefreshThresholdSeconds) * time.Second

				// Certificates are stored by socket id in the filesystem. The certificate for this socket **id**
				// may still be valid but it may not be for the socket's current dns name (socket name can change).
				// If the current socket dns name is not a SAN in the certificate, we need to fetch a new one.
				if slices.Contains(leaf.DNSNames, socket.Socket.Dnsname) {
					if elapsedLifetime < elapsedLifetimeRefreshThreshold {
						// Certificate is for the correct name and it is not expired -- return it.
						nextRefresh := leaf.NotBefore.Add(elapsedLifetimeRefreshThreshold)
						return tlsCert, nextRefresh, nil
					}
					// Fallthrough to fetch a new certificate as the current one is expired
				}
				// Fallthrough to fetch a new certificate as the current one has an incorrect dns name
			} else {
				c.logger.Info("failed to parse existing certificate as x509 certificate object", zap.String("socket_id", socket.SocketID), zap.Error(err))
				// fallthrough to fetch a new certificate as we do not know if the current one is expired or not
			}
		}

		// fetch and parse a new certificate as either the existing one is due for renewal, or there is no existing one
		newCertBytes, newCertKeyBytes, err := c.GetTLSCertificateForSocket(socket)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to fetch fresh TLS certificate for socket: %v", err)
		}
		newTlsCert, err := tls.X509KeyPair(newCertBytes, newCertKeyBytes)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to parse the new certificate and key: %v", err)
		}

		// parse certificate pem to determine lifetime details
		block, rest := pem.Decode(newCertBytes)
		if block == nil {
			return nil, time.Time{}, fmt.Errorf("newly retrieved certificate data did not contain a certificate, data: %s", string(rest))
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("failed to parse newly retrieved certificate as x509 certiticate object: %v", err)
		}

		// try to store the new certificate in the filesystem
		if err := b0Util.StoreConnectorSocketCertificate(newCertKeyBytes, newCertBytes, orgID, socket.SocketID); err != nil {
			c.logger.Warn("failed to store the new TLS certificate for socket", zap.String("socket_id", socket.SocketID), zap.Error(err))
		}

		// return the certificate and when it should be next refreshed
		totalLifetime := leaf.NotAfter.Sub(leaf.NotBefore)
		elapsedLifetimeRefreshThresholdSeconds := float64(totalLifetime.Seconds() * refreshFactor)
		elapsedLifetimeRefreshThreshold := time.Duration(elapsedLifetimeRefreshThresholdSeconds) * time.Second
		nextRefresh := leaf.NotBefore.Add(elapsedLifetimeRefreshThreshold)
		return &newTlsCert, nextRefresh, nil
	}
}

func (c *ConnectorService) uploadConnectorMetadata(ctx context.Context) {
	metadata := cmds.MetadataFromContext(ctx)
	c.logger.Debug("collected connector metadata", zap.Any("metadata", metadata))

	var pbstruct structpb.Struct
	if err := util.AsPbStruct(metadata, &pbstruct); err != nil {
		c.logger.Error("failed to convert go struct to pb struct", zap.Error(err))
		return
	}

	err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_Metadata{
			Metadata: &pb.ConnectorMetadata{
				Data: &pbstruct,
			},
		},
	})
	if err != nil {
		c.logger.Error("failed to send connector metadata", zap.Error(err))
		return
	}
}

func (c *ConnectorService) sendControlStreamRequest(request *pb.ControlStreamRequest) error {
	if c.stream == nil {
		return fmt.Errorf(errors.ErrStreamNotConnected)
	}

	return c.stream.Send(request)
}

func hashStruct(data interface{}) (string, error) {
	var buf bytes.Buffer

	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(data); err != nil {
		return "", err
	}

	hash := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(hash[:]), nil
}

func (c *ConnectorService) hostkey() (*gossh.Signer, error) {
	c.sshPrivateHostKeyLock.Lock()
	defer c.sshPrivateHostKeyLock.Unlock()

	if c.sshPrivateHostKey != nil {
		return c.sshPrivateHostKey, nil
	}

	hostkeySigner, err := b0Util.Hostkey()
	if err != nil {
		if hostkeySigner == nil {
			return nil, fmt.Errorf("failed to get hostkey: %s", err)
		} else {
			c.logger.Warn("failed to store hostkey", zap.Error(err))
		}
	}

	c.sshPrivateHostKey = hostkeySigner

	return c.sshPrivateHostKey, nil
}

func (c *ConnectorService) Certificate() (*tls.Certificate, error) {
	c.connectorCertificateLock.Lock()
	defer c.connectorCertificateLock.Unlock()

	if c.connectorCertificate != nil {
		return c.connectorCertificate, nil
	}

	var connectorID string
	if c.config.ConnectorId != "" {
		connectorID = c.config.ConnectorId
	} else {
		var err error
		connectorID, err = c.connectorIDFromToken()
		if err != nil {
			return nil, fmt.Errorf("failed to get connector id: %w", err)
		}
	}

	orgID, err := c.orgIDFromToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get org id: %w", err)
	}

	c.connectorCertificate, err = b0Util.GetEndToEndEncryptionCertificate(orgID, connectorID)
	if err != nil {
		c.logger.Warn("failed to get end to end encryption certificate", zap.Error(err))
	}

	if c.connectorCertificate != nil {
		return c.connectorCertificate, nil
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "border0"},
		SignatureAlgorithm: x509.PureEd25519,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csrPem := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	requestId := uuid.New().String()

	recChan := make(chan *pb.ControlStreamResponse)
	defer close(recChan)

	c.requests.Store(requestId, recChan)
	defer c.requests.Delete(requestId)

	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_CertificateSignRequest{
			CertificateSignRequest: &pb.CertificateSignRequest{
				RequestId:                 requestId,
				CertificateSigningRequest: pem.EncodeToMemory(&csrPem),
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("failed to send connector certificate sign request: %w", err)
	}

	var certificate []byte
	select {
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timeout waiting for certificate sign response")
	case r := <-recChan:
		response := r.GetCertificateSignResponse()
		if response == nil {
			return nil, fmt.Errorf("invalid response")
		}

		if response.GetRequestId() == "" {
			return nil, fmt.Errorf("invalid response")
		}

		certificate = response.GetCertificate()
	}

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privKeyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	cert, err := tls.X509KeyPair(certificate, pem.EncodeToMemory(privKeyPem))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	c.connectorCertificate = &cert

	if err := b0Util.StoreConnectorCertificate(pem.EncodeToMemory(privKeyPem), certificate, orgID, connectorID); err != nil {
		c.logger.Warn("failed to store the end to end encryption certificate", zap.Error(err))
	}

	return c.connectorCertificate, nil
}

// GetTLSCertificateForSocket is used to get a fresh TLS certificate for a given socket.
// The certificate will have the socket DNS name as a SAN and is signed by the org-wide CA.
func (c *ConnectorService) GetTLSCertificateForSocket(socket *border0.Socket) ([]byte, []byte, error) {
	// generate private key
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privKeyPem := &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes}

	// build template with socket ids passed in the DNS names of the CSR
	csrTemplate := x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "border0"},
		SignatureAlgorithm: x509.PureEd25519,
		DNSNames:           []string{socket.SocketID},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate request: %w", err)
	}
	csrPem := pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes}

	// initialize response channel
	recChan := make(chan *pb.ControlStreamResponse)
	defer close(recChan)

	// register request id to request router
	requestId := uuid.New().String()
	c.requests.Store(requestId, recChan)
	defer c.requests.Delete(requestId)

	// send request over grpc channel
	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_CertificateSignRequest{
			CertificateSignRequest: &pb.CertificateSignRequest{
				RequestId:                 requestId,
				CertificateSigningRequest: pem.EncodeToMemory(&csrPem),
			},
		},
	}); err != nil {
		return nil, nil, fmt.Errorf("failed to send connector certificate sign request: %w", err)
	}

	// handle response or timeout
	select {
	case <-time.After(5 * time.Second):
		return nil, nil, fmt.Errorf("timeout waiting for certificate sign response")
	case r := <-recChan:
		response := r.GetCertificateSignResponse()
		if response == nil {
			return nil, nil, fmt.Errorf("invalid response")
		}
		if response.GetRequestId() == "" {
			return nil, nil, fmt.Errorf("invalid response")
		}
		return response.GetCertificate(), pem.EncodeToMemory(privKeyPem), nil
	}
}

func (c *ConnectorService) announce(discoverable bool, udp4Addr *net.UDPAddr, udp6Addr *net.UDPAddr) error {
	logOpts := []zapcore.Field{zap.Bool("discoverable", discoverable)}

	udp4 := ""
	udp6 := ""
	if discoverable {
		if udp4Addr != nil {
			udp4 = udp4Addr.String()
			logOpts = append(logOpts, zap.String("udp4", udp4))
		}
		if udp6Addr != nil {
			udp6 = udp6Addr.String()
			logOpts = append(logOpts, zap.String("udp6", udp6))
		}
	}

	c.logger.Info("sending discoverability message", logOpts...)

	if err := c.sendControlStreamRequest(&pb.ControlStreamRequest{
		RequestType: &pb.ControlStreamRequest_DiscoveryDetails{
			DiscoveryDetails: &common.DiscoveryDetailsMessage{
				Discoverable:       discoverable,
				EndpointPublicUdp4: udp4,
				EndpointPublicUdp6: udp6,
				PublicKey:          c.deviceState.GetPublicKey().B64(),
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to send discoverability message: %w", err)
	}

	return nil
}
