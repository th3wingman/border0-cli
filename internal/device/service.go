package device

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/device/config"
	"github.com/borderzero/border0-cli/internal/device/handlers"
	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/device/utils/debouncer"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-cli/internal/device/wg/endpoint"
	"github.com/borderzero/border0-cli/internal/device/wgmgr"
	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/borderzero/border0-go/types/connector"
	"github.com/borderzero/border0-proto/common"
	pb "github.com/borderzero/border0-proto/device"
	backoff "github.com/cenkalti/backoff/v4"
	"github.com/shirou/gopsutil/v3/host"
	"go.uber.org/atomic"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const defaultWgPort = 32442

var (
	serverRequestedDisconnection = errors.New("server requested disconnection")
)

type Service interface {
	Start()
	Close() error
	StartVPN() error
	StopVPN() error
	Status() (bool, error)
	GetVpnPeers() ([]stats.Peer, error)
	GetVpnStats() *stats.Stats
	GetWireGuardConfig() (string, error)
	GetExitNode() string
	GetExitNodes() []string
	SetExitNode(string) error
}

type service struct {
	version string
	logger  *zap.Logger
	config  *config.Configuration

	peerMap  endpoint.Mapping
	state    state.State
	wgmgr    wgmgr.WireGuardManager
	stats    stats.Manager
	gotState bool

	streamReady *atomic.Bool
	stream      pb.DeviceManagementService_ControlStreamClient

	// runtime management
	bo     backoff.BackOff
	ctx    context.Context
	cancel context.CancelFunc
}

func NewService(
	version string,
	logger *zap.Logger,
	configuration *config.Configuration,
	state state.State,
) (Service, error) {
	peerMap := endpoint.NewMapping()
	svc := &service{
		version:     version,
		logger:      logger,
		peerMap:     peerMap,
		state:       state,
		stats:       stats.NewManager(logger),
		config:      configuration,
		streamReady: atomic.NewBool(false),
		stream:      nil,
	}

	announceChan := debouncer.NewDebouncer(time.Millisecond*500, func(a *wgmgr.DiscoverabilityAnnouncement) {
		if err := svc.announce(a.Discoverable, a.UDP4Address, a.UDP6Address); err != nil {
			logger.Error("failed to announce discoverability (in debouncer)", zap.Error(err))
		}
	})

	wgPort := defaultWgPort
	if wgPortOverride := strings.TrimSpace(os.Getenv("BORDER0_WG_BIND_PORT")); wgPortOverride != "" {
		wgPortOverrideInt64, err := strconv.ParseInt(wgPortOverride, 10, 16)
		if err != nil {
			logger.Error(
				"failed to parse port in BORDER0_WG_BIND_PORT as a 16 bit integer",
				zap.String("BORDER0_WG_BIND_PORT", wgPortOverride),
				zap.Error(err),
			)
		} else {
			wgPort = int(wgPortOverrideInt64)
		}
	}

	wgmgr, err := wgmgr.New(
		logger,
		state,
		svc.stats,
		peerMap,
		configuration.ManagedNetworkingInterfaceName,
		configuration.RelayURL,
		announceChan,
		false,
		wgPort,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start wireguard manager: %v", err)
	}
	svc.wgmgr = wgmgr
	return svc, nil
}

func (s *service) Close() error {
	if err := s.announce(false, nil, nil); err != nil {
		s.logger.Warn("failed to announce final un-discoverability", zap.Error(err))
	}
	time.Sleep(time.Millisecond * 100) // allow some time for final undiscoverablity message to go through
	s.cancel()
	if err := s.state.
		SetWireGuardPeers(nil).
		RemoveManagedInterface(s.config.ManagedNetworkingInterfaceName).
		Commit(); err != nil {
		s.logger.Error("failed to clean up state during service closure", zap.Error(err))
	}
	return s.wgmgr.Close()
}

func (s *service) Status() (bool, error) {
	return s.wgmgr.IsRunning(), nil
}

func (s *service) GetWireGuardConfig() (string, error) {
	return s.wgmgr.GetWireGuardConfig()
}

func (s *service) GetVpnPeers() ([]stats.Peer, error) {
	return s.wgmgr.GetPeerStats()
}

func (s *service) GetVpnStats() *stats.Stats {
	return s.wgmgr.GetStats()
}

func (s *service) Start() {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	defer s.cancel()
	s.bo = backoff.WithContext(
		backoff.NewExponentialBackOff(
			backoff.WithMaxElapsedTime(time.Duration(0)), // never time out
			backoff.WithInitialInterval(time.Second*2),   // first backoff starts at 2 seconds
			backoff.WithMultiplier(2),                    // double the backoff after each error e.g. 2x, 4x, 8x, 16x...
			backoff.WithMaxInterval(time.Minute*15),      // cap the max backoff at 15 minutes
			backoff.WithRandomizationFactor(0.5),         // add some jitter to backoff (avoid overwhelming api)
		),
		s.ctx,
	)
	notify := func(e error, d time.Duration) {
		s.logger.Error("failure during backoff", zap.Error(e), zap.Duration("backoff", d))
	}
	if err := backoff.RetryNotify(s.start, s.bo, notify); err != nil {
		s.logger.Error("error in device control stream", zap.Error(err))
	}
}

func (s *service) start() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("recovered from panic: %v", r)
		}
	}()

	grpcClient, err := s.newNodeControlServerGrpcClient()
	if err != nil {
		return fmt.Errorf("failed to initialize node control server client: %v", err)
	}
	defer grpcClient.Close()

	stream, err := pb.NewDeviceManagementServiceClient(grpcClient).ControlStream(s.ctx)
	if err != nil {
		return fmt.Errorf("failed to setup node control stream: %v", err)
	}
	s.stream = stream

	// perform auth handshake against api
	if err := s.auth(); err != nil {
		return fmt.Errorf("failed to perform authentication handshake with control server: %v", err)
	}

	// reset the backoff object to clear current backoff amount
	s.bo.Reset()

	// mark the stream as ready
	s.streamReady.Store(true)
	defer s.streamReady.Store(false)

	// announce discoverability when re-connecting
	if err := s.announceDiscoverability(s.wgmgr.IsRunning()); err != nil {
		s.logger.Error("failed to announce discoverability")
	}

	// start stats manager
	statsCtx, statsCtxCancel := context.WithCancel(context.Background())
	defer statsCtxCancel()
	go s.stats.Push(
		statsCtx,
		time.Minute, // push once a minute
		func(counters *stats.Delta) error {
			s.logger.Debug(
				"pushing metrics now",
				zap.Uint64("bytes_in", counters.BytesIn),
				zap.Uint64("bytes_out", counters.BytesOut),
				zap.Uint64("packets_in", counters.PacketsIn),
				zap.Uint64("packets_out", counters.PacketsOut),
			)
			return s.stream.Send(&pb.DeviceToServerMessage{
				Message: &pb.DeviceToServerMessage_Stats{
					Stats: &common.StatsMessage{
						StatsMessageType: &common.StatsMessage_NetworkDeviceStats{
							NetworkDeviceStats: &common.NetworkDeviceStatsMessage{
								Timestamp:  timestamppb.New(time.Now()),
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

	// handle all further messaging e.g. peer updates, etc
	if err = s.handleStream(); err != nil {
		if errors.Is(err, serverRequestedDisconnection) {
			return backoff.Permanent(err)
		}
		return fmt.Errorf("error handling control stream: %v", err)
	}
	return nil
}

func (s *service) StartVPN() error {
	if s.wgmgr.IsRunning() {
		return nil
	}
	if err := s.wgmgr.Start(); err != nil {
		return fmt.Errorf("failed to start the vpn: %v", err)
	}
	return s.announceDiscoverability(true)
}

func (s *service) StopVPN() error {
	if !s.wgmgr.IsRunning() {
		return nil
	}
	if err := s.wgmgr.Stop(); err != nil {
		return fmt.Errorf("failed to stop the vpn: %v", err)
	}
	return s.announceDiscoverability(false)
}

func (s *service) handleStream() error {
	s.logger.Info("authenticated successfully to control server")

	// start a ticker that triggers every 20 seconds
	heartBeatTicker := time.NewTicker(20 * time.Second)
	defer heartBeatTicker.Stop()

	// start a goroutine to handle sending heartbeat messages
	go func() {
		for {
			select {
			case <-heartBeatTicker.C:
				err := s.stream.Send(&pb.DeviceToServerMessage{
					Message: &pb.DeviceToServerMessage_Heartbeat{
						Heartbeat: &common.HeartbeatMessage{},
					},
				})
				if err != nil {
					s.logger.Error("failed to send heartbeat", zap.Error(err))
					return // Exit the goroutine if sending fails
				}
				s.logger.Info("Heartbeat sent")
			case <-s.ctx.Done():
				return
			}
		}
	}()

	// Receive loop to handle any incoming messages or responses
	for {
		in, err := s.stream.Recv()
		if err != nil {
			return fmt.Errorf("stream receive error: %v", err)
		}

		// Handle different types of incoming messages here
		switch in.Message.(type) {
		case *pb.ServerToDeviceMessage_Heartbeat:
			s.logger.Debug("heartbeat response received")
		case *pb.ServerToDeviceMessage_NetworkState:
			if err := handlers.HandleNetworkStateMessage(s.logger, s.state, s.wgmgr, in.GetNetworkState()); err != nil {
				s.logger.Error("failed to configure wireguard peers", zap.Error(err))
				continue
			}
			s.gotState = true
			s.logger.Info("re-configured wireguard peers successfully")
		case *pb.ServerToDeviceMessage_PeerOnline:
			if err := handlers.HandlePeerOnlineMessage(s.logger, s.state, s.wgmgr, in.GetPeerOnline()); err != nil {
				s.logger.Error("failed to add wireguard peer", zap.Error(err))
				continue
			}
			s.logger.Info("added wireguard peer successfully")
		case *pb.ServerToDeviceMessage_PeerOffline:
			if err := handlers.HandlePeerOfflineMessage(s.logger, s.state, s.peerMap, s.wgmgr, in.GetPeerOffline()); err != nil {
				s.logger.Error("failed to remove wireguard peer", zap.Error(err))
				continue
			}
			s.logger.Info("removed wireguard peer successfully")
		case *pb.ServerToDeviceMessage_Disconnect:
			reason := ""
			if disconnectMsg := in.GetDisconnect(); disconnectMsg != nil {
				reason = disconnectMsg.GetReason().String()
			}

			// check if it's the server shutdown/device deleted message and expire the key
			// this will force a reauthentication on the next connection
			if reason == common.DisconnectionReason_SERVER_SHUTDOWN.String() {
				s.state.SetKeyExpiry(pointer.To(time.Now()))
				s.state.Commit()
			}

			s.logger.Error("server requested disconnection", zap.String("reason", reason))
			return serverRequestedDisconnection
		case *pb.ServerToDeviceMessage_Service:
			if !s.gotState {
				// not ready to handle service messages until we have the network state
				continue
			}

			if err := handlers.HandleServiceMessage(s.logger, s.state, s.wgmgr, in.GetService()); err != nil {
				s.logger.Error("failed to handle service message", zap.Error(err))
				continue
			}
		default:
			// log unexpected message types
			s.logger.Info("Received unknown message type")
		}
	}
}

func fetchHostMetadata(ctx context.Context) (*connector.HostMetadata, error) {
	var hostMetadata connector.HostMetadata

	info, err := host.InfoWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get host metadata: %v", err)
	}

	if info != nil {
		hostMetadata = connector.HostMetadata{
			Hostname:        info.Hostname,
			Uptime:          info.Uptime,
			OS:              info.OS,
			Platform:        info.Platform,
			PlatformVersion: info.PlatformVersion,
			KernelVersion:   info.KernelVersion,
			KernelArch:      info.KernelArch,
		}
		return &hostMetadata, nil
	}

	return nil, nil
}

func (s *service) newNodeControlServerGrpcClient() (*grpc.ClientConn, error) {
	credOpts := []credentialOption{
		withPublicKey(s.state.GetPublicKey().B64()),
		withInsecureTransport(s.config.DeviceManagementInsecureTransport),
		withClientVersion(s.version),
	}

	hostData, err := fetchHostMetadata(s.ctx)
	if err != nil {
		// log error but continue
		s.logger.Error("failed to fetch host metadata", zap.Error(err))
	}

	if hostData != nil {
		credOpts = append(credOpts, withHostMetadata(hostData))
	}

	grpcOpts := []grpc.DialOption{
		grpc.WithPerRPCCredentials(newDeviceManagementStreamCredentials(credOpts...)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                20 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	if s.config.DeviceManagementInsecureTransport {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	s.logger.Info("connecting to node server", zap.String("server", s.config.DeviceManagementServer))

	client, err := grpc.NewClient(s.config.DeviceManagementServer, grpcOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to control server: %v", err)
	}

	return client, nil
}

func (s *service) auth() error {
	// receive the challenge from the server
	in, err := s.stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive challenge from server: %v", err)
	}
	challengeMsg := in.GetAuthChallenge()
	if challengeMsg == nil {
		return fmt.Errorf("expected auth challenge message, got nil")
	}
	serverPub, err := nacl.ParsePublicKeyB64(challengeMsg.GetServerPublicKey())
	if err != nil {
		return fmt.Errorf("failed to parse server public key for authentication challenge: %v", err)
	}
	challengeNonce := [24]byte(challengeMsg.GetChallengeNonce())
	fmtChallengeNonce := nacl.Nonce(&challengeNonce)

	solution, solutionNonce, err := nacl.SolveChallenge(
		challengeMsg.GetChallenge(),
		fmtChallengeNonce,
		serverPub,
		s.state.GetPrivateKey(),
	)
	if err != nil {
		return fmt.Errorf("failed to solve device management grpc server challenge: %v", err)
	}

	// send the decrypted challenge back as the solution
	if err := s.stream.Send(&pb.DeviceToServerMessage{
		Message: &pb.DeviceToServerMessage_AuthChallengeSolution{
			AuthChallengeSolution: &pb.AuthChallengeSolutionMessage{
				Solved:      solution,
				SolvedNonce: []byte(solutionNonce[:]),
			},
		},
	}); err != nil {
		return fmt.Errorf("failed to send challenge solution: %v", err)
	}
	return nil
}

func (s *service) announceDiscoverability(discoverable bool) error {
	return s.announce(discoverable, s.wgmgr.GetPublicIPv4Address(), s.wgmgr.GetPublicIPv6Address())
}

func (s *service) announce(discoverable bool, udp4Addr, udp6Addr *net.UDPAddr) error {
	// if the stream is unavailable, make sure we announce when it is available
	if !s.streamReady.Load() {
		return nil
	}

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

	s.logger.Info("sending discoverability message", logOpts...)
	return s.stream.Send(&pb.DeviceToServerMessage{
		Message: &pb.DeviceToServerMessage_DiscoveryDetails{
			DiscoveryDetails: &common.DiscoveryDetailsMessage{
				Discoverable:       discoverable,
				EndpointPublicUdp4: udp4,
				EndpointPublicUdp6: udp6,
			},
		},
	})
}

func (s *service) GetExitNode() string {
	return s.wgmgr.GetExitNode()
}

func (s *service) GetExitNodes() []string {
	return s.wgmgr.GetExitNodes()
}

func (s *service) SetExitNode(exitNode string) error {
	return s.wgmgr.SetExitNode(exitNode)
}
