package vpnlib

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util"
	"go.uber.org/zap"
)

const ipForwardingNotEnabledMessage = `
IP forwarding is not enabled - your VPN will not be able to forward packets.
To enable ip forwarding run: sysctl -w net.ipv4.ip_forward=1
Also make sure to enable NAT: iptables -t nat -A POSTROUTING -o <interface> -j MASQUERADE
`

// optional configuration for the vpn "server" side.
type serverConfig struct {
	verbose bool
}

// ServerOption represents a configuration option for the vpn "server" side.
type ServerOption func(*serverConfig)

// WithServerVerboseLogs returns the ServerOption that toggles verbose logging.
func WithServerVerboseLogs(verbose bool) ServerOption {
	return func(c *serverConfig) { c.verbose = verbose }
}

// RunServer runs the VPN "server"
func RunServer(
	ctx context.Context,
	logger *zap.Logger,
	vpnClientListener net.Listener,
	dhcpPoolSubnet string,
	advertisedRoutes []string,
	border0API border0.Border0API,
	socket models.Socket,
	opts ...ServerOption,
) error {
	config := &serverConfig{verbose: false}
	for _, opt := range opts {
		opt(config)
	}

	if !util.RunningAsAdministrator() {
		return errors.New("connector must be running as system administrator in order to manage vpn sockets")
	}

	// Create an IP pool that will be used to assign IPs to clients
	dhcpPool, err := NewIPPool(dhcpPoolSubnet)
	if err != nil {
		return fmt.Errorf("failed to create IP Pool: %v", err)
	}
	subnetSize := dhcpPool.GetSubnetSize()
	serverIp := dhcpPool.GetServerIp()

	tun, err := CreateTun()
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %v", err)
	}
	defer tun.Close()

	logger.Info(
		"Started VPN server",
		zap.String("interface", tun.Name()),
		zap.String("server_ip", serverIp),
		zap.String("dhcp_pool_subnet", dhcpPoolSubnet),
		zap.Any("routes", advertisedRoutes),
	)

	if err = AddServerIp(tun.Name(), serverIp, subnetSize); err != nil {
		return fmt.Errorf("failed to add server IP to interface: %v", err)
	}

	if runtime.GOOS != "linux" {
		// On linux the routes are added to the interface when creating the interface and adding the IP
		if err = AddRoutesToIface(tun.Name(), []string{dhcpPoolSubnet}); err != nil {
			logger.Warn("failed to add routes to interface", zap.Error(err))
		}
	}

	if runtime.GOOS == "linux" {
		forwardingEnabled, err := CheckIPForwardingEnabled()
		if err != nil {
			logger.Warn("failed to check if ip forwarding is enabled", zap.Error(err))
		}
		if !forwardingEnabled {
			logger.Warn(ipForwardingNotEnabledMessage)
		}
	}

	// create the connection map
	connMap := NewConnectionMap()

	// Now start the Tun to Conn goroutine
	// This will listen for packets on the TUN interface and forward them to the right connection
	go tunToConnMapCopy(ctx, logger, tun, connMap, config.verbose)

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		default:
			client, err := vpnClientListener.Accept()
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					logger.Error("failed to accept new vpn connection", zap.Error(err))
				}
				continue // note: if context is cancelled, above case will catch it
			}
			go handleIPPacketConn(
				ctx,
				logger,
				client,
				tun,
				dhcpPool,
				connMap,
				advertisedRoutes,
				border0API,
				socket,
			)
		}
	}
}

func handleIPPacketConn(
	ctx context.Context,
	logger *zap.Logger,
	client net.Conn,
	tun io.Writer,
	dhcpPool *IPPool,
	connMap *ConnectionMap,
	advertisedRoutes []string,
	border0API border0.Border0API,
	socket models.Socket,
) {
	defer client.Close()

	// authz
	e2eeConn, ok := client.(border0.E2EEncryptionConn)
	if !ok {
		logger.Error("failed to cast connection to e2eencryption")
		return
	}

	if e2eeConn.Metadata == nil {
		logger.Error("invalid e2e metadata")
		return
	}

	allowed := false
	for _, action := range e2eeConn.Metadata.AllowedActions {
		switch permission := action.(type) {
		case string:
			allowed = true
		case models.Permissions:
			if permission.VPN != nil {
				allowed = true
			}
		}

		if allowed {
			break
		}
	}

	if !allowed {
		if err := border0API.UpdateSession(models.SessionUpdate{
			SessionKey:     e2eeConn.Metadata.SessionKey,
			Socket:         &socket,
			Result:         models.ResultDenied,
			AuthInfoFailed: "VPN access denied by Policy",
		}); err != nil {
			logger.Error("failed to update session", zap.Error(err))
		}

		return
	}

	// allocate a new IP in the pool for the new client
	clientIP, err := dhcpPool.Allocate()
	if err != nil {
		if err := errorEvent(border0API, e2eeConn.Metadata, socket, "vpn_session", fmt.Sprintf("failed to allocate client IP: %s", err)); err != nil {
			logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}
	defer dhcpPool.Release(clientIP)

	// attach new client connection to connection map
	connMap.Set(clientIP, client)
	defer connMap.Delete(clientIP)

	metadata, err := json.Marshal(struct {
		PeerIP string `json:"peer_ip"`
	}{clientIP})
	if err != nil {
		logger.Error("failed to marshal metadata", zap.Error(err))
		return
	}

	if err := border0API.CreateSessionEvent(models.SessionEvent{
		SessionKey: e2eeConn.Metadata.SessionKey,
		Socket:     &socket,
		Type:       "vpn_session",
		Status:     "success",
		Metadata:   string(metadata),
	}); err != nil {
		logger.Error("failed to create session event", zap.Error(err))
		return
	}

	// define control message
	controlMessage := &ControlMessage{
		ClientIp:   clientIP,
		ServerIp:   dhcpPool.GetServerIp(),
		SubnetSize: dhcpPool.GetSubnetSize(),
		Routes:     advertisedRoutes,
	}
	controlMessageBytes, err := controlMessage.Build()
	if err != nil {
		if err := errorEvent(border0API, e2eeConn.Metadata, socket, "vpn_session", fmt.Sprintf("failed to build control message: %s", err)); err != nil {
			logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	// write control message
	n, err := client.Write(controlMessageBytes)
	if err != nil {
		if err := errorEvent(border0API, e2eeConn.Metadata, socket, "vpn_session", fmt.Sprintf("failed to write control message to net conn: %s", err)); err != nil {
			logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}
	if n < len(controlMessageBytes) {
		if err := errorEvent(border0API, e2eeConn.Metadata, socket, "vpn_session", fmt.Sprintf("failed to write entire control message bytes: %s", err)); err != nil {
			logger.Error("failed to create session event", zap.Error(err))
		}

		return
	}

	// kick off routine to read packets from clients and forward them to the interface
	if err = ConnToTunCopy(ctx, logger, client, clientIP, tun); err != nil {
		if !errors.Is(err, io.EOF) {
			if err := errorEvent(border0API, e2eeConn.Metadata, socket, "vpn_session", fmt.Sprintf("failed to forward packets between client conn and interface: %s", err)); err != nil {
				logger.Error("failed to create session event", zap.Error(err))
			}
		}
		return
	}
}

// tunToConnMapCopy reads packets and fowards them to the appropriate connection in a ConnectionMap.
// This function is used by the VPN "server" and must *not* be used by clients. This function is resilient
// to errors and will run for as long as the source is not closed and the context is not cancelled.
func tunToConnMapCopy(
	ctx context.Context,
	logger *zap.Logger,
	source io.Reader,
	dstMap *ConnectionMap,
	verbose bool,
) error {

	packetBufferSize := 9000
	packetbuffer := make([]byte, packetBufferSize)
	b0HeaderBuffer := make([]byte, border0HeaderByteSize)

	for {
		select {
		case <-ctx.Done():
			if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			return nil
		default:
			// read one packet from the source
			n, err := source.Read(packetbuffer)
			if err != nil {
				if !errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return nil // source was closed, have to return
				}
				logger.Warn("failed to read packet", zap.Error(err))
				continue
			}
			packet := packetbuffer[:n]

			// ignore non IPv4 packets
			ipVersion := (packet[0] & 0xF0) >> 4
			if ipVersion != 4 {
				if verbose {
					logger.Info("received non IPv4 packet", zap.Uint8("ip_version_byte", uint8(ipVersion)))
				}
				continue
			}
			if err := validateIPv4(packet); err != nil {
				logger.Warn("received invalid IPv4 packet", zap.Error(err))
				continue
			}

			_, dstIp := parseIpFromPacketHeader(packet)
			dstIpString := dstIp.String()

			if dstConn, exists := dstMap.Get(dstIpString); exists {

				// we produce a "border0 header" so that we can write a single packet
				// across multiple connection writes (under the hood) if needed.
				binary.BigEndian.PutUint16(b0HeaderBuffer, uint16(n))

				// write packet to target connection
				_, err = dstConn.Write(append(b0HeaderBuffer, packetbuffer[:n]...))
				if err != nil {
					// if there's any errors, we kick the client out
					dstConn.Close()
					dstMap.Delete(dstIpString)

					if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
						logger.Info("client disconnected", zap.String("dst_ip", dstIpString))
					} else {
						logger.Warn("client kicked due to error", zap.String("dst_ip", dstIpString))
					}
				}
			} else {
				if verbose {
					logger.Info("received IPv4 for invalid destination address", zap.String("dst_ip", dstIpString))
				}
			}
		}
	}
}

func errorEvent(border0API border0.Border0API, e2eeMetadata *border0.ConnMetadata, socket models.Socket, eventType string, message string) error {
	metadata, err := json.Marshal(struct {
		Error string `json:"error"`
	}{message})
	if err != nil {
		return err
	}

	return border0API.CreateSessionEvent(models.SessionEvent{
		SessionKey: e2eeMetadata.SessionKey,
		Socket:     &socket,
		Type:       eventType,
		Status:     "error",
		Metadata:   string(metadata),
	})
}
