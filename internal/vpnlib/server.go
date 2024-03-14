package vpnlib

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"

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
	opts ...ServerOption,
) error {
	config := &serverConfig{verbose: false}
	for _, opt := range opts {
		opt(config)
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
) {
	defer client.Close()

	// allocate a new IP in the pool for the new client
	clientIP, err := dhcpPool.Allocate()
	if err != nil {
		logger.Error("failed to allocate client IP", zap.Error(err))
		return
	}
	defer dhcpPool.Release(clientIP)

	// attach new client connection to connection map
	connMap.Set(clientIP, client)
	defer connMap.Delete(clientIP)

	logger.Info("new client connected", zap.String("peer_ip", clientIP))

	// define control message
	controlMessage := &ControlMessage{
		ClientIp:   clientIP,
		ServerIp:   dhcpPool.GetServerIp(),
		SubnetSize: dhcpPool.GetSubnetSize(),
		Routes:     advertisedRoutes,
	}
	controlMessageBytes, err := controlMessage.Build()
	if err != nil {
		logger.Error("failed to build control message", zap.Error(err))
		return
	}

	// write control message
	n, err := client.Write(controlMessageBytes)
	if err != nil {
		logger.Error("failed to write control message to net conn", zap.Error(err))
		return
	}
	if n < len(controlMessageBytes) {
		logger.Error("failed to write entire control message bytes", zap.Int("bytes_written", n), zap.Int("message_length", len(controlMessageBytes)))
		return
	}

	// kick off routine to read packets from clients and forward them to the interface
	if err = ConnToTunCopy(ctx, logger, client, clientIP, tun); err != nil {
		if !errors.Is(err, io.EOF) {
			logger.Error("failed to forward packets between client conn and interface", zap.Error(err))
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
