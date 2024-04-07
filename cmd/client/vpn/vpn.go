package vpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/borderzero/border0-cli/internal/vpnlib"
	"github.com/cenkalti/backoff/v4"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	maxBackoffRetries     = 3
	maxConnectionAttempts = 3
)

var (
	hostname   string
	useWsProxy bool
)

type networkRoute struct {
	network   string
	nextHopIp string
}

// clientVpnCmd represents the client tls command
var clientVpnCmd = &cobra.Command{
	Use:               "vpn",
	Short:             "Start a Border0 VPN",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			hostname = args[0]
		}

		if !util.RunningAsAdministrator() {
			return errors.New("command must be ran as system administrator")
		}

		if hostname == "" {
			pickedHost, err := client.PickHost(hostname, enum.VPNSocket)
			if err != nil {
				return fmt.Errorf("failed to pick host: %v", err)
			}
			hostname = pickedHost.Hostname()
		}

		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// signal handler
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, os.Interrupt)
		go func() {
			<-sigs
			fmt.Println("shutdown signal received")
			cancel()
		}()

		resourceExists := true
		for attemptsAvailable := maxConnectionAttempts; attemptsAvailable > 0 && resourceExists; attemptsAvailable-- {

			select {
			case <-ctx.Done():
				if err := ctx.Err(); err != nil && !errors.Is(err, context.Canceled) {
					return err
				}
				return nil
			default:
				exponentialBackoff := backoff.NewExponentialBackOff()
				exponentialBackoff.InitialInterval = 1 * time.Second
				exponentialBackoff.MaxInterval = 5 * time.Second
				exponentialBackoff.Multiplier = 1.5

				retryFn := func() error {
					established, err := runClient(ctx, logger.Logger, hostname)

					// if the context is cancelled we simply return nil here.
					// the next run of the loop will catch the ctx.Done and exit
					select {
					case <-ctx.Done():
						return nil
					default:
						// do nothing
					}

					if err != nil {
						// if the client returns a "resource not found"
						// error, then we do not want to retry connecting.
						if errors.Is(err, client.ErrResourceNotFound) {
							resourceExists = false
							return nil
						}
						// if by the time the client returned we already had
						// established an end to end session with a remote
						// connector, then we top up the available reconnections.
						if established {
							logger.Logger.Info("VPN client disconnected, will attempt to reconnect...", zap.Error(err))
							attemptsAvailable = maxConnectionAttempts
							return nil
						}
						// a real failure happened, this will be retried
						return fmt.Errorf("failed to establish connection to VPN socket: %v", err)
					}

					// if by the time the client returned we already had
					// established an end to end session with a remote
					// connector, then we top up the available reconnections.
					if established {
						logger.Logger.Info("VPN client disconnected, will attempt to reconnect...")
						attemptsAvailable = maxConnectionAttempts
					}
					return nil
				}

				err := backoff.Retry(retryFn, backoff.WithMaxRetries(exponentialBackoff, maxBackoffRetries))
				if err != nil {
					logger.Logger.Warn("failed to connect to VPN socket", zap.Error(err))
					continue
				}
			}
		}

		if !resourceExists {
			return fmt.Errorf("resource %s does not exist", hostname)
		}
		return fmt.Errorf("failed to connect to VPN socket (%d attempts)", maxConnectionAttempts)
	},
}

func runClient(parentCtx context.Context, logger *zap.Logger, hostname string) (bool, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	established := false

	info, err := client.GetResourceInfo(logger, hostname)
	if err != nil {
		if errors.Is(err, client.ErrResourceNotFound) {
			return established, err
		}
		return established, fmt.Errorf("failed to get certificate: %v", err)
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{info.Certficate.Raw},
		PrivateKey:  info.PrivateKey,
	}

	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("failed to get system cert pool: %v", err.Error())
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      systemCertPool,
		ServerName:   hostname,
	}

	conn, err := establishConnection(info.ConnectorAuthenticationEnabled, info.EndToEndEncryptionEnabled, fmt.Sprintf("%s:%d", hostname, info.Port), &tlsConfig, info.CaCertificate, useWsProxy)
	if err != nil {
		return established, fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	// NOTE: This line is important! established is used on every return statement in this function
	// to signal the caller that a connection was established. The caller uses this information to
	// determine whether it will retry connecting or not (e.g. if a failure occured after a connection
	// was successfully established, this function will be re-ran). This is done to make the client
	// resilient to temporary disconnections e.g. socket re-configurations, etc.
	established = true

	iface, err := vpnlib.CreateTun()
	if err != nil {
		return established, fmt.Errorf("failed to create TUN interface: %v", err)
	}
	defer iface.Close()

	logger.Info("Created TUN interface", zap.String("interface_name", iface.Name()))

	ctrl, err := vpnlib.GetControlMessage(conn)
	if err != nil {
		return established, fmt.Errorf("failed to get control message from connection: %v\nIt's likely the Remote VPN server hasnt been started", err)
	}
	logger.Info("Connected, Session info:", zap.Any("control_message", ctrl))

	if err = vpnlib.AddIpToIface(iface.Name(), ctrl.ClientIp, ctrl.ServerIp, ctrl.SubnetSize); err != nil {
		return established, fmt.Errorf("failed to add IPs to interface: %v", err)
	}

	// keep track of the routes we need to delete when we exit
	routesToDel := []networkRoute{}
	defer cleanUpAfterSessionDown(routesToDel)

	// Get the remote address of the tunnel connection
	// we'll use that to determine the address family
	remoteAddr := conn.RemoteAddr().(*net.TCPAddr)

	var vpnGatewayAf int // Tunnel over IPv4 or IPv6
	var vpnGatewayIp string

	if remoteAddr.IP.To4() != nil {
		vpnGatewayAf = 4
		vpnGatewayIp = remoteAddr.IP.String() + "/32"
	} else if remoteAddr.IP.To16() != nil {
		vpnGatewayAf = 6
		vpnGatewayIp = remoteAddr.IP.String() + "/128"
	} else {
		return established, fmt.Errorf("failed to determine address family for remote address: %v", remoteAddr.IP)
	}

	defaultV4GatewayIp, _, err := vpnlib.GetDefaultGateway(4)
	if err != nil {
		return established, fmt.Errorf("failed to get default IPv4 gateway: %v", err)
	}

	// The code block below only runs when the VPN gateway (i.e. the Border0 anycast proxies)
	// are being talked to via IPv4.
	//
	// The code ensures that the Border0 proxy keeps being reached via the *current* default gateway
	//
	// We don't care about doing this when the VPN gateway run on IPv6 because the VPN only supports
	// IPv4 routes, so there is currently no way that a VPN server can instruct a client to override
	// the existing route to the proxy.
	//
	// If we were not to do this (when VPN gateway has an IPv4) then the route to the VPN gateway
	// would be itself (in a loop). If we did not do it for VPN servers then its likely that
	// nothing would resolve (if the VPN server cannot connect to the dns server IP addresses).
	if vpnGatewayAf == 4 {
		for _, route := range ctrl.Routes {
			if route == "0.0.0.0/0" {
				if err = vpnlib.AddRoutesViaGateway(defaultV4GatewayIp.String(), []string{vpnGatewayIp}); err != nil {
					return established, fmt.Errorf("failed to add static route for VPN Gateway %s, towards %s: %v", vpnGatewayIp, defaultV4GatewayIp.String(), err)
				}
				routesToDel = append(routesToDel, networkRoute{network: vpnGatewayIp, nextHopIp: defaultV4GatewayIp.String()})
			}
		}
	}

	processedRoutes := []string{}
	for _, route := range ctrl.Routes {
		// special handling for v4 default route
		if route == "0.0.0.0/0" {
			processedRoutes = append(processedRoutes, "0.0.0.0/1", "128.0.0.0/1")
			continue
		}
		// special handling for v6 default route
		if route == "::/0" {
			processedRoutes = append(processedRoutes, "200::/3")
			continue
		}
		processedRoutes = append(processedRoutes, route)
	}
	ctrl.Routes = processedRoutes

	// handle routes to current DNS servers
	dnsServersBypassRoutes, err := vpnlib.GetDnsByPassRoutes(iface.Name(), ctrl.Routes, 4)
	if err != nil {
		return established, fmt.Errorf("failed to get DNS servers bypass routes: %v", err)
	}
	if len(dnsServersBypassRoutes) > 0 {
		for dnsServer := range dnsServersBypassRoutes {
			logger.Info(
				"adding bypass route for dns server",
				zap.String("dns_server", dnsServer),
				zap.String("default_gateway", defaultV4GatewayIp.String()),
			)
			err = vpnlib.AddRoutesViaGateway(defaultV4GatewayIp.String(), []string{dnsServer})
			if err != nil {
				logger.Error(
					"failed to add bypass route for DNS server",
					zap.String("dns_server", dnsServer),
					zap.String("default_gateway", defaultV4GatewayIp.String()),
					zap.Error(err),
				)
			}
			// ensures added routes get cleaned up
			routesToDel = append(routesToDel, networkRoute{network: dnsServer, nextHopIp: defaultV4GatewayIp.String()})
		}
	}

	// Now we can add the routes that the server sent to us a the client
	// These routes will be routed through the VPN

	// check if we're running on Windows , if so we need to sleep for a few seconds
	// Seems like it's slow to update the routing table on Windows
	// if we don't wait, windows will use the wrong "Interface" for the route.
	// It seems to then choose the old default gateway, which is not what we want
	// So we wait a few seconds, and then add the routes, it then picks the VPN interfaces as the correct interface
	if runtime.GOOS == "windows" {
		logger.Info("adding VPN routes, waiting 5 seconds for interface to be ready...")
		for i := 0; i < 10; i++ {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if err = vpnlib.AddRoutesViaGateway(ctrl.ServerIp, ctrl.Routes); err != nil {
		return established, fmt.Errorf("failed to add routes to interface: %v", err)
	}
	logger.Info("connected to vpn server", zap.String("remote_address", conn.RemoteAddr().String()))

	icmpConn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return established, fmt.Errorf("failed to open ICMP \"connection\": %v", err)
	}
	defer icmpConn.Close()

	go func() {
		<-parentCtx.Done()

		// When the parent context is done, the child
		// context will automatically be done as well.
		// The TunToConnCopy routing will automatically
		// be stopped. However, we *MUST* manually close
		// the socket connection because it is not tied
		// to the context. This will
		//   - stop the ConnToTunCopy routine which will make runClient() reach the end
		//   - a defer statement closes the TUN iface
		//   - a defer statement runs cleanUpAfterSessionDown() which removes added routes
		//   - a defer statement closes the icmp "conn"
		conn.Close()
	}()

	// Now start the Tun to Conn goroutine
	// This will listen for packets on the TUN interface and forward them to the right connection
	go vpnlib.TunToConnCopy(ctx, logger, iface, conn)

	// Let's start a goroutine that send keep alive ping messges to the other side
	go func() {
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: os.Getpid() & 0xffff, Seq: 1,
				Data: []byte("Border0-keepalive-ping"),
			},
		}
		// Convert message to bytes
		b, err := msg.Marshal(nil)
		if err != nil {
			logger.Error("error marshaling ICMP message, icmp keep-alives will be disabled for this session", zap.Error(err))
			return
		}

		icmpKeepAliveInterval := time.Second * 120
		lastPing := time.Now().Add(icmpKeepAliveInterval * -1)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				if time.Since(lastPing) >= icmpKeepAliveInterval {
					n, err := icmpConn.WriteTo(b, &net.IPAddr{IP: net.ParseIP(ctrl.ServerIp)})
					if err != nil {
						if errors.Is(err, net.ErrClosed) {
							return
						}
						logger.Info("error writing ICMP keep-alive message", zap.Error(err))
					} else if n != len(b) {
						logger.Info("wrote partial ICMP keep-alive message", zap.Int("bytes_written", n), zap.Int("message_size", len(b)))
					}
					lastPing = time.Now()
				}
			}
		}
	}()

	// Now start the Conn to Tun goroutine
	// This will listen for packets on the connection and forward them to the TUN interface
	// note: this blocks
	if err = vpnlib.ConnToTunCopy(ctx, logger, conn, ctrl.ServerIp, iface); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			return established, fmt.Errorf("failed to forward between tls conn and TUN iface: %v", err)
		}
	}

	return established, nil
}

func cleanUpAfterSessionDown(routesToDelete []networkRoute) {
	fmt.Println("Cleaning up routes...")

	for _, route := range routesToDelete {
		err := vpnlib.DeleteRoutesViaGateway(route.nextHopIp, []string{route.network})
		if err != nil {
			log.Println("failed to delete static route during session clean up", route.network, "via", route.nextHopIp, err)
		}
	}

	fmt.Println("Done cleaning up routes!")
}

func establishConnection(connectorAuthenticationEnabled, end2EndEncryptionEnabled bool, addr string, tlsConfig *tls.Config, caCertificate *x509.Certificate, useWsProxy bool) (conn net.Conn, err error) {
	conn, err = client.Connect(addr, true, tlsConfig, tlsConfig.Certificates[0], caCertificate, connectorAuthenticationEnabled, end2EndEncryptionEnabled, useWsProxy)
	return
}

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(clientVpnCmd)

	clientVpnCmd.Flags().StringVarP(&hostname, "service", "", "", "The Border0 service identifier")
	clientVpnCmd.Flags().BoolVarP(&useWsProxy, "wsproxy", "w", false, "Use websocket proxy")

}
