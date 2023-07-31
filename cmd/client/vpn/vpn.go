package vpn

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/borderzero/border0-cli/internal/vpnlib"
	"github.com/songgao/water"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

var (
	hostname string
)

// clientVpnCmd represents the client tls command
var clientVpnCmd = &cobra.Command{
	Use:               "vpn",
	Short:             "Start a Border0 VPN",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			hostname = args[0]
		}

		if hostname == "" {
			pickedHost, err := client.PickHost(hostname, enum.TLSSocket)
			if err != nil {
				return fmt.Errorf("failed to pick host: %v", err)
			}
			hostname = pickedHost.Hostname()
		}

		info, err := client.GetResourceInfo(logger.Logger, hostname)
		if err != nil {
			return fmt.Errorf("failed to get certificate: %v", err)
		}

		certificate := tls.Certificate{
			Certificate: [][]byte{info.Certficate.Raw},
			PrivateKey:  info.PrivateKey,
		}

		tlsConfig := tls.Config{
			Certificates:       []tls.Certificate{certificate},
			InsecureSkipVerify: true,
		}

		conn, err := establishConnection(info.ConnectorAuthenticationEnabled, fmt.Sprintf("%s:%d", hostname, info.Port), &tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect: %v", err)
		}

		defer conn.Close()

		iface, err := water.New(water.Config{DeviceType: water.TUN})
		if err != nil {
			return fmt.Errorf("failed to create TUN iface: %v", err)
		}
		logger.Logger.Info("Created TUN interface", zap.String("interface_name", iface.Name()))

		defer iface.Close()

		ctrl, err := vpnlib.GetControlMessage(conn)
		if err != nil {
			return fmt.Errorf("failed to get control message from connection: %v", err)
		}
		logger.Logger.Info("Received control message", zap.Any("control_message", ctrl))

		if err = vpnlib.AddIpToIface(iface.Name(), ctrl.ClientIp, ctrl.ServerIp, ctrl.SubnetSize); err != nil {
			return fmt.Errorf("failed to add static IPs to interface: %v", err)
		}

		if err = vpnlib.AddRoutesToIface(iface.Name(), ctrl.Routes); err != nil {
			return fmt.Errorf("failed to add routes to interface: %v", err)
		}

		// create the connection map
		cm := vpnlib.NewConnectionMap()
		cm.Set(ctrl.ServerIp, conn)
		defer cm.Delete(ctrl.ServerIp)

		// Now start the Tun to Conn goroutine
		// This will listen for packets on the TUN interface and forward them to the right connection
		go vpnlib.TunToConnCopy(iface, cm, true, conn)

		// Let's start a goroutine that send keep alive ping messges to the other side
		go func() {
			// Create ICMP Echo message
			c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
			if err != nil {
				fmt.Println("Error opening ICMP socket:", err)
				return
			}
			defer c.Close()
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
				fmt.Println("Error marshaling ICMP message:", err)
				return
			}

			for {
				// send an ICMP ping to ctrl.ServerIp
				n, err := c.WriteTo(b, &net.IPAddr{IP: net.ParseIP(ctrl.ServerIp)})
				if err != nil {
					fmt.Println("Error writing ICMP keep alive message:", err)
					return
				} else if n != len(b) {
					fmt.Println("Got short write from WriteTo")
					return
				}
				time.Sleep(120 * time.Second)
			}
		}()

		// Now start the Conn to Tun goroutine
		// This will listen for packets on the connection and forward them to the TUN interface
		// note: this blocks

		if err = vpnlib.ConnToTunCopy(conn, iface); err != nil {
			fmt.Println("Error forwarding packets:", err)
			return fmt.Errorf("failed to forward between tls conn and TUN iface: %v", err)
		}

		fmt.Println("Done forwarding packets")
		return nil
	},
}

func establishConnection(connectorAuthenticationEnabled bool, addr string, tlsConfig *tls.Config) (conn net.Conn, err error) {
	if connectorAuthenticationEnabled {
		conn, err = client.ConnectorAuthConnect(addr, tlsConfig)
	} else {
		conn, err = tls.Dial("tcp", addr, tlsConfig)
	}
	return
}

func AddCommandsTo(client *cobra.Command) {
	client.AddCommand(clientVpnCmd)

	clientVpnCmd.Flags().StringVarP(&hostname, "service", "", "", "The Border0 service identifier")
}
