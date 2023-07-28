package vpn

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/borderzero/border0-cli/internal/vpnlib"
	"github.com/songgao/water"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
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

		iface, err := water.New(water.Config{DeviceType: water.TUN})
		if err != nil {
			return fmt.Errorf("failed to create TUN iface: %v", err)
		}
		logger.Logger.Info("Created TUN interface", zap.String("interface_name", iface.Name()))

		ctrl, err := vpnlib.GetControlMessage(conn, time.Second*5)
		if err != nil {
			return fmt.Errorf("failed to get control message from connection: %v", err)
		}
		logger.Logger.Info("Received control message", zap.Any("control_message", ctrl))

		if err = vpnlib.AddIpToIface(iface.Name(), ctrl.ClientIp, ctrl.ServerIp); err != nil {
			return fmt.Errorf("failed to add static IPs to interface: %v", err)
		}

		if err = vpnlib.AddRoutesToIface(iface.Name(), ctrl.Routes); err != nil {
			return fmt.Errorf("failed to add routes to interface: %v", err)
		}

		// note: this blocks
		if err = vpnlib.PacketCopy(conn, iface); err != nil {
			return fmt.Errorf("failed to forward between tls conn and TUN iface: %v", err)
		}
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
