package wgmgr

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/borderzero/border0-cli/internal/device/state"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func writeConfig(w io.Writer, cfg wgtypes.Config) error {
	if cfg.PrivateKey != nil {
		if _, err := fmt.Fprintf(w, "private_key=%s\n", hexKey(*cfg.PrivateKey)); err != nil {
			return fmt.Errorf("failed to write private_key config: %v", err)
		}
	}

	if cfg.ListenPort != nil {
		if _, err := fmt.Fprintf(w, "listen_port=%d\n", *cfg.ListenPort); err != nil {
			return fmt.Errorf("failed to write listen_port config: %v", err)
		}
	}

	if cfg.FirewallMark != nil {
		if _, err := fmt.Fprintf(w, "fwmark=%d\n", *cfg.FirewallMark); err != nil {
			return fmt.Errorf("failed to write fwmark config: %v", err)
		}
	}

	if cfg.ReplacePeers {
		if _, err := fmt.Fprintln(w, "replace_peers=true"); err != nil {
			return fmt.Errorf("failed to write replace_peers config: %v", err)
		}
	}

	for _, p := range cfg.Peers {
		if _, err := fmt.Fprintf(w, "public_key=%s\n", hexKey(p.PublicKey)); err != nil {
			return fmt.Errorf("failed to write public_key config for peer: %v", err)
		}

		if p.Remove {
			if _, err := fmt.Fprintln(w, "remove=true"); err != nil {
				return fmt.Errorf("failed to write remove config for peer: %v", err)
			}
		}

		if p.UpdateOnly {
			if _, err := fmt.Fprintln(w, "update_only=true"); err != nil {
				return fmt.Errorf("failed to write update_only config for peer: %v", err)
			}
		}

		if p.PresharedKey != nil {
			if _, err := fmt.Fprintf(w, "preshared_key=%s\n", hexKey(*p.PresharedKey)); err != nil {
				return fmt.Errorf("failed to write preshared_key config for peer: %v", err)
			}
		}

		if p.Endpoint != nil {
			// NOTE(@adriano): here we would normally use p.Endpoint.String() in order to use
			// the peer's public IP address:port as the identifier of the peer/endpoint. However
			// endpoint here is really just any string that uniquely identifies the peer... It
			// doesn't matter what this is as long as the conn.Bind interface implementation's
			// "ParseEndpoint(endpoint string)" method returns the conn.Endpoint that corresponds
			// to the appropriate peer/endpoint.
			//
			// We've taken the liberty of using the public key (base64 encoded) as the unique
			// identifier here, and from the public key we can determine the peer's upd-over-ipv4
			// and udp-over-ipv6 addresses in other parts of the code.
			if _, err := fmt.Fprintf(w, "endpoint=%s\n", p.PublicKey.String()); err != nil {
				return fmt.Errorf("failed to write endpoint config for peer: %v", err)
			}
		}

		if p.PersistentKeepaliveInterval != nil {
			if _, err := fmt.Fprintf(w, "persistent_keepalive_interval=%d\n", int(p.PersistentKeepaliveInterval.Seconds())); err != nil {
				return fmt.Errorf("failed to write persistent_keepalive_interval config for peer: %v", err)
			}
		}

		if p.ReplaceAllowedIPs {
			if _, err := fmt.Fprintln(w, "replace_allowed_ips=true"); err != nil {
				return fmt.Errorf("failed to write replace_allowed_ips config for peer: %v", err)
			}
		}

		for _, ip := range p.AllowedIPs {
			if _, err := fmt.Fprintf(w, "allowed_ip=%s\n", ip.String()); err != nil {
				return fmt.Errorf("failed to write allowed_ip config: %v", err)
			}
		}
	}

	return nil
}

func hexKey(k wgtypes.Key) string {
	return hex.EncodeToString(k[:])
}

func ping(ip netip.Addr, n int, interval time.Duration) {
	network := "ip4:icmp"
	if ip.Is6() {
		network = "ip6:icmp"
	}
	conn, err := net.Dial(network, ip.String())
	if err != nil {
		return
	}
	defer conn.Close()
	for i := 1; i <= n; i++ {
		message := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff, // ICMP ID
				Seq:  i,
				Data: []byte("HELLO-R-U-THERE"),
			},
		}
		bin, err := message.Marshal(nil)
		if err != nil {
			continue
		}
		_, err = conn.Write(bin)
		if err != nil {
			continue
		}
		time.Sleep(interval)
	}
}

func findAvailableTunName(iface string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	existing := make(map[string]bool)
	for _, intf := range interfaces {
		existing[intf.Name] = true
	}

	if iface != "" {
		if !existing[iface] {
			return iface, nil
		}
	}

	// requested iface name not available, find another available name
	for i := 1; i <= maxUtunValue; i++ {
		name := fmt.Sprintf("utun%d", i)
		if !existing[name] {
			return name, nil
		}
	}

	return "", fmt.Errorf("no utun interface name available under %d", maxUtunValue)
}

func addrChanged(a, b net.Addr) (string, string, bool) {
	astr := ""
	bstr := ""
	if a != nil {
		astr = a.String()
	}
	if b != nil {
		bstr = b.String()
	}
	return astr, bstr, astr != bstr
}

func transformPeer(pc *state.PeerConfig) wgtypes.PeerConfig {

	allowedIPs := []net.IPNet{}

	if pc.RuntimeIPv6Address.IsValid() {
		allowedIPs = append(allowedIPs, net.IPNet{
			IP:   pc.RuntimeIPv6Address.AsSlice(),
			Mask: net.CIDRMask(ipv6Bits, ipv6Bits),
		})
	}
	if pc.RuntimeIPv4Address.IsValid() {
		allowedIPs = append(allowedIPs, net.IPNet{
			IP:   pc.RuntimeIPv4Address.AsSlice(),
			Mask: net.CIDRMask(ipv4Bits, ipv4Bits),
		})
	}

	for _, svc := range pc.Services {
		if svc.RuntimeIPv6Address.IsValid() {
			allowedIPs = append(allowedIPs, net.IPNet{
				IP:   svc.RuntimeIPv6Address.AsSlice(),
				Mask: net.CIDRMask(ipv6Bits, ipv6Bits),
			})
		}
		if svc.RuntimeIPv4Address.IsValid() {
			allowedIPs = append(allowedIPs, net.IPNet{
				IP:   svc.RuntimeIPv4Address.AsSlice(),
				Mask: net.CIDRMask(ipv4Bits, ipv4Bits),
			})
		}
		for _, snroute := range svc.RuntimeSubnetRoutes {
			if snroute.IsValid() {
				allowedIPs = append(allowedIPs, net.IPNet{
					IP:   snroute.Addr().AsSlice(),
					Mask: net.CIDRMask(snroute.Bits(), snroute.Addr().BitLen()),
				})
			}
		}
	}

	return wgtypes.PeerConfig{
		PublicKey:                   *pc.RuntimePublicKey.Raw(),
		Endpoint:                    net.UDPAddrFromAddrPort(pc.RuntimeEndpointUDP4),
		PersistentKeepaliveInterval: &pc.PersistentKeepaliveInterval,
		AllowedIPs:                  allowedIPs,
		ReplaceAllowedIPs:           true,
	}
}
