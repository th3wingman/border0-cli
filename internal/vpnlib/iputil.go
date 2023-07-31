package vpnlib

import (
	"fmt"
	"net"
)

const (
	ipv4HeaderLengthBytes = 20
	subnetMaxSize         = 30
)

func cidrToUsableIPs(cidr string) ([]string, uint8, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid cidr range: %v", err)
	}

	subnetSize, _ := ipnet.Mask.Size()
	if subnetSize > subnetMaxSize {
		return nil, 0, fmt.Errorf("invalid cidr range, must have at least 2 usable addresses (i.e. /30 or less), got %d", subnetSize)
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIp(ip) {
		ips = append(ips, ip.String())
	}

	// remove network and broadcast addresses
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	return ips, uint8(subnetSize), nil
}

func incIp(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parseIpFromPacketHeader(packet []byte) (net.IP, net.IP) {
	return net.IP(packet[12:16]), net.IP(packet[16:20])
}

func validateIPv4(packet []byte) error {
	if len(packet) < ipv4HeaderLengthBytes {
		return fmt.Errorf("packet too short")
	}
	ipVersion := (packet[0] & 0xF0) >> 4
	if ipVersion != 4 {
		return fmt.Errorf("packet header advertises non IPv4")
	}
	return nil
}
