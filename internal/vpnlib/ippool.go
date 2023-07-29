package vpnlib

import (
	"errors"
	"fmt"
	"sync"
)

// This is a pool of IPs that can be allocated to clients.
type IPPool struct {
	sync.Mutex
	ips map[string]bool

	serverIp   string
	subnetSize uint8
}

// NewIPPool creates a new IP pool based on the provided CIDR.
// This pool will be used to allocate IPs to clients. (think DHCP)
func NewIPPool(cidr string) (*IPPool, error) {
	usableIps, subnetSize, err := cidrToUsableIPs(cidr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cidr: %v", err)
	}

	serverIp := usableIps[0]
	ips := make(map[string]bool)
	for _, ip := range usableIps[1:] {
		ips[ip] = true
	}

	return &IPPool{
		ips:        ips,
		serverIp:   serverIp,
		subnetSize: subnetSize,
	}, nil
}

// GetServerIp returns the server ip
func (p *IPPool) GetServerIp() string {
	return p.serverIp
}

// GetSubnetSize returns the subnet size
func (p *IPPool) GetSubnetSize() uint8 {
	return p.subnetSize
}

// Allocate allocates an available IP address from the pool.
// This will find a free IP address and mark it as used.
func (p *IPPool) Allocate() (string, error) {
	p.Lock()
	defer p.Unlock()

	for ip, available := range p.ips {
		if available {
			p.ips[ip] = false
			return ip, nil
		}
	}
	return "", errors.New("IP Pool exhausted")
}

// Release releases an IP address back to the pool.
// This will mark the IP address as available.
func (p *IPPool) Release(ip string) {
	p.Lock()
	defer p.Unlock()

	if _, ok := p.ips[ip]; ok {
		p.ips[ip] = true
	}
}
