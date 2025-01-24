package state

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/border0-go/types/service"
)

const (
	// IPv4DefaultRoute represents the entire IPv4 Internet.
	IPv4DefaultRoute = "0.0.0.0/0"

	// IPv6DefaultRoute represents the entire IPv6 Internet.
	IPv6DefaultRoute = "::/0"
)

type ServiceConfig struct {
	Name         string   `yaml:"name,omitempty" json:"name,omitempty"`
	Type         string   `yaml:"type,omitempty" json:"type,omitempty"`
	IPv4Address  string   `yaml:"ipv4_address,omitempty" json:"ipv4_address,omitempty"`
	IPv6Address  string   `yaml:"ipv6_address,omitempty" json:"ipv6_address,omitempty"`
	SubnetRoutes []string `yaml:"subnet_routes,omitempty" json:"subnet_routes,omitempty"`
	DNSName      string   `yaml:"dns_name,omitempty" json:"dns_name,omitempty"`
	UpstreamType string   `yaml:"upstream_type,omitempty" json:"upstream_type,omitempty"`

	// below are runtime objects which should not be serialized
	RuntimeIPv4Address  netip.Addr     `yaml:"-" json:"-"`
	RuntimeIPv6Address  netip.Addr     `yaml:"-" json:"-"`
	RuntimeSubnetRoutes []netip.Prefix `yaml:"-" json:"-"`
}

// PeerConfig represents configuration for a single peer.
type PeerConfig struct {
	Name                        string           `yaml:"name" json:"name"`
	PublicKey                   string           `yaml:"public_key" json:"public_key"`
	EndpointUDP4                string           `yaml:"endpoint_udp4,omitempty" json:"endpoint_udp4,omitempty"`
	EndpointUDP6                string           `yaml:"endpoint_udp6,omitempty" json:"endpoint_udp6,omitempty"`
	PersistentKeepaliveInterval time.Duration    `yaml:"persistent_keepalive_interval" json:"persistent_keepalive_interval"`
	IPv4Address                 string           `yaml:"ipv4_address,omitempty" json:"ipv4_address,omitempty"`
	IPv6Address                 string           `yaml:"ipv6_address,omitempty" json:"ipv6_address,omitempty"`
	Services                    []*ServiceConfig `yaml:"services,omitempty" json:"services,omitempty"`

	// below are runtime objects which should not be serialized
	RuntimePublicKey    *nacl.PublicKey `yaml:"-" json:"-"`
	RuntimeEndpointUDP4 netip.AddrPort  `yaml:"-" json:"-"`
	RuntimeEndpointUDP6 netip.AddrPort  `yaml:"-" json:"-"`
	RuntimeIPv4Address  netip.Addr      `yaml:"-" json:"-"`
	RuntimeIPv6Address  netip.Addr      `yaml:"-" json:"-"`
}

// decodeAndValidate decodes the string values of a
// PeerConfig onto the respective runtime objects.
func (p *PeerConfig) decodeAndValidate(exitNode string) error {
	// decode key
	wgkey, err := nacl.ParsePublicKeyB64(p.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse peer's public key as a wgtypes.Key object: %v", err)
	}
	p.RuntimePublicKey = wgkey

	// decode udp4 endpoint
	if p.EndpointUDP4 != "" {
		endpointUDP4AddrPort, err := netip.ParseAddrPort(p.EndpointUDP4)
		if err != nil {
			return fmt.Errorf("failed to parse peer's (non-empty) udp4 endpoint as a netip.AddrPort object: %v", err)
		}
		p.RuntimeEndpointUDP4 = endpointUDP4AddrPort
	}

	// decode udp6 endpoint
	if p.EndpointUDP6 != "" {
		endpointUDP6AddrPort, err := netip.ParseAddrPort(p.EndpointUDP6)
		if err != nil {
			return fmt.Errorf("failed to parse peer's (non-empty) udp6 endpoint as a netip.AddrPort object: %v", err)
		}
		p.RuntimeEndpointUDP6 = endpointUDP6AddrPort
	}

	// decode peer's ipv4 in private network
	if p.IPv4Address != "" {
		ipv4Addr, err := netip.ParseAddr(p.IPv4Address)
		if err != nil {
			return fmt.Errorf("failed to parse peer's (non-empty) ipv4 address as a netip.Addr object: %v", err)
		}
		p.RuntimeIPv4Address = ipv4Addr
	}

	// decode peer's ipv6 in private network
	if p.IPv6Address != "" {
		ipv6Addr, err := netip.ParseAddr(p.IPv6Address)
		if err != nil {
			return fmt.Errorf("failed to parse peer's (non-empty) ipv6 address as a netip.Addr object: %v", err)
		}
		p.RuntimeIPv6Address = ipv6Addr
	}

	// decode peer's services
	for i, service := range p.Services {
		if err := service.decodeAndValidate(exitNode); err != nil {
			return fmt.Errorf("failed to decode and validate service at index %d for peer %s: %v", i, err, p.PublicKey)
		}
	}

	return nil
}

// decodeAndValidate decodes the string values of a
// ServiceConfig onto the respective runtime objects.
func (c *ServiceConfig) decodeAndValidate(exitNode string) error {

	// decode service's ipv4 in private network
	if c.IPv4Address != "" {
		ipv4Addr, err := netip.ParseAddr(c.IPv4Address)
		if err != nil {
			return fmt.Errorf("failed to parse service's (non-empty) ipv4 address as a netip.Addr object: %v", err)
		}
		c.RuntimeIPv4Address = ipv4Addr
	}

	// decode service's ipv6 in private network
	if c.IPv6Address != "" {
		ipv6Addr, err := netip.ParseAddr(c.IPv6Address)
		if err != nil {
			return fmt.Errorf("failed to parse service's (non-empty) ipv6 address as a netip.Addr object: %v", err)
		}
		c.RuntimeIPv6Address = ipv6Addr
	}

	// decode subnet routes
	subnetRoutes := []netip.Prefix{}
	for i, route := range c.SubnetRoutes {
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return fmt.Errorf("failed to parse service's subnet route at index %d (%s) as a netip.Prefix object: %v", i, route, err)
		}
		subnetRoutes = append(subnetRoutes, prefix)
	}
	c.RuntimeSubnetRoutes = subnetRoutes

	if c.Type == service.ServiceTypeExitNode && c.Name == exitNode {
		c.RuntimeSubnetRoutes = []netip.Prefix{
			netip.MustParsePrefix(IPv4DefaultRoute),
			netip.MustParsePrefix(IPv6DefaultRoute),
		}
	}

	return nil
}
