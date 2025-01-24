//go:build openbsd

package routes

import (
	"net/netip"
	"time"

	"go.uber.org/zap"
)

// platform-dependent implementation of RouteManager (for OpenBSD).
type managerOpenBSD struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of RouteManager (for OpenBSD).
func newManagerForPlatform(logger *zap.Logger) RouteManager {
	return &managerOpenBSD{
		logger:  logger,
		timeout: defaultRouteCommandTimeout,
	}
}

// GetDnsResolvers returns all DNS resolver addresses.
func (m *managerOpenBSD) GetDnsResolvers() ([]netip.Addr, error) { return nil, errNotImplemented }

// GetDefaultV4Gateway gets the interface name and
// the IP address of the default gateway for IPv4.
func (m *managerOpenBSD) GetDefaultV4Gateway() (string, string, bool, error) {
	return "", "", false, errNotImplemented
}

// GetDefaultV6Gateway gets the interface name and
// the IP address of the default gateway for IPv6.
func (m *managerOpenBSD) GetDefaultV6Gateway() (string, string, bool, error) {
	return "", "", false, errNotImplemented
}

// AssignV4Address assigns an IPv4 address to a given interface.
func (m *managerOpenBSD) AssignV4Address(iface, ipv4 string) error { return errNotImplemented }

// AssignV6Address assigns an IPv6 address to a given interface.
func (m *managerOpenBSD) AssignV6Address(iface, ipv6 string) error { return errNotImplemented }

// AddV4Route adds a route for traffic for an IPv4 subnet to be routed to the given interface.
func (m *managerOpenBSD) AddV4Route(iface, cidrv4 string) error { return errNotImplemented }

// AddV6Route adds a route for traffic for an IPv6 subnet to be routed to the given interface.
func (m *managerOpenBSD) AddV6Route(iface, cidrv6 string) error { return errNotImplemented }

// AddV4RouteViaGateway adds a route for traffic for an IPv4 subnet to be routed to the given gateway.
func (m *managerOpenBSD) AddV4RouteViaGateway(iface, gwip, ipv4 string) error {
	return errNotImplemented
}

// AddV6RouteViaGateway adds a route for traffic for an IPv6 subnet to be routed to the given gateway.
func (m *managerOpenBSD) AddV6RouteViaGateway(iface, gwip, ipv6 string) error {
	return errNotImplemented
}

// RouteExists checks if a route for the given CIDR exists (optionally via the given gateway).
func (m *managerOpenBSD) RouteExists(cidr string, gwip string) (bool, error) {
	return false, errNotImplemented
}

// DeleteRoute deletes a route for a given CIDR (v4 or v6).
func (m *managerOpenBSD) DeleteRoute(cidr string, gwip string) error { return errNotImplemented }
