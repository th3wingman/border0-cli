//go:build darwin

package nat

import (
	"time"

	"go.uber.org/zap"
)

// platform-dependent implementation of NATManager (for Darwin).
type managerDarwin struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of NATManager (for Darwin).
func newManagerForPlatform(logger *zap.Logger) (NATManager, error) {
	return &managerDarwin{
		logger:  logger,
		timeout: defaultNATCommandTimeout,
	}, nil
}

// SetupIPv4NAT sets up IPv4 NAT-ing.
func (m *managerDarwin) SetupIPv4NAT(devicesRange, iface string) error { return errNotSupported }

// SetupIPv6NAT sets up IPv6 NAT-ing.
func (m *managerDarwin) SetupIPv6NAT(devicesRange, iface string) error { return errNotSupported }

// CleanupIPv4NAT removes IPv4 NAT-ing.
func (m *managerDarwin) CleanupIPv4NAT(devicesRange, iface string) error { return errNotSupported }

// CleanupIPv6NAT removes IPv6 NAT-ing.
func (m *managerDarwin) CleanupIPv6NAT(devicesRange, iface string) error { return errNotSupported }

// SetupIPv4WireGuardIngress sets up ingress for udp-over-ipv4 traffic to the WireGuard bind port.
func (n *managerDarwin) SetupIPv4WireGuardIngress(port int) error { return errNotSupported }

// SetupIPv6WireGuardIngress sets up ingress for udp-over-ipv6 traffic to the WireGuard bind port.
func (n *managerDarwin) SetupIPv6WireGuardIngress(port int) error { return errNotSupported }

// SetupIPv4WireGuardIngress removes ingress for udp-over-ipv4 traffic to the WireGuard bind port.
func (n *managerDarwin) CleanupIPv4WireGuardIngress(port int) error { return errNotSupported }

// SetupIPv6WireGuardIngress removes ingress for udp-over-ipv6 traffic to the WireGuard bind port.
func (n *managerDarwin) CleanupIPv6WireGuardIngress(port int) error { return errNotSupported }
