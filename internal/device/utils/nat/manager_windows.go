//go:build windows

package nat

import (
	"time"

	"go.uber.org/zap"
)

// platform-dependent implementation of NATManager (for Windows).
type managerWindows struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of NATManager (for Windows).
func newManagerForPlatform(logger *zap.Logger) (NATManager, error) {
	return &managerWindows{
		logger:  logger,
		timeout: defaultNATCommandTimeout,
	}, nil
}

// SetupIPv4NAT sets up IPv4 NAT-ing.
func (m *managerWindows) SetupIPv4NAT(devicesRange, iface string) error { return errNotSupported }

// SetupIPv6NAT sets up IPv6 NAT-ing.
func (m *managerWindows) SetupIPv6NAT(devicesRange, iface string) error { return errNotSupported }

// CleanupIPv4NAT removes IPv4 NAT-ing.
func (m *managerWindows) CleanupIPv4NAT(devicesRange, iface string) error { return errNotSupported }

// CleanupIPv6NAT removes IPv6 NAT-ing.
func (m *managerWindows) CleanupIPv6NAT(devicesRange, iface string) error { return errNotSupported }

// SetupIPv4WireGuardIngress sets up ingress for udp-over-ipv4 traffic to the WireGuard bind port.
func (n *managerWindows) SetupIPv4WireGuardIngress(port int) error { return errNotSupported }

// SetupIPv6WireGuardIngress sets up ingress for udp-over-ipv6 traffic to the WireGuard bind port.
func (n *managerWindows) SetupIPv6WireGuardIngress(port int) error { return errNotSupported }

// SetupIPv4WireGuardIngress removes ingress for udp-over-ipv4 traffic to the WireGuard bind port.
func (n *managerWindows) CleanupIPv4WireGuardIngress(port int) error { return errNotSupported }

// SetupIPv6WireGuardIngress removes ingress for udp-over-ipv6 traffic to the WireGuard bind port.
func (n *managerWindows) CleanupIPv6WireGuardIngress(port int) error { return errNotSupported }
