package nat

import (
	"fmt"
	"runtime"
	"time"

	"go.uber.org/zap"
)

const defaultNATCommandTimeout = time.Second * 10

var errNotSupported = fmt.Errorf("enabling kernel-based NAT is not supported on %s", runtime.GOOS)

// NATManager represents an entity capable of NAT-ing traffic.
type NATManager interface {
	SetupIPv4NAT(devicesRange, iface string) error
	SetupIPv6NAT(devicesRange, iface string) error
	CleanupIPv4NAT(devicesRange, iface string) error
	CleanupIPv6NAT(devicesRange, iface string) error

	SetupIPv4WireGuardIngress(port int) error
	SetupIPv6WireGuardIngress(port int) error
	CleanupIPv4WireGuardIngress(port int) error
	CleanupIPv6WireGuardIngress(port int) error
}

// platform-independent implementation of ForwardingManager.
type natManager struct{ NATManager }

// noopNATManager implements NATManager with no-op operations
type noopNATManager struct{}

func (n *noopNATManager) SetupIPv4NAT(devicesRange, iface string) error   { return nil }
func (n *noopNATManager) SetupIPv6NAT(devicesRange, iface string) error   { return nil }
func (n *noopNATManager) CleanupIPv4NAT(devicesRange, iface string) error { return nil }
func (n *noopNATManager) CleanupIPv6NAT(devicesRange, iface string) error { return nil }
func (n *noopNATManager) SetupIPv4WireGuardIngress(port int) error        { return nil }
func (n *noopNATManager) SetupIPv6WireGuardIngress(port int) error        { return nil }
func (n *noopNATManager) CleanupIPv4WireGuardIngress(port int) error      { return nil }
func (n *noopNATManager) CleanupIPv6WireGuardIngress(port int) error      { return nil }

// NewManager returns a platform-independent implementation of NATManager.
func NewManager(logger *zap.Logger) (NATManager, error) {
	m, err := newManagerForPlatform(logger)
	if err != nil {
		logger.Warn("Failed to initialize NAT manager, using no-op implementation", zap.Error(err))
		return &noopNATManager{}, nil
	}

	return &natManager{m}, nil
}
