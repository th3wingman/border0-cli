//go:build linux

package ipfw

import (
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/command"
	"go.uber.org/zap"
)

// platform-dependent implementation of ForwardingManager (for Linux).
type managerLinux struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of ForwardingManager (for Linux).
func newManagerForPlatform(logger *zap.Logger) ForwardingManager {
	return &managerLinux{
		logger:  logger,
		timeout: defaultForwardingCommandTimeout,
	}
}

// SetupIPv4Forwarding sets up IPv4 forwarding.
func (m *managerLinux) SetupIPv4Forwarding() error {
	return command.Run(
		m.logger,
		m.timeout,

		"sysctl",
		"--write", "net.ipv4.ip_forward=1",
	)
}

// SetupIPv6Forwarding sets up IPv6 forwarding.
func (m *managerLinux) SetupIPv6Forwarding() error {
	return command.Run(
		m.logger,
		m.timeout,

		"sysctl",
		"--write", "net.ipv6.conf.all.forwarding=1",
	)
}
