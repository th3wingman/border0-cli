//go:build darwin

package ipfw

import (
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/command"
	"go.uber.org/zap"
)

// platform-dependent implementation of ForwardingManager (for Darwin).
type managerDarwin struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of ForwardingManager (for Darwin).
func newManagerForPlatform(logger *zap.Logger) ForwardingManager {
	return &managerDarwin{
		logger:  logger,
		timeout: defaultForwardingCommandTimeout,
	}
}

// SetupIPv4Forwarding sets up IPv4 forwarding.
func (m *managerDarwin) SetupIPv4Forwarding() error {
	return command.Run(
		m.logger,
		m.timeout,

		"sysctl",
		"--write", "net.inet.ip.forwarding=1",
	)
}

// SetupIPv6Forwarding sets up IPv6 forwarding.
func (m *managerDarwin) SetupIPv6Forwarding() error {
	return command.Run(
		m.logger,
		m.timeout,

		"sysctl",
		"--write", "net.inet6.ip6.forwarding=1",
	)
}
