//go:build openbsd

package ipfw

import (
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/command"
	"go.uber.org/zap"
)

// platform-dependent implementation of ForwardingManager (for OpenBSD).
type managerOpenBSD struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of ForwardingManager (for OpenBSD).
func newManagerForPlatform(logger *zap.Logger) ForwardingManager {
	return &managerOpenBSD{
		logger:  logger,
		timeout: defaultForwardingCommandTimeout,
	}
}

// SetupIPv4Forwarding sets up IPv4 forwarding for BSD.
func (m *managerOpenBSD) SetupIPv4Forwarding() error {
	return command.Run(
		m.logger,
		m.timeout,

		"sudo",
		"sysctl",
		"net.inet.ip.forwarding=1",
	)
}

// SetupIPv6Forwarding sets up IPv6 forwarding for BSD.
func (m *managerOpenBSD) SetupIPv6Forwarding() error {
	return command.Run(
		m.logger,
		m.timeout,

		"sudo",
		"sysctl",
		"net.inet6.ip6.forwarding=1",
	)
}
