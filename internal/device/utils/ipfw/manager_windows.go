//go:build windows

package ipfw

import (
	"os/exec"
	"syscall"
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/command"
	"go.uber.org/zap"
)

// platform-dependent implementation of ForwardingManager (for Windows).
type managerWindows struct {
	logger  *zap.Logger
	timeout time.Duration
}

// newManagerForPlatform returns the default platform-dependent
// implementation of ForwardingManager (for Windows).
func newManagerForPlatform(logger *zap.Logger) ForwardingManager {
	return &managerWindows{
		logger:  logger,
		timeout: defaultForwardingCommandTimeout,
	}
}

// SetupIPv4Forwarding sets up IPv4 forwarding.
func (m *managerWindows) SetupIPv4Forwarding() error {
	return command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} },

		"powershell",
		"Set-ItemProperty",
		"-Path",
		`"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"`,
		"-Name",
		`"IPEnableRouter"`,
		"-Value",
		"1",
	)
}

// SetupIPv6Forwarding sets up IPv6 forwarding.
func (m *managerWindows) SetupIPv6Forwarding() error {
	return command.RunWithModifier(
		m.logger,
		m.timeout,
		func(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true} },

		"powershell",
		"Set-ItemProperty",
		"-Path",
		`"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"`,
		"-Name",
		`"IPEnableRouter"`,
		"-Value",
		"1",
	)
}
