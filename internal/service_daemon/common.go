package service_daemon

import (
	"strings"

	"github.com/takama/daemon"
)

// IsInstalled returns true if a given service is installed.
func IsInstalled(service daemon.Daemon) (bool, error) {
	status, err := service.Status()
	if err != nil {
		if err.Error() != "Service is not installed" {
			return false, err
		}
		return false, nil
	}
	return strings.Contains(status, "is running"), nil
}
