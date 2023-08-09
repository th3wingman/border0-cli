//go:build !openbsd
// +build !openbsd

package service_daemon

import (
	"runtime"
	"strings"

	"github.com/takama/daemon"
)

// New initializes a new service daemon object with a given name and description.
func New(name, description string) (daemon.Daemon, error) {
	deamonType := daemon.SystemDaemon
	if runtime.GOOS == "darwin" {
		deamonType = daemon.GlobalDaemon
	}
	daemon, err := daemon.New(name, description, deamonType)
	if err != nil {
		return nil, err
	}
	return daemon, err
}

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
