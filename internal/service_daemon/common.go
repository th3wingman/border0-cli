package service_daemon

import (
	"strings"
)

// Service represents a service daemon.
type Service interface {
	Install(args ...string) (string, error)
	Remove() (string, error)
	Start() (string, error)
	Stop() (string, error)
	Status() (string, error)
}

// IsInstalled returns true if a given service is installed.
func IsInstalled(service Service) (bool, error) {
	status, err := service.Status()
	if err != nil {
		if err.Error() != "Service is not installed" {
			return false, err
		}
		return false, nil
	}
	return strings.Contains(status, "is running") || strings.Contains(status, "stopped"), nil
}
