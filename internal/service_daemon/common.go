package service_daemon

import (
	"strings"
)

const (
	notInstalledMessageDarwin  = "is not installed"
	notInstalledMessageLinux   = "is not installed"
	notInstalledMessageWindows = "does not exist"
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
		for _, notInstalledMsg := range []string{
			notInstalledMessageDarwin,
			notInstalledMessageLinux,
			notInstalledMessageWindows,
		} {
			if strings.Contains(err.Error(), notInstalledMsg) {
				return false, nil
			}
		}
		return false, err
	}
	return strings.Contains(status, "is running") || strings.Contains(status, "stopped"), nil
}
