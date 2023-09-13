package service_daemon

import (
	"errors"
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
	return false, errors.New("this code is going away!")
}
