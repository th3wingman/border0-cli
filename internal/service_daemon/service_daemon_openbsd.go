//go:build openbsd
// +build openbsd

package service_daemon

import "fmt"

func New(name, description string) (Service, error) {
	return nil, fmt.Errorf("service not supported on openbsd")
}
