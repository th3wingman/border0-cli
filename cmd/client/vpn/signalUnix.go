//go:build !windows
// +build !windows

package vpn

import (
	"os"
	"os/signal"
	"syscall"
)

func setupSignalHandling(sigCh chan os.Signal) {
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL)
}
