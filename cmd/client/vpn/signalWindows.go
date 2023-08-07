//go:build windows
// +build windows

package vpn

import (
	"os"
	"os/signal"
)

func setupSignalHandling(sigCh chan os.Signal) {
	signal.Notify(sigCh, os.Interrupt)

}
