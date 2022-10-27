//go:build windows
// +build windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

func handleSignals(chsyscall chan os.Signal) {

	signal.Notify(chsyscall, os.Interrupt, syscall.SIGTERM,
		syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT,
		syscall.SIGHUP, syscall.SIGALRM)

}
