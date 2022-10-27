//go:build !windows
// +build !windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"
)

func handleSignals(chsyscall chan os.Signal) {
	signals := []os.Signal{os.Interrupt, syscall.SIGTERM,
		syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT,
		syscall.SIGTSTP, syscall.SIGHUP, syscall.SIGALRM, syscall.SIGUSR1, syscall.SIGUSR2}

	signal.Notify(chsyscall, signals...)

}
