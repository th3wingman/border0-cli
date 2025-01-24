package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
)

const defaultUnixSckPath = "/var/run/border0.sock"

var (
	unixSckPath             = getUnixSocketPath()
	windowsFallbackAddrFile = filepath.Join(os.Getenv("PROGRAMDATA"), "border0-device.addr")
	windowsTCPAddr          = "127.0.0.1:0"
)

// getUnixSocketPath checks if the BORDER0_UNIX_SOCKET environment variable is set.
func getUnixSocketPath() string {
	if envPath := os.Getenv("BORDER0_UNIX_SOCKET"); envPath != "" {
		return envPath
	}
	return defaultUnixSckPath
}

func GetHTTPClient() (*http.Client, error) {
	var dialAddr string

	switch runtime.GOOS {
	case "windows":
		// Read the TCP address from the file
		addr, err := os.ReadFile(windowsFallbackAddrFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read TCP address from file: %w", err)
		}
		dialAddr = string(addr)
	default:
		dialAddr = "unix:" + unixSckPath
	}

	client := &http.Client{
		Transport: &http.Transport{
			Dial: func(_, _ string) (net.Conn, error) {
				if runtime.GOOS == "windows" {
					return net.Dial("tcp", dialAddr)
				}
				return net.Dial("unix", unixSckPath)
			},
		},
	}

	return client, nil
}

func GetHTTPListener() (net.Listener, error) {
	filesToCleanUp := []string{unixSckPath, windowsFallbackAddrFile}
	for _, file := range filesToCleanUp {
		_, err := os.Stat(file)
		// the result from os.IsNotExist is more reliable than os.IsExist
		if !os.IsNotExist(err) {
			if err := os.Remove(file); err != nil {
				return nil, fmt.Errorf("failed to clean up file [%s]: %w", file, err)
			}
		}
	}
	switch runtime.GOOS {
	case "windows":
		listener, err := net.Listen("tcp", windowsTCPAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen to local tcp port: %w", err)
		}
		content := []byte(listener.Addr().String())

		if err := os.WriteFile(windowsFallbackAddrFile, content, 0666); err != nil {
			return nil, fmt.Errorf("failed to write local tcp port to file: %w", err)
		}
		return listener, nil
	default:
		unixListener, err := net.Listen("unix", unixSckPath)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on unix socket %s: %v", unixSckPath, err)
		}
		if err := os.Chmod(unixSckPath, 0666); err != nil {
			unixListener.Close()
			return nil, fmt.Errorf("failed to chmod unix socket %s: %v", unixSckPath, err)
		}
		return unixListener, nil
	}
}
