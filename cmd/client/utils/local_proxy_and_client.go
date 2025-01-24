package utils

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/skratchdot/open-golang/open"
	"github.com/spf13/cobra"
)

func writeRdpConnFile(address string) (string, error) {
	rdpFileContents := []byte(fmt.Sprintf("full address:s:%s\nprompt for credentials:i:1", address))

	// Create temporary .rdp file
	tmpDir := os.TempDir()

	rdpFilePath := filepath.Join(tmpDir, fmt.Sprintf("temp-%d.rdp", time.Now().UnixNano())) // timestamped to avoid collisions on multiple runs
	if err := os.WriteFile(rdpFilePath, rdpFileContents, 0644); err != nil {
		return "", fmt.Errorf("failed to create RDP file: %w", err)
	}
	return rdpFilePath, nil
}

// StartLocalProxyAndOpenClient starts a local listener on the given
// local port and opens the system's default client application
// for specified protocol.
func StartLocalProxyAndOpenClient(
	cmd *cobra.Command,
	args []string,
	protocol string,
	hostname string,
	localListenerPort int,
	useWsProxy bool,
) error {
	info, err := client.GetResourceInfo(logger.Logger, hostname)
	if err != nil {
		return fmt.Errorf("failed to get certificate: %v", err)
	}

	certificate := tls.Certificate{
		Certificate: [][]byte{info.Certficate.Raw},
		PrivateKey:  info.PrivateKey,
	}

	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("failed to get system cert pool: %v", err.Error())
	}

	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      systemCertPool,
		ServerName:   hostname,
	}

	localListenerAddress := fmt.Sprintf("localhost:%d", localListenerPort)

	l, err := net.Listen("tcp", localListenerAddress)
	if err != nil {
		log.Fatalln("Error: Unable to start local TLS listener.")
	}

	// if the user didn't specify a local listener port, we used 0 to let the OS pick a port
	// we need to update the localListenerAddress to reflect the actual port chosen by the OS
	if localListenerPort == 0 {
		allocatedPort := l.Addr().(*net.TCPAddr).Port
		localListenerAddress = fmt.Sprintf("localhost:%d", allocatedPort)
	}

	log.Print("Waiting for connections on ", localListenerAddress, "...")

	clientOpenURI := fmt.Sprintf("%s://%s", protocol, localListenerAddress)
	postOpenCleanup := func() { /* noop */ }

	if protocol == "rdp" {
		rdpConnFilePath, err := writeRdpConnFile(localListenerAddress)
		if err != nil {
			return err
		}
		defer os.Remove(rdpConnFilePath)

		postOpenCleanup = func() {
			// best effort removal
			time.Sleep(time.Second * 5)
			os.Remove(rdpConnFilePath)
		}
		clientOpenURI = rdpConnFilePath
	}

	go func() {
		if err := open.Run(clientOpenURI); err != nil {
			log.Printf("Failed to open system's %s client: %v", protocol, err)
		}
		postOpenCleanup()
	}()

	for {
		lcon, err := l.Accept()
		if err != nil {
			log.Fatalf("Listener: Accept Error: %s\n", err)
		}

		go func() {
			conn, err := client.Connect(net.JoinHostPort(hostname, strconv.Itoa(info.Port)), true, &tlsConfig, certificate, info.CaCertificate, info.ConnectorAuthenticationEnabled, info.EndToEndEncryptionEnabled, useWsProxy)
			if err != nil {
				if errors.Is(err, client.ErrConnectorHandshakeFailed) || errors.Is(err, client.ErrProxyHandshakeFailed) {
					fmt.Printf("Error: %s. You may not be authorized for this socket. Speak to your Border0 administrator\n", err)
					return
				}
				fmt.Printf("failed to connect: %s\n", err)
				return
			}

			log.Print("Connection established from ", lcon.RemoteAddr())
			Copy(conn, lcon, lcon)
		}()
	}
}
