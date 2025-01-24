package db

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/borderzero/border0-cli/client/preference"
	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/spf13/cobra"
)

var tableplusCmd = &cobra.Command{
	Use:   "db:tableplus",
	Short: "Connect to a database socket with TablePlus",
	RunE: func(cmd *cobra.Command, args []string) error {
		pickedHost, err := client.PickHost(hostname, enum.DatabaseSocket)
		if err != nil {
			return err
		}
		hostname = pickedHost.Hostname()

		// Let's read preferences from the config file
		pref, err := preference.Read()
		if err != nil {
			fmt.Println("WARNING: could not read preference file:", err)
		}
		socketPref := preference.NewDatabaseSocket(hostname)

		dbName := dbNameFrom(args)

		if pickedHost.DatabaseType == enum.DatabaseTypePostgres {
			// Postgres databases require a database name to connect

			var suggestedDBName string

			if dbName == "" {
				suggestedSocket := pref.GetOrSuggestSocket(hostname, enum.DatabaseSocket)
				if preference.Found(suggestedSocket) {
					suggestedDBName = suggestedSocket.DatabaseName
					socketPref = suggestedSocket
				}
			}

			dbName, err = client.EnterDBName(dbName, suggestedDBName)
			if err != nil {
				return err
			}

			socketPref.DatabaseName = dbName
		}

		socketPref.DatabaseClient = "tableplus"
		pref.SetSocket(socketPref)

		if err := preference.Write(pref); err != nil {
			fmt.Println("WARNING: could not update preference file:", err)
		}

		info, err := client.GetResourceInfo(logger.Logger, hostname)
		if err != nil {
			return err
		}

		var connStr string

		if info.PrivateNetworkEnabled {
			// Connect over VPN
			// No need to start a listener

			connStr = fmt.Sprintf(
				"%s://%s:%d/%s?Environment=local&name=%s",
				pickedHost.DatabaseType,
				info.SocketName,
				info.Port,
				dbName,
				info.SocketName,
			)
		} else {
			// Connect over TLS via proxy
			// Need to start a listener

			if info.ConnectorAuthenticationEnabled || info.EndToEndEncryptionEnabled || useWsProxy {
				info.Port, err = client.StartConnectorAuthListener(hostname, info.Port, info.SetupTLSCertificate(), info.CaCertificate, 0, info.ConnectorAuthenticationEnabled, info.EndToEndEncryptionEnabled, useWsProxy)
				if err != nil {
					return fmt.Errorf("could not start listener: %w", err)
				}

				hostname = "localhost"
			}

			connStr = fmt.Sprintf(
				"%s://%s:%d/%s?Environment=local&name=%s",
				pickedHost.DatabaseType,
				"127.0.0.1",
				info.Port,
				dbName,
				pickedHost.Hostname(),
			)
		}

		fmt.Println("Starting up TablePlus...")
		switch runtime.GOOS {
		case "darwin":
			err = client.ExecCommand("open", connStr, "-a", "TablePlus")
		default:
			return fmt.Errorf("the TablePlus database client is not supported for this operating system (%s)", runtime.GOOS)
		}

		if !info.PrivateNetworkEnabled {
			// Connect over TLS via proxy
			// Need to wait for the user to close the connection

			if info.ConnectorAuthenticationEnabled || info.EndToEndEncryptionEnabled {
				ch := make(chan os.Signal, 1)
				signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
				<-ch
			}
		}

		return err
	},
}
