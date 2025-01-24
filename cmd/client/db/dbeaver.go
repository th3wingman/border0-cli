package db

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/borderzero/border0-cli/client/preference"
	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/spf13/cobra"
)

var dbeaverCmd = &cobra.Command{
	Use:   "db:dbeaver",
	Short: "Connect to a database socket with dbeaver",
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

		var suggestedDBName string

		dbName := dbNameFrom(args)
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
		socketPref.DatabaseClient = "dbeaver"
		pref.SetSocket(socketPref)

		info, err := client.GetResourceInfo(logger.Logger, hostname)
		if err != nil {
			return err
		}

		var driver string
		switch pickedHost.DatabaseType {
		case "mysql":
			driver = "mariadb"
		case "mssql":
			driver = "microsoft"
		case "postgres":
			driver = "postgresql"
		default:
			driver = "mariadb"
		}

		var connectionParams []string

		if info.PrivateNetworkEnabled {
			// Connect over VPN
			// No need to add SSL certificates
			// No need to start a listener

			connectionParams = []string{
				"host=" + info.SocketName,
				"port=" + fmt.Sprint(info.Port),
				"database=" + dbName,
				"driver=" + driver,
				"user=placeholder",
				"savePassword=true", // does not ask user for a password on connection
				"openConsole=true",  // opens the SQL console for this database (also sets connect to true)
				"prop.useSSL=false",
			}
		} else {
			// Connect over TLS via proxy
			// Need to add SSL certificates
			// Need to start a listener

			connectionName := hostname

			if info.ConnectorAuthenticationEnabled || info.EndToEndEncryptionEnabled || useWsProxy {
				info.Port, err = client.StartConnectorAuthListener(hostname, info.Port, info.SetupTLSCertificate(), info.CaCertificate, 0, info.ConnectorAuthenticationEnabled, info.EndToEndEncryptionEnabled, useWsProxy)
				if err != nil {
					return fmt.Errorf("could not start listener: %w", err)
				}

				hostname = "localhost"
			}

			keyStore, keyStorePassword, _ := client.CertToKeyStore(info.Certficate, info.PrivateKey)
			defer client.Zeroing(keyStorePassword)

			home, err := util.GetUserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home dir : %w", err)
			}

			_, claims, err := client.MTLSLogin(logger.Logger, connectionName)
			if err != nil {
				return err
			}

			orgID := fmt.Sprint(claims["org_id"])
			keyStorePath := filepath.Join(home, ".border0", orgID+".jks")
			client.WriteKeyStore(keyStore, keyStorePath, keyStorePassword)

			// for more about jdbc driver properties, see:
			// https://dev.mysql.com/doc/connector-j/5.1/en/connector-j-connp-props-security.html
			// also see this page for connection parameters:
			// https://github.com/dbeaver/dbeaver/wiki/Command-Line#connection-parameters
			connectionParams = []string{
				"host=" + hostname,
				"port=" + fmt.Sprint(info.Port),
				"database=" + dbName,
				"prop.clientCertificateKeyStoreUrl=file:" + keyStorePath,
				"prop.clientCertificateKeyStorePassword=" + string(keyStorePassword),
				"driver=" + driver,
				"user=placeholder",
				"savePassword=true", // does not ask user for a password on connection
				"openConsole=true",  // opens the SQL console for this database (also sets connect to true)
			}

			if info.ConnectorAuthenticationEnabled || info.EndToEndEncryptionEnabled || useWsProxy {
				if info.ConnectorAuthenticationEnabled {
					// NOTE: temp fix - do this to bypass the error that complains the mismatch between
					//       private hostname and the CN in certificate (*.border0.io)
					connectionParams = append(connectionParams, "prop.disableSslHostnameVerification=true")
				}
				// when using connector authentication, e2e encryption or ws proxy, we started a local listener
				// and it does not require SSL, so we disable it to avoid server side ssl error in dbeaver
				connectionParams = append(connectionParams, "prop.sslMode=disable")
			} else {
				// otherwise, we use trust mode to enable SSL
				connectionParams = append(connectionParams, []string{
					"prop.sslMode=trust",
					// backward compatibile with older versions jdbc mariadb driver
					"prop.useSSL=true",
					"prop.verifyServerCertificate=false",
					"prop.requireSSL=false",
				}...)
			}
		}

		connStr := strings.Join(connectionParams, "|")

		persistPreference := func() {
			// persist preference to json file
			if err == nil {
				if err := preference.Write(pref); err != nil {
					fmt.Println("WARNING: could not update preference file:", err)
				}
			}
		}
		// make sure we will persist preference on successful connection to socket
		defer persistPreference()
		client.OnInterruptDo(persistPreference)

		fmt.Println("Starting up DBeaver...")
		switch runtime.GOOS {
		case "darwin":
			err = client.ExecCommand("open", "-a", "dbeaver", "--args", "-con", connStr)
		case "windows":
			connStr = `"` + connStr + `"`
			err = client.ExecCommand("cmd", "/C", "start", "", `c:\Program Files\DBeaver\dbeaver.exe`, "-con", connStr)
		default:
			err = client.ExecCommand("dbeaver", "-con", connStr)
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
