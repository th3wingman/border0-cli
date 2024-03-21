package install

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	awsc "github.com/aws/aws-sdk-go-v2/config"
	"github.com/borderzero/border0-cli/internal/connector_v2/config"
	"github.com/borderzero/border0-cli/internal/connector_v2/daemon"
	"github.com/borderzero/border0-cli/internal/connector_v2/invite"
	"github.com/borderzero/border0-cli/internal/util"
	"gopkg.in/yaml.v3"
)

// RunInstallWizard runs the connector install wizard for the local machine.
func RunInstallWizard(
	ctx context.Context,
	version string,
	daemonOnly bool,
	token string,
	inviteCode string,
	tokenPersistenceSsmPath string,
) error {
	// ensure not already installed
	ok, err := daemon.IsInstalled()
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("The Border0 Connector is already installed")
	}

	connectorToken := ""
	if !daemonOnly {
		// get the system hostname to derive the connector name off of
		hostname, err := util.GetFormattedHostname()
		if err != nil {
			return fmt.Errorf("failed to get system hostname: %v", err)
		}
		connectorName, err := getUniqueConnectorName(ctx, version, maxString(hostname, 40))
		if err != nil {
			return fmt.Errorf("failed to determine unique name for connector: %v", err)
		}
		border0Connector, err := createNewBorder0Connector(ctx, connectorName, "CLI-Installed Border0 Connector", version, true)
		if err != nil {
			return fmt.Errorf("failed to create new connector: %v", err)
		}
		newConnectorToken, err := generateNewBorder0ConnectorToken(
			ctx,
			border0Connector.ConnectorID,
			version,
			fmt.Sprintf("%s-token", maxString(connectorName, 50)),
		)
		if err != nil {
			return fmt.Errorf("failed to create new connector token: %v", err)
		}
		connectorToken = newConnectorToken.Token
	} else {
		if token != "" {
			connectorToken = token
		} else {
			hasToken := false

			// retrieve token from SSM
			if tokenPersistenceSsmPath != "" {
				loadDefaultConfigCtx, loadDefaultConfigCtxCancel := context.WithTimeout(ctx, timeoutLoadDefaultConfig)
				loadDefaultConfigCtxCancel()
				cfg, err := awsc.LoadDefaultConfig(loadDefaultConfigCtx)
				if err != nil {
					return fmt.Errorf("unable to load AWS SDK config: %v", err)
				}
				token, err := getBorder0TokenInSsmParameterStore(ctx, cfg, tokenPersistenceSsmPath)
				if err != nil {
					return fmt.Errorf("failed to check ssm parameter %s for connector token: %v", tokenPersistenceSsmPath, err)
				}
				if token != nil {
					connectorToken = *token
					hasToken = true
				}
			}

			if !hasToken {
				// try exchange invite code for token
				token, err := invite.ExchangeForConnectorToken(ctx, inviteCode)
				if err != nil {
					return fmt.Errorf("failed to exchange invite code for connector token: %v", err)
				}
				connectorToken = token
				hasToken = true

				// best effort storage in AWS SSM
				if tokenPersistenceSsmPath != "" {
					// load aws config
					loadDefaultConfigCtx, loadDefaultConfigCtxCancel := context.WithTimeout(ctx, timeoutLoadDefaultConfig)
					loadDefaultConfigCtxCancel()
					cfg, err := awsc.LoadDefaultConfig(loadDefaultConfigCtx)
					if err != nil {
						fmt.Printf("failed to load AWS SDK config for persisting token in ssm parameter: %v", err)
					}

					// store in ssm
					if err = saveBorder0TokenInSsmParameterStore(ctx, cfg, token, tokenPersistenceSsmPath); err != nil {
						fmt.Printf("failed to persist token in ssm parameter: %v\n", err)
					}
				}
			}
		}
	}

	configFileBytes := []byte("# token: [[ connector token goes here ]]")
	if connectorToken != "" {
		yamlBytes, err := yaml.Marshal(config.Configuration{Token: connectorToken})
		if err != nil {
			return fmt.Errorf("failed to encode configuration to yaml: %v", err)
		}
		configFileBytes = yamlBytes
	}

	configFile := makeConfigPath()
	if err := os.WriteFile(configFile, configFileBytes, 0600); err != nil {
		return fmt.Errorf("failed to encode configuration to yaml: %v", err)
	}
	fmt.Printf("🚀 Border0 Connector configuration file \"%s\" written successfully!\n", configFile)

	connectorSvc, err := daemon.GetConnectorService(
		daemon.WithConfigurationFilePath(configFile),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize new connector service object: %v", err)
	}

	if err = connectorSvc.Install(); err != nil {
		return fmt.Errorf("failed to install service: %v", err)
	}
	fmt.Println("🚀 Border0 Connector service installed successfully!")

	if err = connectorSvc.Start(); err != nil {
		return fmt.Errorf("failed to start service: %v", err)
	}
	fmt.Println("🚀 Border0 Connector service started successfully!")

	return nil
}

func makeConfigPath() string {
	serviceConfigPath := "/etc/border0/"

	if runtime.GOOS == "windows" {
		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		homedir := u.HomeDir
		serviceConfigPath = filepath.Join(homedir, "border0")
	}

	// check if serviceConfigPath exists and create it if not
	if _, err := os.Stat(serviceConfigPath); os.IsNotExist(err) {
		os.MkdirAll(serviceConfigPath, 0755)
	}

	return filepath.Join(serviceConfigPath, "border0.yaml")
}
