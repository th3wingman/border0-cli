package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/borderzero/border0-cli/internal"
	"github.com/borderzero/border0-cli/internal/connector"
	"github.com/borderzero/border0-cli/internal/connector/config"

	"github.com/borderzero/border0-cli/internal/connector_v2/daemon"
	"github.com/borderzero/border0-cli/internal/connector_v2/install"
	"github.com/borderzero/border0-cli/internal/connector_v2/invite"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/kardianos/service"

	connectorv2 "github.com/borderzero/border0-cli/internal/connector_v2"
	connectorv2config "github.com/borderzero/border0-cli/internal/connector_v2/config"

	"github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// connectorCmd represents the connector service
var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "Border0 Connector commands section, we can manage our connector functionality here",
}

const (
	serviceName           = "border0" // must match binary name
	defaultConfigFileName = "border0.yaml"
)

var (
	serviceConfigPath = "/etc/border0/"
)

// hidden variables used for connector v2 only
var (
	token       string
	daemonOnly  bool
	connectorId string
	inviteCode  string

	tokenPersistenceSsmPath string
)

type Socket struct {
	Type      string `yaml:"type"`
	SSHServer bool   `yaml:"sshserver"`
}

type CurrentConnectorConfig struct {
	Sockets     []map[string]Socket `yaml:"sockets"`
	Credentials Credentials         `yaml:"credentials"`
}

type Credentials struct {
	Token string `yaml:"token"`
}

func displayServiceStatus(serviceName string) {
	system := runtime.GOOS

	var output []byte
	var err error

	if system == "linux" {
		output, err = exec.Command("systemctl", "show", serviceName, "--no-page").Output()
	} else if system == "darwin" {
		output, err = exec.Command("launchctl", "print", fmt.Sprintf("system/%s", serviceName)).Output()
	} else if system == "windows" {
		output, err = exec.Command("sc", "queryex", serviceName).Output()
	} else {
		fmt.Printf("Unsupported platform: %s\n", system)
		return
	}

	if err != nil {
		fmt.Printf("The %s service could not be found.\n", serviceName)
		return
	}

	status := strings.TrimSpace(string(output))

	if system == "linux" {
		lines := strings.Split(status, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ActiveState=") {
				activeState := strings.TrimPrefix(line, "ActiveState=")
				if activeState == "active" {
					fmt.Printf("The %s service is currently running.\n", serviceName)
				} else {
					fmt.Printf("The %s service is not running.\n", serviceName)
				}
			} else if strings.HasPrefix(line, "MainPID=") {
				fmt.Println(line)
			}
		}
		return
	}

	if system == "darwin" {
		lines := strings.Split(status, "\n")
		for _, line := range lines {
			// remove all whitespace and tabs from line
			line = strings.Trim(line, "\t ")
			// process "state" line
			if strings.Contains(line, "state =") {
				state := strings.Trim(strings.TrimPrefix(line, "state ="), "\t ")
				if state != "running" {
					fmt.Printf("The %s service is not running.\n", serviceName)
					return
				}
				fmt.Printf("The %s service is currently running. ", serviceName)
				continue
			}
			// process "pid" line
			if strings.Contains(line, "pid =") {
				fmt.Printf("(%s)", line)
			}
		}
		fmt.Println() // newline
	}

	if system == "windows" {
		lines := strings.Split(status, "\r\n")
		for _, line := range lines {
			if strings.Contains(line, "STATE") {
				if strings.Contains(line, "RUNNING") {
					fmt.Printf("The %s service is currently running.\n", serviceName)
				} else {
					fmt.Printf("The %s service is not running.\n", serviceName)
				}
			} else if strings.Contains(line, "PID") {
				fmt.Println(line)
			}
		}
		return
	}
}

var connectorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start the connector in foreground ad-hoc mode",
	Run: func(cmd *cobra.Command, args []string) {
		log, _ := logging.BuildProduction()
		defer log.Sync()

		SetRlimit()

		v2 := false

		var configPath string
		configPathFromEnv := os.Getenv("BORDER0_CONFIG_FILE")
		// check if the config file is provided as a flag or environment variable
		if connectorConfig != "" {
			configPath = connectorConfig
		} else if configPathFromEnv != "" {
			configPath = configPathFromEnv
		} else {
			// check if defaultConfigFileName "border0.yaml" exists in the current directory
			// if not check if it exists in the serviceConfigPath directory
			if _, err := os.Stat(defaultConfigFileName); err == nil {
				configPath = filepath.Join(defaultConfigFileName)
				log.Info("using config file in the current directory", zap.String("config_path", configPath))
			} else if _, err := os.Stat(serviceConfigPath + defaultConfigFileName); err == nil {
				configPath = filepath.Join(serviceConfigPath + defaultConfigFileName)
				log.Info("using config file in the service config directory", zap.String("config_path", configPath))
			} else {
				log.Debug("no legacy connector config found, defaulting to connector v2", zap.String("error", err.Error()))
				v2 = true
			}
		}

		parser := config.NewConfigParser()

		var cfg *config.Config
		if !v2 {
			log.Info("reading the config", zap.String("config_path", configPath))

			parsedCfg, err := parser.Parse(configPath)
			if err == nil && parsedCfg != nil {
				cfg = parsedCfg
			}
			if err != nil {
				log.Debug("failed to parse legacy connector config, defaulting to connector v2", zap.String("error", err.Error()))
				v2 = true
			}
			if !v2 {
				if err := cfg.Validate(); err != nil {
					log.Debug("failed to validate legacy connector config, defaulting to connector v2", zap.String("error", err.Error()))
					v2 = true
				}
			}
		}

		// We need to handle OS service control messages.
		// This is really only necessary on Windows.
		//
		// Removing this code will cause the Windows Service Manager
		// to interpret the lack of control message handling as the
		// service failing to respond to the start request and will
		// emit the error message "The service did not respond to the
		// start or control request in a timely fashion."
		go func() {
			connectorSvc, err := daemon.GetConnectorService(
				daemon.WithConfigurationFilePath(connectorConfig),
			)
			if err != nil {
				log.Error("failed to acquire connector service daemon", zap.Error(err))
				return
			}
			if serviceFlag != "" {
				err = service.Control(connectorSvc, serviceFlag)
				if err != nil {
					log.Error("failed to handle OS service control message", zap.Error(err))
				}
			}
			if err = connectorSvc.Run(); err != nil {
				log.Error("failed to run connector service daemon", zap.Error(err))
				return
			}
		}()

		if v2 {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			// when --invite is provided, exchange the invite code for a connector token,
			// and then set the token in the environment variable
			if inviteCode != "" {
				connectorToken, err := invite.ExchangeForConnectorToken(ctx, inviteCode)
				if err != nil {
					log.Fatal("failed to exchange invite code for connector token", zap.Error(err))
				}
				_ = connectorv2config.SetBorder0Token(connectorToken)
			}

			config, err := connectorv2config.GetConfiguration(ctx, connectorConfig)
			if err != nil {
				log.Fatal("failed to get connector (v2) configuration", zap.Error(err))
			}
			if connectorId != "" {
				config.ConnectorId = connectorId
			}

			connectorv2.NewConnectorService(ctx, log, internal.Version, config).Start()
			return
		}

		svc, err := config.StartSSMSession(cfg)
		if err != nil {
			log.Error("failed to start ssm session", zap.String("error", err.Error()))
		}

		if svc != nil {
			if err := parser.LoadSSMInConfig(svc, cfg); err != nil {
				log.Error("failed to load ssm config", zap.String("error", err.Error()))
			}

			parser := config.NewConfigParser()

			log.Info("reading the config", zap.String("config_path", configPath))
			cfg, err := parser.Parse(configPath)
			if err != nil {
				log.Fatal("failed to parse config", zap.String("error", err.Error()))
			}

			if err := cfg.Validate(); err != nil {
				log.Fatal("failed to validate config", zap.String("error", err.Error()))
			}

			svc, err := config.StartSSMSession(cfg)
			if err != nil {
				log.Error("failed to start ssm session", zap.String("error", err.Error()))
			}

			if svc != nil {
				if err := parser.LoadSSMInConfig(svc, cfg); err != nil {
					log.Error("failed to load ssm config", zap.String("error", err.Error()))
				}
			}

			if err := connector.NewConnectorService(*cfg, log, internal.Version).Start(); err != nil {
				log.Error("failed to start connector", zap.String("error", err.Error()))
			}
		}
	},
}

func connectorInstallAws(cmd *cobra.Command) {
	ctx := cmd.Context()

	sigs := make(chan os.Signal, 1)
	defer close(sigs)

	signal.Notify(sigs, os.Interrupt, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	defer signal.Stop(sigs)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		if sig, ok := <-sigs; ok {
			fmt.Println("Received shutdown signal:", sig.String())
			cancel()
		}
	}()

	loginCmd.Run(cmd, []string{})
	if err := install.RunCloudInstallWizardForAWS(ctx, inviteCode, internal.Version); err != nil {
		fmt.Printf("\nError: %s\n", err)
		os.Exit(1)
	}
}

func connectorInstallLocal(cmd *cobra.Command) {
	// ensure running as root
	if !util.RunningAsAdministrator() {
		fmt.Printf("\nError: command must be ran as system administrator")
		os.Exit(1)
	}
	if !daemonOnly && token != "" {
		fmt.Printf("\nError: --token can only be populated when --daemon-only is set")
		os.Exit(1)
	}
	if !daemonOnly {
		loginCmd.Run(cmd, []string{})
	}
	err := install.RunInstallWizard(cmd.Context(), internal.Version, daemonOnly, token, inviteCode, tokenPersistenceSsmPath)
	if err != nil {
		fmt.Printf("\nError: %s\n", err)
		os.Exit(1)
	}
}

var connectorInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "install the connector service on the machine",
	Run: func(cmd *cobra.Command, args []string) {
		if aws {
			connectorInstallAws(cmd)
			return
		}
		connectorInstallLocal(cmd)
	},
}

var connectorUnInstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "uninstall the connector service from the machine",
	Run: func(cmd *cobra.Command, args []string) {
		if !util.RunningAsAdministrator() {
			log.Println("Error: command must be ran as system administrator")
			os.Exit(1)
		}

		if err := daemon.Uninstall(); err != nil {
			log.Printf("Failed to uninstall service: %v", err)
			os.Exit(1)
		}

		configPath := filepath.Join(serviceConfigPath + defaultConfigFileName)
		// check if the file exists
		if _, err := os.Stat(configPath); os.IsNotExist(err) {
			fmt.Println("Config file does not exist. Nothing else to do.")
			os.Exit(0)
		}

		data, err := os.ReadFile(configPath)
		if err != nil {
			fmt.Printf("Error reading YAML file: %v", err)
		}

		var currentConfig CurrentConnectorConfig
		err = yaml.Unmarshal(data, &currentConfig)
		if err != nil {
			fmt.Printf("Error unmarshaling YAML data: %v", err)
		}

		// check if the token is valid
		if currentConfig.Credentials.Token != "" {
			client, err := http.NewClientWithAccessToken(currentConfig.Credentials.Token)
			if err != nil {
				log.Fatalf("error: %v", err)
			}

			for _, socketMap := range currentConfig.Sockets {
				for socketName, socket := range socketMap {
					if socket.SSHServer {
						// now we delete the socket
						_ = client.Request("DELETE", "socket/"+socketName, nil, nil)
						break // we only need to delete one socket
					}
				}
			}
		}

		// ask the user if we should remove the config file in configPath
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Do you want to remove the '%s' config file? [y/N]: ", configPath)
		text, _ := reader.ReadString('\n')

		// Remove the newline character at the end of the input
		text = strings.TrimSpace(text)

		// Check if the user wants to remove the config file
		if strings.ToLower(text) == "y" {

			err := os.Remove(configPath)
			if err != nil {
				fmt.Println("Error removing the config file:", err)
			} else {
				fmt.Println("Config file removed successfully")
			}
			// now also remove the socket

		}
	},
}

var connectorStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "display the connector service status",
	Run: func(cmd *cobra.Command, args []string) {
		displayServiceStatus(serviceName)
	},
}

func init() {
	connectorStartCmd.Flags().StringVarP(&serviceFlag, "service", "s", "", "used to provide service actions e.g. start | stop | install | uninstall...")
	connectorStartCmd.Flags().StringVarP(&connectorConfig, "config", "f", "", "yaml configuration file for connector service, see https://docs.border0.com for more info")
	connectorStartCmd.Flags().StringVarP(&connectorId, "connector-id", "", "", "connector id to use with connector control stream")
	connectorStartCmd.Flags().StringVarP(&inviteCode, "invite", "i", "", "invite code for installing the connector")

	// The start command needs to be able to handle OS control
	// messages through a 'service' flag, really only in Windows.
	// The customer does not need to know about this flag so we hide it.
	connectorStartCmd.Flags().MarkHidden("service")

	connectorInstallCmd.Flags().BoolVarP(&aws, "aws", "", false, "true to run the connector installation wizard for AWS")
	connectorInstallCmd.Flags().BoolVarP(&daemonOnly, "daemon-only", "d", false, "Install the daemon only, do not create connector")
	connectorInstallCmd.Flags().StringVarP(&token, "token", "t", "", "Border0 token for use by the installed connector")
	connectorInstallCmd.Flags().StringVarP(&inviteCode, "invite", "i", "", "invite code for installing the connector")
	connectorInstallCmd.Flags().StringVarP(&tokenPersistenceSsmPath, "token-persistence-ssm-path", "p", "", "path in AWS SSM to persist connector token after exchanging an invite token")
	connectorInstallCmd.Flags().MarkHidden("token-persistence-ssm-path") // hidden as it is only used in web installer
	connectorInstallCmd.Flags().BoolVar(&qr, "qr", false, "Print a QR code for authenticating with a mobile device")
	connectorInstallCmd.Flags().MarkHidden("qr")

	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStatusCmd)
	connectorCmd.AddCommand(connectorInstallCmd)
	connectorCmd.AddCommand(connectorUnInstallCmd)
	rootCmd.AddCommand(connectorCmd)
}
