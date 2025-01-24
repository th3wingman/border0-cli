package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/borderzero/border0-cli/internal"
	border0_connector "github.com/borderzero/border0-cli/internal/connector"
	"github.com/borderzero/border0-cli/internal/connector/config"
	"github.com/borderzero/border0-go"
	"github.com/borderzero/border0-go/client"
	"github.com/jedib0t/go-pretty/v6/table"

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

type statusOutput struct {
	State       string `json:"state,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	Pid         string `json:"pid,omitempty"`
	Error       string `json:"error_message,omitempty"`
}

func displayServiceStatus(serviceName string) {
	system := runtime.GOOS

	var output []byte
	var err error
	statusOutput := statusOutput{
		ServiceName: serviceName,
		State:       "unknown",
	}

	switch system {
	case "linux":
		output, err = exec.Command("systemctl", "show", serviceName, "--no-page").Output()
	case "darwin":
		output, err = exec.Command("launchctl", "print", fmt.Sprintf("system/%s", serviceName)).Output()
	case "windows":
		output, err = exec.Command("sc", "queryex", serviceName).Output()
	default:
		if jsonOutput {
			statusOutput.Error = fmt.Sprintf("unsupported platform: %s", system)
			jsonOutput, _ := json.Marshal(statusOutput)
			fmt.Println(string(jsonOutput))
		} else {
			fmt.Printf("The %s service could not be found.\n", serviceName)
		}
		return
	}

	if err != nil {
		if jsonOutput {
			statusOutput.Error = fmt.Sprintf("the %s service could not be found", serviceName)
			jsonOutput, _ := json.Marshal(statusOutput)
			fmt.Println(string(jsonOutput))
		} else {
			fmt.Printf("The %s service could not be found.\n", serviceName)
		}
		return
	}

	status := strings.TrimSpace(string(output))

	switch system {
	case "linux":
		lines := strings.Split(status, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ActiveState=") {
				activeState := strings.TrimPrefix(line, "ActiveState=")
				if activeState == "active" {
					statusOutput.State = "running"
				} else {
					statusOutput.State = "not running"
				}
			} else if strings.HasPrefix(line, "MainPID=") {
				statusOutput.Pid = strings.TrimPrefix(line, "MainPID=")
				if statusOutput.Pid == "0" {
					statusOutput.Pid = ""
				}
			}
		}
	case "darwin":
		lines := strings.Split(status, "\n")
		for _, line := range lines {
			line = strings.Trim(line, "\t ")
			if strings.Contains(line, "state =") {
				statusOutput.State = strings.Trim(strings.TrimPrefix(line, "state ="), "\t ")
			}
			if strings.Contains(line, "pid =") {
				statusOutput.Pid = strings.Trim(strings.TrimPrefix(line, "pid ="), "\t ")
			}
		}
	case "windows":
		lines := strings.Split(status, "\r\n")
		for _, line := range lines {
			if strings.Contains(line, "STATE") {
				if strings.Contains(line, "RUNNING") {
					statusOutput.State = "running"
				} else {
					statusOutput.State = "not running"
				}
			} else if strings.Contains(line, "PID") {
				statusOutput.Pid = strings.TrimPrefix(line, "PID")
			}
		}
	}

	if jsonOutput {
		jsonOutput, _ := json.Marshal(statusOutput)
		fmt.Println(string(jsonOutput))
	} else {
		fmt.Printf("The %s service is currently %s.\n", serviceName, statusOutput.State)
		if statusOutput.Pid != "" {
			fmt.Println("PID:", statusOutput.Pid)
		}
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

			connectorv2.NewConnectorService(log, internal.Version, config).Start(ctx)
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

			if err := border0_connector.NewConnectorService(*cfg, log, internal.Version).Start(); err != nil {
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

var connectorCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "create a new connector",
	RunE: func(cmd *cobra.Command, args []string) error {
		if name == "" {
			return fmt.Errorf("empty name not allowed")
		}

		token, err := http.GetToken()
		if err != nil {
			return fmt.Errorf("failed to read token, make sure you're logged in. %v", err)
		}

		api := border0.NewAPIClient(
			client.WithAuthToken(token),
			client.WithRetryMax(2),
		)
		connector, err := api.CreateConnector(cmd.Context(), &client.Connector{
			Name:                     name,
			Description:              description,
			BuiltInSshServiceEnabled: withSSH,
		})
		if err != nil {
			return fmt.Errorf("failed to create connector: %v", err)
		}

		if jsonOutput {
			connectorJSON, err := json.Marshal(connector)
			if err != nil {
				return fmt.Errorf("failed to marshal connector to JSON: %v", err)
			}
			fmt.Println(string(connectorJSON))
			return nil
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"ID", connector.ConnectorID})
		t.AppendRow(table.Row{"NAME", connector.Name})
		t.AppendRow(table.Row{"DESCRIPTION", connector.Description})
		t.AppendRow(table.Row{"BUILT-IN SSH SERVER", connector.BuiltInSshServiceEnabled})
		t.SetStyle(table.StyleLight)
		fmt.Println(t.Render())
		return err
	},
}

var connectorListCmd = &cobra.Command{
	Use:   "list",
	Short: "list connectors in the organization",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := http.GetToken()
		if err != nil {
			return fmt.Errorf("failed to read token, make sure you're logged in. %v", err)
		}

		api := border0.NewAPIClient(
			client.WithAuthToken(token),
			client.WithRetryMax(2),
		)
		connectors, err := api.Connectors(cmd.Context())
		if err != nil {
			return fmt.Errorf("failed to list connectors: %v", err)
		}

		if jsonOutput {
			connectorListJSON, err := json.Marshal(connectors)
			if err != nil {
				return fmt.Errorf("failed to marshal connector list to JSON: %v", err)
			}
			fmt.Println(string(connectorListJSON))
			return nil
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"CONNECTOR ID", "NAME", "DESCRIPTION"})
		for _, connector := range connectors.List {
			t.AppendRow(table.Row{
				connector.ConnectorID,
				connector.Name,
				truncateString(connector.Description, 50),
			})
		}
		t.SetStyle(table.StyleLight)
		fmt.Println(t.Render())
		return nil
	},
}

var connectorDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete a connector by id",
	RunE: func(cmd *cobra.Command, args []string) error {
		if connectorID == "" {
			return fmt.Errorf("empty connector-id not allowed")
		}

		token, err := http.GetToken()
		if err != nil {
			return fmt.Errorf("failed to read token, make sure you're logged in. %v", err)
		}

		api := border0.NewAPIClient(
			client.WithAuthToken(token),
			client.WithRetryMax(2),
		)
		if err := api.DeleteConnector(cmd.Context(), connectorID); err != nil {
			return fmt.Errorf("failed to delete connector: %v", err)
		}
		fmt.Printf("connector %s deleted successfully!\n", connectorID)
		return nil
	},
}

var connectorTokenCmdTree = &cobra.Command{
	Use:   "token",
	Short: "connector token related commands",
}

var connectorTokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "create a new connector token",
	RunE: func(cmd *cobra.Command, args []string) error {
		if connectorID == "" {
			return fmt.Errorf("empty connector-id not allowed")
		}

		token, err := http.GetToken()
		if err != nil {
			return fmt.Errorf("failed to read token, make sure you're logged in. %v", err)
		}

		api := border0.NewAPIClient(
			client.WithAuthToken(token),
			client.WithRetryMax(2),
		)

		ct := &client.ConnectorToken{
			ConnectorID: connectorID,
			Name:        tokenName,
		}
		if lifetimeDays != 0 {
			ct.ExpiresAt = client.FlexibleTime{Time: time.Now().Add(time.Duration(lifetimeDays) * time.Hour * 24)}
		}

		connectorToken, err := api.CreateConnectorToken(cmd.Context(), ct)
		if err != nil {
			return fmt.Errorf("failed to create connector token: %v", err)
		}

		if jsonOutput {
			connectorTokenJSON, err := json.Marshal(connectorToken)
			if err != nil {
				return fmt.Errorf("failed to marshal connector token to JSON: %v", err)
			}
			fmt.Println(string(connectorTokenJSON))
			return nil
		}

		expiry := connectorToken.ExpiresAt.Local().String()
		if connectorToken.ExpiresAt.IsZero() {
			expiry = "never expires"
		}

		t := table.NewWriter()
		t.AppendRow(table.Row{"CONNECTOR ID", connectorID})
		t.AppendRow(table.Row{"TOKEN ID", connectorToken.ID})
		t.AppendRow(table.Row{"TOKEN NAME", connectorToken.Name})
		t.AppendRow(table.Row{"TOKEN EXPIRY", expiry})
		t.SetStyle(table.StyleLight)
		fmt.Println(t.Render())

		fmt.Printf("\nToken: %s\n", connectorToken.Token)

		return nil
	},
}

var connectorTokenDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "delete a connector token by id",
	RunE: func(cmd *cobra.Command, args []string) error {
		if connectorID == "" {
			return fmt.Errorf("empty connector-id not allowed")
		}
		if tokenID == "" {
			return fmt.Errorf("empty token-id not allowed")
		}

		token, err := http.GetToken()
		if err != nil {
			return fmt.Errorf("failed to read token, make sure you're logged in. %v", err)
		}

		api := border0.NewAPIClient(
			client.WithAuthToken(token),
			client.WithRetryMax(2),
		)
		if err := api.DeleteConnectorToken(cmd.Context(), connectorID, tokenID); err != nil {
			return fmt.Errorf("failed to delete connector token: %v", err)
		}
		fmt.Printf("connector token %s deleted successfully!\n", connectorID)
		return nil
	},
}

var connectorTokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "list connector tokens for a given connector",
	RunE: func(cmd *cobra.Command, args []string) error {
		if connectorID == "" {
			return fmt.Errorf("empty connector-id not allowed")
		}

		token, err := http.GetToken()
		if err != nil {
			return fmt.Errorf("failed to read token, make sure you're logged in. %v", err)
		}

		api := border0.NewAPIClient(
			client.WithAuthToken(token),
			client.WithRetryMax(2),
		)
		connectorTokens, err := api.ConnectorTokens(cmd.Context(), connectorID)
		if err != nil {
			return fmt.Errorf("failed to list connector tokens: %v", err)
		}

		if jsonOutput {
			connectorTokensListJSON, err := json.Marshal(connectorTokens)
			if err != nil {
				return fmt.Errorf("failed to marshal connector token list to JSON: %v", err)
			}
			fmt.Println(string(connectorTokensListJSON))
			return nil
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"TOKEN ID", "TOKEN NAME", "EXPIRY"})
		for _, connectorToken := range connectorTokens.List {
			expiry := connectorToken.ExpiresAt.Local().String()
			if connectorToken.ExpiresAt.IsZero() {
				expiry = "never expires"
			}
			t.AppendRow(table.Row{connectorToken.ID, connectorToken.Name, expiry})
		}
		t.SetStyle(table.StyleLight)
		fmt.Println(t.Render())
		return nil
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

	connectorCreateCmd.Flags().StringVarP(&name, "name", "n", "", "name for new connector")
	connectorCreateCmd.Flags().StringVarP(&description, "description", "d", "", "description for new connector")
	connectorCreateCmd.Flags().BoolVarP(&withSSH, "with-ssh", "s", false, "set if the new connector should have a built-in shell service")
	connectorCreateCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "set for json output")

	connectorListCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "set for json output")

	connectorDeleteCmd.Flags().StringVarP(&connectorID, "connector-id", "i", "", "connector unique identifier (uuid)")

	connectorTokenCreateCmd.Flags().StringVarP(&connectorID, "connector-id", "i", "", "connector unique identifier (uuid)")
	connectorTokenCreateCmd.Flags().StringVarP(&tokenName, "token-name", "t", fmt.Sprintf("cli-connector-token-%d", time.Now().Unix()), "connector token name")
	connectorTokenCreateCmd.Flags().IntVarP(&lifetimeDays, "lifetime-days", "d", 0, "connector token lifetime days (0 for no expiry)")
	connectorTokenCreateCmd.Flags().BoolVarP(&jsonOutput, "json", "j", false, "set for json output")

	connectorTokenListCmd.Flags().StringVarP(&connectorID, "connector-id", "i", "", "connector unique identifier (uuid)")

	connectorTokenDeleteCmd.Flags().StringVarP(&connectorID, "connector-id", "i", "", "connector unique identifier (uuid)")
	connectorTokenDeleteCmd.Flags().StringVarP(&tokenID, "token-id", "t", "", "connector token unique identifier (uuid)")

	connectorTokenCmdTree.AddCommand(connectorTokenCreateCmd)
	connectorTokenCmdTree.AddCommand(connectorTokenListCmd)
	connectorTokenCmdTree.AddCommand(connectorTokenDeleteCmd)

	connectorCmd.AddCommand(connectorTokenCmdTree)
	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStatusCmd)
	connectorCmd.AddCommand(connectorInstallCmd)
	connectorCmd.AddCommand(connectorUnInstallCmd)
	connectorCmd.AddCommand(connectorCreateCmd)
	connectorCmd.AddCommand(connectorListCmd)
	connectorCmd.AddCommand(connectorDeleteCmd)
	rootCmd.AddCommand(connectorCmd)
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return fmt.Sprintf("%s...", s[:maxLen-3])
	}
	return s
}
