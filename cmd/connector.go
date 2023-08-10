package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/connector"
	"github.com/borderzero/border0-cli/internal/connector/config"
	"github.com/borderzero/border0-cli/internal/connector_v2/install"
	"github.com/borderzero/border0-cli/internal/service_daemon"
	"github.com/borderzero/border0-cli/internal/util"

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
	serviceName        = "border0" // must match binary name
	serviceDescription = "Border0 Connector Service"

	defaultConfigFileName = "border0.yaml"
)

var (
	serviceConfigPath = "/etc/border0/"
)

// hidden variables used for connector v2 only
var token string
var daemonOnly bool
var v2 bool
var connectorId string

type TemplateConnectorConfig struct {
	Connector struct {
		Name string `yaml:"name"`
	} `yaml:"connector"`
	Credentials struct {
		Token string `yaml:"token"`
	} `yaml:"credentials"`
	Sockets []map[string]Socket `yaml:"sockets"`
}

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

	if system == "linux" || system == "darwin" {
		output, err = exec.Command("systemctl", "show", serviceName, "--no-page").Output()
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

	if system == "linux" || system == "darwin" {
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
	} else if system == "windows" {
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
	}
}

func makeConfigPath() string {
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

	return filepath.Join(serviceConfigPath, defaultConfigFileName)
}

var connectorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start the connector in foreground ad-hoc mode",
	Run: func(cmd *cobra.Command, args []string) {
		log, _ := logging.BuildProduction()
		defer log.Sync()

		SetRlimit()

		if v2 {
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			config, err := connectorv2config.GetConfiguration(ctx, connectorConfig)
			if err != nil {
				log.Fatal("failed to get connector (v2) configuration", zap.Error(err))
			}
			if connectorId != "" {
				config.ConnectorId = connectorId
			}

			connectorv2.NewConnectorService(ctx, log, version, config).Start()
		} else {
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
					log.Fatal("no default " + defaultConfigFileName + " config file found, neither in the current directory nor in '" + serviceConfigPath + "' please specify a config file with the --config flag")
				}
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

				if err := connector.NewConnectorService(*cfg, log, version).Start(); err != nil {
					log.Error("failed to start connector", zap.String("error", err.Error()))
				}
			}
		}
	},
}

var connectorStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop ad-hoc connector process",
	Run: func(cmd *cobra.Command, args []string) {
		connector.NewConnectorService(*config.NewConfig(), nil, version).Stop()
	},
}

func connectorInstallAws(ctx context.Context) {
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

	if err := install.RunCloudInstallWizardForAWS(ctx, version); err != nil {
		fmt.Printf("\nError: %s\n", err)
		os.Exit(1)
	}
}

func connectorInstallLocal(ctx context.Context) {
	err := install.RunInstallWizard(ctx, version, daemonOnly, token)
	if err != nil {
		fmt.Printf("\nError: %s\n", err)
		os.Exit(1)
	}
}

func randString(n int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyz")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

var connectorInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "install the connector service on the machine",
	Run: func(cmd *cobra.Command, args []string) {

		if v2 {
			if aws {
				connectorInstallAws(cmd.Context())
				return
			}
			loginCmd.Run(cmd, []string{})
			connectorInstallLocal(cmd.Context())
			return
		}

		if !util.RunningAsAdministrator() {
			log.Println("Error: command must be ran as system administrator")
			os.Exit(1)
		}
		service, err := service_daemon.New(serviceName, serviceDescription)
		if err != nil {
			log.Println("Error: ", err)
			os.Exit(1)
		}
		installed, err := service_daemon.IsInstalled(service)
		if err != nil {
			log.Printf("Error: failed to check whether service is already installed: %v", err)
			os.Exit(1)
		}
		if installed {
			log.Println("Service already installed")
			os.Exit(1)
		}

		disableBrowser = true
		loginCmd.Run(cmd, []string{})

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		hostname, err := util.GetFormattedHostname()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		now := time.Now()
		oneYearLater := now.AddDate(1, 0, 0)
		oneYearFromNow := oneYearLater.Unix()

		tokenName := fmt.Sprintf("Connector %s", hostname)
		// s := models.Socket{}
		t := models.Token{}
		newToken := &models.Token{
			Name:      tokenName,
			Role:      "connector",
			ExpiresAt: oneYearFromNow,
		}
		err = client.WithVersion(version).Request("POST", "organizations/tokens", &t, newToken)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		configPath := makeConfigPath()

		// staging with setting the new socket name
		socketName := hostname
		// function to check if the socket name exists
		socketExists := func(name string) bool {
			err := client.Request("GET", "socket/"+name, &models.Socket{}, nil)
			return err == nil
		}

		// now we check if the socketName socket exists
		err = client.Request("GET", "socket/"+socketName, &models.Socket{}, nil)
		if err == nil {
			// ask user to provide a new socket name
			fmt.Printf("Socket '%s' already exists.\n", socketName)
			socketName = fmt.Sprintf("%s-%s", hostname, randString(5))
			fmt.Printf("Provide a new socket name, eg: '%s'? :", socketName)
			reader := bufio.NewReader(os.Stdin)
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			if len(text) != 0 {
				text = strings.TrimSpace(text)
				text = strings.ToLower(text) // Convert the input text to lowercase
				validInput := regexp.MustCompile(`^[a-zA-Z0-9-]{3,}$`)
				if !validInput.MatchString(text) {
					fmt.Printf("I got '%v', that looks invalid. Using randomized name.\n", socketName)
				} else {
					socketName = text
				}
			}
			// let's check if the socket already exists
			if !socketExists(socketName) {
				fmt.Printf("Using '%s' as socket name.\n", socketName)
			} else {
				fmt.Println("Generating randomized name.")
				socketName = fmt.Sprintf("%s-%s", hostname, randString(5))
			}
		}

		// we are going to generate out template connector config yaml file
		config := TemplateConnectorConfig{}
		config.Connector.Name = fmt.Sprintf("%s-cntr", strings.ToLower(hostname))
		config.Credentials.Token = t.Token

		sshServerSocket := Socket{
			Type:      "ssh",
			SSHServer: true,
		}
		config.Sockets = append(config.Sockets, map[string]Socket{socketName: sshServerSocket})

		yamlData, err := yaml.Marshal(&config)
		if err != nil {
			log.Fatalf("Error marshaling YAML data: %v", err)
		}

		// Now we write the file
		f, err := os.Create(configPath)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		defer f.Close()
		_, err = f.WriteString(string(yamlData))
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		// now we set the permissions to 0644
		if err := os.Chmod(configPath, 0644); err != nil {
			log.Fatalf("error: %v", err)
		}

		// Now we install the service
		installResult, err := service.Install("connector", "start", "--config", configPath)
		if err != nil {
			log.Fatalf("error: %v %v", installResult, err)
		}
		fmt.Println("\n", installResult)
		// Also start the service
		startResult, err := service.Start()
		if err != nil {
			log.Fatalf("error: %v %v", startResult, err)
		}
		fmt.Println(startResult)

		attempts := 10
		var socket *models.Socket
		for i := 0; i < attempts; i++ {
			// lets check if the socket exists
			err = client.Request("GET", "socket/"+socketName, &socket, nil)
			if err == nil {
				// socket exists
				break
			}
			fmt.Println("Waiting for socket to be created...")
			time.Sleep(2 * time.Second)
		}
		// now lets get the socket

		if socket == nil {
			log.Fatalf("Error: failed to get newly created socket after %d attempts", attempts)
		}

		socketURL := fmt.Sprintf("https://client.border0.com/#/ssh/%s", socket.Dnsname)
		printThis := fmt.Sprintf("\n🚀 Service started successfully.\nYou can now connect to this machine using the following url: \n%s", socketURL)
		fmt.Println(printThis)
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
		service, err := service_daemon.New(serviceName, serviceDescription)
		if err != nil {
			log.Println("Error: ", err)
			os.Exit(1)
		}
		installed, err := service_daemon.IsInstalled(service)
		if err != nil {
			log.Printf("Error: failed to check whether service is already installed: %v", err)
			os.Exit(1)
		}
		if !installed {
			log.Printf("The service is NOT installed")
			os.Exit(1)
		}

		result, err := service.Stop()
		if err == nil {
			fmt.Println(result)
		}
		result, err = service.Remove()
		if err != nil {
			fmt.Println(result)
		} else {
			fmt.Println(result)
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
	connectorStartCmd.Flags().StringVarP(&connectorConfig, "config", "f", "", "yaml configuration file for connector service, see https://docs.border0.com for more info")
	connectorStartCmd.Flags().BoolVarP(&v2, "v2", "", false, "use connector v2")
	connectorStartCmd.Flags().StringVarP(&connectorId, "connector-id", "", "", "connector id to use with connector control stream")
	connectorInstallCmd.Flags().BoolVarP(&v2, "v2", "", false, "use connector v2")
	connectorInstallCmd.Flags().BoolVarP(&aws, "aws", "", false, "true to run the connector installation wizard for AWS")
	connectorInstallCmd.Flags().BoolVarP(&daemonOnly, "daemon-only", "d", false, "Install the daemon only, do not create connector")
	connectorInstallCmd.Flags().StringVarP(&token, "token", "t", "", "Border0 token for use by the installed connector")

	// hide connector v2 related flags for now
	connectorStartCmd.Flag("v2").Hidden = true
	connectorStartCmd.Flag("connector-id").Hidden = true
	connectorInstallCmd.Flag("v2").Hidden = true
	connectorInstallCmd.Flag("aws").Hidden = true
	connectorInstallCmd.Flag("daemon-only").Hidden = true
	connectorInstallCmd.Flag("token").Hidden = true

	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStopCmd)
	connectorCmd.AddCommand(connectorStatusCmd)
	connectorCmd.AddCommand(connectorInstallCmd)
	connectorCmd.AddCommand(connectorUnInstallCmd)
	rootCmd.AddCommand(connectorCmd)
}
