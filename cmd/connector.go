package cmd

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/connector"
	"github.com/borderzero/border0-cli/internal/connector/config"
	"github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/logging"
	"github.com/spf13/cobra"
	"github.com/takama/daemon"
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// connectorCmd represents the connector service
var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "Border0 Connector commands section, we can manage our connector functionality here",
}

const (
	// for Service
	serviceDescription = "border0.com Service"
)

var serviceConfigPath = "/etc/border0/"
var serviceName = "border0"

type Service struct {
	daemon.Daemon
}

var service_dependencies = []string{}

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

func copyFile(src, dst, username string) error {
	// Open the source file for reading
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create the destination file
	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	// Copy the contents of the source file to the destination file
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	// Sync the file to ensure it is written to disk
	err = dstFile.Sync()
	if err != nil {
		return err
	}

	if err := os.Chmod(dst, 0600); err != nil {
		return err
	}

	// get uid and gid of the username
	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	// Convert UID and GID strings to integers
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		fmt.Println("Error:", err)
		return err
	}
	// set the ownership of the file to the user
	if err := os.Chown(dst, uid, gid); err != nil {
		return err
	}

	return nil
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

	return filepath.Join(serviceConfigPath, "border0.yaml")
}

func checkRootPermission() {
	if runtime.GOOS != "windows" {
		if os.Geteuid() != 0 {
			log.Printf("You need to run this command as root or with sudo")
			os.Exit(1)
		}
	}
}

var connectorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start ad-hoc connector",
	Run: func(cmd *cobra.Command, args []string) {
		log, _ := logging.BuildProduction()
		defer log.Sync()

		var configPath string
		if connectorConfig != "" {
			configPath = connectorConfig
		} else {
			configPath = filepath.Join("border0.yaml")
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

		SetRlimit()
		if err := connector.NewConnectorService(*cfg, log, version).Start(); err != nil {
			log.Error("failed to start connector", zap.String("error", err.Error()))
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

var connectorInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "install the connector service on the machine",
	Run: func(cmd *cobra.Command, args []string) {
		// put the install code here
		deamonType := daemon.SystemDaemon
		if runtime.GOOS == "darwin" {
			// GlobalDaemon is a system daemon that runs as the root user and stores its
			// property list in the global LaunchDaemons directory. In other words,
			// system-wide daemons provided by the administrator. Valid for macOS only.
			deamonType = daemon.GlobalDaemon
		}

		srv, err := daemon.New(serviceName, serviceDescription, deamonType, service_dependencies...)
		if err != nil {
			log.Println("Error: ", err)
			os.Exit(1)
		}
		service := &Service{srv}
		checkRootPermission()

		disableBrowser = true
		loginCmd.Run(cmd, []string{})

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		myHostname, err := os.Hostname()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		now := time.Now()
		oneYearLater := now.AddDate(1, 0, 0)
		oneYearFromNow := int(oneYearLater.Unix())

		tokenName := fmt.Sprintf("Connector on %s host", myHostname)
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

		u, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		homedir := u.HomeDir

		configPath := makeConfigPath()
		// check if current user has sudo permissions
		// Also check for sudo users
		username := os.Getenv("SUDO_USER")
		if username != "" {
			// we are in sudo mode
			if runtime.GOOS == "darwin" {
				// This is because of:
				// https://github.com/golang/go/issues/24383
				// os/user: LookupUser() doesn't find users on macOS when compiled with CGO_ENABLED=0
				// So we'll just hard code for MACOS
				homedir = "/Users/" + username
			} else {
				u, err = user.Lookup(username)
				if err != nil {
					log.Fatal(err)
				}
				homedir = u.HomeDir
			}
			// now copy the newly created token file to user's home directory
			// lets determine the token file path
			userTokenFile := fmt.Sprintf("%s/.border0/token", homedir)
			// lets copy the token file
			err := copyFile(http.TokenFilePath(), userTokenFile, username)
			if err != nil {
				fmt.Println("Error:", err)
			}

		}

		//now write the randString fucntion
		randString := func(n int) string {
			r := rand.New(rand.NewSource(time.Now().UnixNano()))
			var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyz")
			b := make([]rune, n)
			for i := range b {
				b[i] = letters[r.Intn(len(letters))]
			}
			return string(b)
		}
		// staging with setting the new socket name
		socketName := strings.ToLower(myHostname)
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
			socketName = fmt.Sprintf("%s-%s", myHostname, randString(5))
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
				socketName = fmt.Sprintf("%s-%s", myHostname, randString(5))
			}
		}

		// we are going to generate out template connector config yaml file
		config := TemplateConnectorConfig{}
		config.Connector.Name = fmt.Sprintf("%s-cntr", myHostname)
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

		socket := models.Socket{}
		for i := 0; i < 10; i++ {
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

		socketURL := fmt.Sprintf("https://client.border0.com/#/ssh/%s", socket.Dnsname)
		printThis := fmt.Sprintf("\n🚀 Service started successfully.\nYou can now connect to this machine using the following url: \n%s", socketURL)
		fmt.Println(printThis)

	},
}
var connectorUnInstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "uninstall the connector service from the machine",
	Run: func(cmd *cobra.Command, args []string) {
		// put the uninstall code here

		deamonType := daemon.SystemDaemon
		if runtime.GOOS == "darwin" {
			// GlobalDaemon is a system daemon that runs as the root user and stores its
			// property list in the global LaunchDaemons directory. In other words,
			// system-wide daemons provided by the administrator. Valid for macOS only.
			deamonType = daemon.GlobalDaemon
		}

		srv, err := daemon.New(serviceName, serviceDescription, deamonType, service_dependencies...)
		if err != nil {
			log.Println("Error: ", err)
			os.Exit(1)
		}
		service := &Service{srv}
		checkRootPermission()

		result, err := service.Stop()
		if err == nil {
			fmt.Println(result)
		}
		result, err = service.Remove()
		if err != nil {
			fmt.Println(result)
		}

		configPath := makeConfigPath()

		data, err := os.ReadFile(configPath)
		if err != nil {
			log.Fatalf("Error reading YAML file: %v", err)
		}

		var currentConfig CurrentConnectorConfig
		err = yaml.Unmarshal(data, &currentConfig)
		if err != nil {
			log.Fatalf("Error unmarshaling YAML data: %v", err)
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
	connectorStartCmd.Flags().StringVarP(&connectorConfig, "config", "f", "", "setup configuration for connector command")
	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStopCmd)
	connectorCmd.AddCommand(connectorStatusCmd)
	connectorCmd.AddCommand(connectorInstallCmd)
	connectorCmd.AddCommand(connectorUnInstallCmd)
	rootCmd.AddCommand(connectorCmd)
}
