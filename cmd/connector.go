package cmd

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/user"
	"path/filepath"
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
)

// connectorCmd represents the connector service
var connectorCmd = &cobra.Command{
	Use:   "connector",
	Short: "connector wrapper",
}

// var stdlog, errlog *log.Logger

const (
	// for Service
	service_name        = "border0_connector"
	service_description = "border0.com Service"
)

type Service struct {
	daemon.Daemon
}

var service_dependencies = []string{}

// conenctorServiceCmd represents the conenctor service command
var conenctorServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install, Remove, Start and Stop the border0 connector service",

	Run: func(cmd *cobra.Command, args []string) {

		// Default type is SystemDaemon
		// SystemDaemon is a system daemon that runs as the root user. In other words,
		// system-wide daemons provided by the administrator. Valid for FreeBSD, Linux
		// and Windows only.
		deamonType := daemon.SystemDaemon
		if runtime.GOOS == "darwin" {
			// GlobalDaemon is a system daemon that runs as the root user and stores its
			// property list in the global LaunchDaemons directory. In other words,
			// system-wide daemons provided by the administrator. Valid for macOS only.
			deamonType = daemon.GlobalDaemon
		}

		srv, err := daemon.New(service_name, service_description, deamonType, service_dependencies...)
		if err != nil {
			log.Println("Error: ", err)
			os.Exit(1)
		}
		service := &Service{srv}
		status, err := service.Manage(cmd)
		if err != nil {
			log.Println(status, "\nError: ", err)
			os.Exit(1)
		}
		fmt.Println(status)
	},
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

func (service *Service) Manage(cmd *cobra.Command) (string, error) {

	usage := fmt.Sprintf("Usage: %s %s %s install | unremove ", os.Args[0], os.Args[1], os.Args[2])

	// if received any kind of command, do it

	if len(os.Args) > 3 {
		command := os.Args[3]
		switch command {
		case "install":
			// first do border0 login and fetch the admin token
			// then use the token to fetch the connector token
			// then use the connector token to generate the config file

			// check if the user is root
			if os.Geteuid() != 0 {
				log.Printf("You need to run this command as root or with sudo")
				os.Exit(1)
			}

			loginCmd.Run(cmd, []string{})

			client, err := http.NewClient()
			if err != nil {
				log.Fatalf("error: %v", err)
			}

			myHostname, err := os.Hostname()
			if err != nil {
				return "", err
			}

			// s := models.Socket{}
			t := models.Token{}
			newToken := &models.Token{
				Name:      myHostname + "-cntr",
				Role:      "connector",
				ExpiresAt: 0,
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
			configPath := "/etc/border0.yaml"
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
					configPath = filepath.Join(homedir, "border0.yaml")
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
				// err = copyFile(tokenFile, userTokenFile)
				err := copyFile(http.TokenFilePath(), userTokenFile, username)
				if err != nil {
					fmt.Println("Error:", err)
				}

			}

			//now write the randString fucntion
			randString := func(n int) string {
				var letters = []rune("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
				b := make([]rune, n)
				for i := range b {
					b[i] = letters[rand.Intn(len(letters))]
				}
				return string(b)
			}
			// staging with setting the new socket name
			socketName := fmt.Sprintf("%s", myHostname)
			// function to check if the socket name exists
			socketExists := func(name string) bool {
				err := client.Request("GET", "socket/"+name, &models.Socket{}, nil)
				return err == nil
			}

			// now we check if the socketName socket exists
			err = client.Request("GET", "socket/"+socketName, &models.Socket{}, nil)
			if err == nil {
				// lets ask the use for input if we should delete the socket
				reader := bufio.NewReader(os.Stdin)
				fmt.Printf("Socket %s already exists. Do you want to delete it? [y/n]: ", socketName)
				text, _ := reader.ReadString('\n')
				text = strings.TrimSpace(text)
				if text != "y" {
					// ask user to provide a new socket name
					fmt.Printf("Please provide a new socket name, eg: my-awsm-%s-cntr:", myHostname)
					text, _ := reader.ReadString('\n')
					text = strings.TrimSpace(text)
					socketName = text
					// lets check if the socket exists
					for {
						// check if the socketName socket exists
						if !socketExists(socketName) {
							break
						}
						// ask the user for input to provide a new socket name
						fmt.Printf("Socket %s already exists. Please provide a new socket name, e.g., my-other-awsm-%s-cntr: ", socketName, myHostname)
						text, _ := reader.ReadString('\n')
						text = strings.TrimSpace(text)

						if text != "" {
							socketName = text
						} else {
							// lets generate a random socket name
							socketName = fmt.Sprintf("%s-%s", myHostname, randString(4))
							fmt.Printf("Looks like you do not want to provide a socket name, I will generate one for you: %s\n", socketName)
						}
					}
				} else {
					// lets delete the socket
					err = client.Request("DELETE", "socket/"+socketName, nil, nil)
					if err != nil {
						return "", err
					}
				}
			}

			// Now we generate a basic Yaml
			yaml := fmt.Sprintf(`---
connector:
    name: "%s-cntr"

credentials:
    token: %s

sockets:
    - %s:
        type: ssh
        sshserver: true
 `, myHostname, t.Token, socketName)

			// Now we write the file
			f, err := os.Create(configPath)
			if err != nil {
				return "", err
			}
			defer f.Close()
			_, err = f.WriteString(yaml)
			if err != nil {
				return "", err
			}
			// now we set the permissions to 0600
			if err := os.Chmod(configPath, 0600); err != nil {
				return "", err
			}

			// Now we install the service
			result, err := service.Install("connector", "start", "--config", configPath)
			if err != nil {
				return result, err
			}
			// Also start the service
			fmt.Println("\n", result)
			startResult, err := service.Start()
			if err != nil {
				return startResult, err
			}
			fmt.Println(startResult)
			// now do a loop and wait for the socket to be created, sleep 1s between each loop
			// and then print the socket url
			// lets wait for 5 seconds
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
			printThis := fmt.Sprintf("\n🚀 Service started successfully. You can now connect to this machine using the following url: \n%s", socketURL)
			fmt.Println(printThis)
			return "", err

		case "uninstall":
			result, err := service.Stop()
			if err == nil {
				fmt.Println(result)
			}
			result, err = service.Remove()
			if err != nil {
				return result, err
			}

			// ask the user if we should remove the config file in /etc/border0.yaml
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Do you want to remove the config file in /etc/border0.yaml? [y/N]: ")
			text, _ := reader.ReadString('\n')

			// Remove the newline character at the end of the input
			text = strings.TrimSpace(text)

			// Check if the user wants to remove the config file
			if strings.ToLower(text) == "y" {

				err := os.Remove("/etc/border0.yaml")
				if err != nil {
					fmt.Println("Error removing the config file:", err)
				} else {
					fmt.Println("Config file removed successfully")
				}
				// now also remove the socket

			}
			return result, err
		case "start":
			return service.Start()
		case "stop":
			return service.Stop()
		case "restart":
			resultFromStop, err := service.Stop()
			if err != nil {
				return resultFromStop, err
			}
			resultFromStart, err := service.Start()
			result := resultFromStop + "\n" + resultFromStart
			return result, err
		case "status":
			return service.Status()
		default:
			return usage, nil
		}

	}
	return usage, nil
}

var connectorStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start the connector",
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
	Short: "stop the connector",
	Run: func(cmd *cobra.Command, args []string) {
		connector.NewConnectorService(*config.NewConfig(), nil, version).Stop()
	},
}

var connectorUnInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "install the connector service on the machine",
	Run: func(cmd *cobra.Command, args []string) {
		connector.NewConnectorService(*config.NewConfig(), nil, version).Stop()
		// put the install code here

	},
}
var connectorInstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "uninstall the connector service from the machine",
	Run: func(cmd *cobra.Command, args []string) {
		connector.NewConnectorService(*config.NewConfig(), nil, version).Stop()
		// put the uninstall code here

		deamonType := daemon.SystemDaemon
		if runtime.GOOS == "darwin" {
			// GlobalDaemon is a system daemon that runs as the root user and stores its
			// property list in the global LaunchDaemons directory. In other words,
			// system-wide daemons provided by the administrator. Valid for macOS only.
			deamonType = daemon.GlobalDaemon
		}

		srv, err := daemon.New(service_name, service_description, deamonType, service_dependencies...)
		if err != nil {
			log.Println("Error: ", err)
			os.Exit(1)
		}
		service := &Service{srv}
		status, err := service.Manage("uninstall")
		if err != nil {
			log.Println(status, "\nError: ", err)
			os.Exit(1)
		}
		fmt.Println(status)

	},
}

func init() {
	connectorStartCmd.Flags().StringVarP(&connectorConfig, "config", "f", "", "setup configuration for connector command")
	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStopCmd)
	connectorCmd.AddCommand(connectorInstallCmd)
	connectorCmd.AddCommand(connectorUnInstallCmd)
	connectorCmd.AddCommand(conenctorServiceCmd)
	rootCmd.AddCommand(connectorCmd)
}
