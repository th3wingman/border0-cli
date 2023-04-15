package cmd

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

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

	usage := fmt.Sprintf("Usage: %s %s %s install | remove | start | stop | status", os.Args[0], os.Args[1], os.Args[2])

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

			// Now we generate a basic Yaml
			// create multilie string
			yaml := fmt.Sprintf(`---
connector:
    name: "%s-cntr"

credentials:
    token: %s

sockets:
    - ssh-%s:
        type: ssh
        sshserver: true
 `, myHostname, t.Token, myHostname)

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

			// Now we install the service
			result, err := service.Install("connector", "start", "--config", configPath)
			if err != nil {
				return result, err
			}
			// Also start the service
			fmt.Println(result)
			return service.Start()

		case "remove":
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

func init() {
	connectorStartCmd.Flags().StringVarP(&connectorConfig, "config", "f", "", "setup configuration for connector command")
	connectorCmd.AddCommand(connectorStartCmd)
	connectorCmd.AddCommand(connectorStopCmd)
	connectorCmd.AddCommand(conenctorServiceCmd)
	rootCmd.AddCommand(connectorCmd)
}
