/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"runtime"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/txn2/txeh"

	"github.com/borderzero/border0-cli/client/preference"
	"github.com/borderzero/border0-cli/cmd/client/db"
	clientTls "github.com/borderzero/border0-cli/cmd/client/tls"

	"github.com/borderzero/border0-cli/cmd/client/hosts"
	"github.com/borderzero/border0-cli/cmd/client/ssh"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/spf13/cobra"
	"github.com/takama/daemon"
)

const (
	// for Service
	service_name        = "border0_service"
	service_description = "Border0.com Service"
)

type Service struct {
	daemon.Daemon
}

var stdlog, errlog *log.Logger

// dependencies that are NOT required by the service, but might be used
var service_dependencies = []string{}

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Client commands",
}

var clientCertCmd = &cobra.Command{
	Use:   "cert",
	Short: "Client certificates",
}

var clientCertFetchCmd = &cobra.Command{
	Use:   "fetch",
	Short: "Fetch Client certificate",
	RunE: func(cmd *cobra.Command, args []string) error {
		if crtPath, keyPath, ok := client.IsClientCertValid(); !ok {
			crtPath, keyPath, err := client.FetchCertAndReturnPaths(hostname)
			if err != nil {
				return err
			}
			fmt.Println("Client certificate file:", crtPath, "and", keyPath)

		} else {
			fmt.Println("Client certificate file:", crtPath, "and", keyPath)
		}
		return nil
	},
}

// clientLoginCmd represents the client login DNS command
var clientLoginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login and get API token so service can authenticate",
	Run: func(cmd *cobra.Command, args []string) {
		if orgID == "" {
			pref, err := preference.Read()
			if err != nil {
				fmt.Println("WARNING: could not read preference file:", err)
			}
			subdomains := pref.RecentlyUsedOrgs(5).Subdomains()

			if len(subdomains) == 1 {
				orgID = subdomains[0]
				fmt.Println("Logging into", orgID, "org...")
			} else if len(subdomains) > 0 {
				if err := survey.AskOne(&survey.Select{
					Message: "choose an org:",
					Options: subdomains,
				}, &orgID, survey.WithValidator(survey.Required)); err != nil {
					fmt.Println("failed to read input:", err)
					return
				}
			}

			if orgID == "" {
				if err = survey.AskOne(&survey.Input{
					Message: "enter an org subdomain:",
				}, &orgID, survey.WithValidator(survey.Required)); err != nil {
					fmt.Println("failed to read input:", err)
					return
				}
			}
		}

		_, claims, err := client.Login(orgID)
		if err != nil {
			log.Fatal(err)
		}

		// read preference file and write logged in org info back to preference file
		id, subdomain := fmt.Sprint(claims["org_id"]), fmt.Sprint(claims["org_subdomain"])
		if err := preference.CreateOrUpdate(id, subdomain); err != nil {
			fmt.Println(err)
		}

		fmt.Println("Login successful")
	},
}

// clientLoginCmd represents the client login DNS command
var clientLoginStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check login status, see if token is still valid",
	Run: func(cmd *cobra.Command, args []string) {
		valid, _, email, err := client.IsExistingClientTokenValid("")
		if !valid {
			fmt.Println(err)
			fmt.Println("Please login again: border0 client login")
		} else {
			fmt.Println("Token Valid, logged in as " + email)
		}
	},
}

// clientDnsUpdaterCmd represents the client dnsupdater command
var clientDnsUpdaterCmd = &cobra.Command{
	Use:   "dnsupdater",
	Short: "this is used by the client service. Updates local dns hosts file with private domains",
	Run: func(cmd *cobra.Command, args []string) {

		if dnsupdater_homedir == "" {
			u, err := user.Current()
			if err != nil {
				log.Fatal(err)
			}
			dnsupdater_homedir = u.HomeDir
		}
		// a default refresh rate to start. will get overwritten by the value returned in API
		// this is to prevent client from overwhelming the API, ie. we can adjust it on API side.

		refresh_rate := 300
		for {
			refresh_rate, _ = updateDNS(dnsupdater_homedir)
			time.Sleep(time.Duration(refresh_rate) * time.Second)
		}

	},
}

// clientServiceCmd represents the client service command
var clientServiceCmd = &cobra.Command{
	Use:   "service",
	Short: "Install, Remove, Start and Stop the border0 client service",

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
			errlog.Println("Error: ", err)
			os.Exit(1)
		}
		service := &Service{srv}
		status, err := service.Manage()
		if err != nil {
			errlog.Println(status, "\nError: ", err)
			os.Exit(1)
		}
		fmt.Println(status)
	},
}

func (service *Service) Manage() (string, error) {

	usage := fmt.Sprintf("Usage: %s %s %s install | remove | start | stop | status", os.Args[0], os.Args[1], os.Args[2])

	// if received any kind of command, do it

	if len(os.Args) > 3 {
		command := os.Args[3]
		switch command {
		case "install":
			u, err := user.Current()
			if err != nil {
				log.Fatal(err)
			}
			homedir := u.HomeDir
			// Also check for sudo users
			username := os.Getenv("SUDO_USER")
			if username != "" {
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
			}

			result, err := service.Install("client", "dnsupdater", "--homedir", homedir)
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
			return service.Remove()
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

func updateDNS(homedir string) (refreshInt int, err error) {
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)

	// default refresh rate is 60secs
	refreshRate := 60
	// Now get the DNS domains request
	// check if we have a valid token before hitting API
	valid, token, _, err := client.IsExistingClientTokenValid(homedir)
	if !valid {
		errlog.Printf(err.Error())
		return refreshRate, err
	}

	dnsDomains, err := client.FetchResources(token)
	if err != nil {
		errlog.Println("Error:", err)
		return refreshRate, err
	}

	// Set refresh hint to what came back from API
	refreshRate = dnsDomains.RefreshHint

	// Add DNS entriess
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		errlog.Printf("couldn't instantiate hosts file  %v", err.Error())
		return refreshRate, err
	}

	for _, ipAddress := range dnsDomains.DefaultIPAddresses {
		hosts.RemoveAddress(ipAddress)
	}

	for _, resource := range dnsDomains.Resources {
		if resource.PrivateSocket {
			for _, domain := range resource.Domains {
				stdlog.Println(domain, resource.IPAddress)
				hosts.AddHost(resource.IPAddress, domain)
			}
		}
	}

	err = hosts.Save()
	if err != nil {
		errlog.Printf("couldn't save file: %v", err.Error())
		return refreshRate, err
	}
	return refreshRate, nil
}

func init() {
	stdlog = log.New(os.Stdout, "", log.Ldate|log.Ltime)
	errlog = log.New(os.Stderr, "", log.Ldate|log.Ltime)

	rootCmd.AddCommand(clientCmd)

	clientCmd.AddCommand(clientCertCmd)
	clientCertCmd.AddCommand(clientCertFetchCmd)
	clientCertFetchCmd.Flags().StringVarP(&hostname, "host", "", "", "The border0 target host")
	clientCertFetchCmd.MarkFlagRequired("host")

	clientCmd.AddCommand(clientLoginCmd)
	clientLoginCmd.Flags().StringVarP(&orgID, "org", "", "", "The border0 organization domain name (without .border0.io)")
	clientLoginCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")

	clientLoginCmd.AddCommand(clientLoginStatusCmd)

	clientCmd.AddCommand(clientDnsUpdaterCmd)
	clientDnsUpdaterCmd.Flags().StringVarP(&dnsupdater_homedir, "homedir", "", "", "The home dir of the user running this service, so it can find tokenfile")

	clientCmd.AddCommand(clientServiceCmd)

	db.AddCommandsTo(clientCmd)
	hosts.AddCommandsTo(clientCmd)
	ssh.AddCommandsTo(clientCmd)
	clientTls.AddCommandsTo(clientCmd)
}
