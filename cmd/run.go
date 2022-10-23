/*
Copyright © 2020 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARR    ANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/ssh"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "run command",

	Run: func(cmd *cobra.Command, args []string) {
		// Start a process
		var processPath string
		var processArgs []string

		if runcommand == "" {
			processPath = args[0]
			processArgs = args[1:]

		} else {
			args = strings.Split(runcommand, " ")
			processPath = args[0]
			processArgs = args[1:]
		}

		process := exec.Command(processPath, processArgs...)
		process.Stdout = cmd.OutOrStdout()
		process.Stderr = cmd.OutOrStderr()
		process.Stdin = cmd.InOrStdin()
		err := process.Start()
		if err != nil {
			errlog.Fatalf("cmd.Start: %v", err)
			os.Exit(1)
		}

		// Let's make sure we catch the signals
		cleanupDone := make(chan bool)
		quitChannel := make(chan bool)
		chsyscall := make(chan os.Signal)

		signal.Notify(chsyscall, os.Interrupt, syscall.SIGTERM,
			syscall.SIGINT, syscall.SIGQUIT, syscall.SIGABRT,
			syscall.SIGTSTP, syscall.SIGHUP, syscall.SIGALRM, syscall.SIGUSR1, syscall.SIGUSR2)
		// This makes sure we intercept the signals and relay them to the process
		go func() {
			for {
				syscall := <-chsyscall
				//fmt.Printf("Received an interrupt, signalling process...+%v", syscall)
				process.Process.Signal(syscall)
			}

		}()

		go createSocketStartTunnel(cmd, quitChannel, cleanupDone)

		process.Wait() // will wait until finished

		// if done, then cleanup.. this makes sure we don't leave any sockets orphans
		quitChannel <- true

		// wait for cleanup to finish
		// We'll set a ticker as well, to make sure we have a timeout
		// In case the cleanup doesn't finish or take to long
		ticker := time.NewTicker(2000 * time.Millisecond)
		for {
			select {
			case <-ticker.C:
				fmt.Println("Timeout reached, exiting")
				os.Exit(process.ProcessState.ExitCode())
			case <-cleanupDone:
				//fmt.Println("Process finished with exit code", process.ProcessState.ExitCode())
				os.Exit(process.ProcessState.ExitCode())
			}
		}

	},
}

func createSocketStartTunnel(cmd *cobra.Command, quitChannel chan bool, cleanupDone chan bool) {
	socketId := ""
	go func() {
		// This will make sure we cleanup the socket as soon as we get something on the quitChannel
		<-quitChannel
		if socketId != "" {
			client, _ := http.NewClient()
			err := client.Request("DELETE", "socket/"+socketId, nil, nil)
			if err != nil {
				log.Printf("error: %v", err)
			}
		}
		// And let our parent know we're done with the clean up
		cleanupDone <- true

	}()

	i := 0
	for {
		i++
		if i < 3 {
			time.Sleep(1000 * time.Millisecond)
		} else if i < 10 {
			time.Sleep(2000 * time.Millisecond)
		} else {
			time.Sleep(time.Duration(i) * time.Second)
		}
		client, err := http.NewClient()
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown-container"
		}
		connection := &models.Socket{
			Name:             hostname,
			Description:      "border0 run " + hostname,
			SocketType:       "ssh",
			CloudAuthEnabled: true,
		}
		c := models.Socket{}
		err = client.WithVersion(version).Request("POST", "connect", &c, connection)
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}
		socketId = c.SocketID

		fmt.Print(print_socket(c))

		userID, _, err := http.GetUserID()
		if err != nil {
			log.Printf("error: %v", err)
			continue
		}

		userIDStr := *userID
		time.Sleep(1 * time.Second)

		SetRlimit()
		localssh = true

		org := models.Organization{}
		err = client.Request("GET", "organization", &org, nil)
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}

		ssh.SshConnect(userIDStr, c.SocketID, c.Tunnels[0].TunnelID, port, hostname, identityFile, proxyHost, version, httpserver, localssh, org.Certificates["ssh_public_key"], "", httpserver_dir)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Sleep for 2 second before reconnecting
		time.Sleep(2 * time.Second)
	}

}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&runcommand, "command", "c", "", "Command to execute")
}
