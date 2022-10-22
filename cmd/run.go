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
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

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
		go startSocketTunnel(cmd)

		if err := process.Wait(); err != nil {
			if exiterr, ok := err.(*exec.ExitError); ok {
				log.Printf("Exit Status: %d", exiterr.ExitCode())
				os.Exit(exiterr.ExitCode())
			} else {
				log.Fatalf("cmd.Wait: %v", err)
				os.Exit(1)

			}
		}

	},
}

func startSocketTunnel(cmd *cobra.Command) {
	// Start a socket tunnel
	for {
		border0ProcessPath := "/usr/local/bin/border0"

		border0ProcessArgs := []string{"connect", "--type", "ssh", "--sshserver", "--name", "mycontainer"}

		border0Process := exec.Command(border0ProcessPath, border0ProcessArgs...)

		border0Process.Stdout = cmd.OutOrStdout()
		border0Process.Stderr = cmd.OutOrStderr()
		border0Process.Stdin = cmd.InOrStdin()

		err := border0Process.Start()
		if err != nil {
			errlog.Fatalf("failed to start Border0 tunnel: %v", err)

		}
		if err := border0Process.Wait(); err != nil {
			if exiterr, ok := err.(*exec.ExitError); ok {
				log.Printf("Border0 tunnel exit Status: %d", exiterr.ExitCode())
				os.Exit(exiterr.ExitCode())
			} else {
				log.Fatalf("cmd.Wait: %v", err)
				os.Exit(1)

			}
		}
		time.Sleep(2 * time.Second)
	}

}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&runcommand, "command", "c", "", "Command to execute")
}
