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
	"bufio"
	"encoding/json"
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
	"github.com/prometheus/procfs"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"

	pprocess "github.com/shirou/gopsutil/process"
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
		quitChannelSsh := make(chan bool)
		quitChannelHttp := make(chan bool)
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

		// HTTP go routines
		go processStats(*process)
		go createHTTPSocketStartTunnel(cmd, quitChannelHttp, cleanupDone)

		// SSH go routines
		go createSocketStartTunnel(cmd, quitChannelSsh, cleanupDone)

		process.Wait() // will wait until finished

		// if done, then cleanup.. this makes sure we don't leave any sockets orphans
		quitChannelSsh <- true
		quitChannelHttp <- true

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
				// TODO need to make sure, both ssh and http are done
				time.Sleep(100 * time.Millisecond)
				os.Exit(process.ProcessState.ExitCode())
			}
		}

	},
}

func createSocketStartTunnel(cmd *cobra.Command, quitChannelSsh chan bool, cleanupDone chan bool) {
	socketId := ""
	go func() {
		// This will make sure we cleanup the socket as soon as we get something on the quitChannel
		<-quitChannelSsh
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
			Name:             "ssh-" + hostname,
			Description:      "border0 systems stats " + hostname,
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
		localsshServer := true

		org := models.Organization{}
		err = client.Request("GET", "organization", &org, nil)
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}

		ssh.SshConnect(userIDStr, c.SocketID, c.Tunnels[0].TunnelID, port, hostname, identityFile, proxyHost, version, httpserver, localsshServer, org.Certificates["ssh_public_key"], "", httpserver_dir)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Sleep for 2 second before reconnecting
		time.Sleep(2 * time.Second)
	}

}

func createHTTPSocketStartTunnel(cmd *cobra.Command, quitChannelHttp chan bool, cleanupDone chan bool) {
	socketId := ""
	go func() {
		// This will make sure we cleanup the socket as soon as we get something on the quitChannel
		<-quitChannelHttp
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
	// Start a goroutine to wait for the process to exit

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
			Name:             "status-" + hostname,
			Description:      "border0 systems stats " + hostname,
			SocketType:       "http",
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
		httpserver = true
		httpserver_dir = "/tmp/border0stats"

		org := models.Organization{}
		err = client.Request("GET", "organization", &org, nil)
		if err != nil {
			log.Printf("Error: %v", err)
			continue
		}

		ssh.SshConnect(userIDStr, c.SocketID, c.Tunnels[0].TunnelID, port, hostname, identityFile, proxyHost, version, httpserver, false, org.Certificates["ssh_public_key"], "", httpserver_dir)
		if err != nil {
			fmt.Println(err)
			continue
		}

		// Sleep for 2 second before reconnecting
		time.Sleep(2 * time.Second)
	}

}

func processStats(process exec.Cmd) {
	os.MkdirAll("/tmp/border0stats", os.ModePerm)

	for {

		f, err := os.OpenFile("/tmp/border0stats/index.html", os.O_WRONLY|os.O_CREATE, 0600)

		if err != nil {
			log.Printf("Error: %v", err)
			return
		}
		defer f.Close()
		w := bufio.NewWriter(f)
		time.Sleep(2 * time.Second)
		p, err := procfs.NewProc(process.Process.Pid)
		if err != nil {
			log.Printf("could not get process: %s", err)
		}

		stat, err := p.Stat()

		if err != nil {
			log.Printf("could not get process stat: %s", err)
		}

		if err != nil {
			log.Printf("could not get process fdinfo: %s", err)
		}

		fs, err := procfs.NewFS("/proc")
		if err != nil {
			log.Printf("failed to open procfs: %v", err)
		}

		loadavg, err := fs.LoadAvg()
		if err != nil {
			log.Printf("failed to get loadavg: %v", err)
		}

		//fmt.Printf("Process %d has %d open file descriptors
		//fmt.Printf("Process %d: %
		exec, _ := p.CmdLine()
		netstat, _ := p.Netstat()
		fmt.Fprintf(w, "<h1>Process data</h1>")
		fmt.Fprintf(w, "command:  %s<br>", stat.Comm)
		fmt.Fprintf(w, "command:  %s<br>", exec)
		fmt.Fprintf(w, "pid:      %d<br>", stat.PID)
		fmt.Fprintf(w, "<hr>")
		fmt.Fprintf(w, "cpu time: %fs<br>", stat.CPUTime())
		fmt.Fprintf(w, "vsize:    %dB<br>", stat.VirtualMemory())
		fmt.Fprintf(w, "rss:      %dB<br>", stat.ResidentMemory())
		fmt.Fprintf(w, "<hr>")
		fmt.Fprintf(w, "Load last 1min:     %f<br>", loadavg.Load1)
		fmt.Fprintf(w, "Load last 5min:     %f<br>", loadavg.Load5)
		fmt.Fprintf(w, "Load last 15min:     %f<br>", loadavg.Load15)
		fmt.Fprintf(w, "<hr>")
		fmt.Fprintf(w, "<h1>Netstat</h1><br>")
		fmt.Fprintf(w, "netstat:     %+v<br>", netstat)

		fmt.Fprintf(w, "<hr>")
		fmt.Fprintf(w, "<h1>Host info</h1><br>")
		hi, _ := host.Info()
		fmt.Fprintf(w, "%+v", hi)

		v, _ := mem.VirtualMemory()

		fmt.Fprintf(w, "====Virtual Memory====<br>")
		// almost every return value is a struct
		fmt.Fprintf(w, "Total: %v, Free:%v, UsedPercent:%f%%\n", v.Total, v.Free, v.UsedPercent)

		fmt.Fprintf(w, "%+v", v)

		sm, _ := mem.SwapMemory()
		fmt.Fprintf(w, "%v swap memory", sm)

		fmt.Fprintf(w, "====CPU data====<br>")
		cput, _ := cpu.Times(true)
		fmt.Fprintf(w, "%+v<br>", cput)

		cpui, _ := cpu.Info()
		fmt.Fprintf(w, "%+v<br>", cpui)

		disku, _ := disk.Usage("/")
		fmt.Fprintf(w, "%+v<br>", disku)

		fmt.Fprintf(w, "====load avg====<br>")
		la, _ := load.Avg()
		fmt.Fprintf(w, "%+v<br>", la)

		fmt.Fprintf(w, "====Network interfaces====<br>")
		ni, _ := net.Interfaces()
		fmt.Fprintf(w, "%+v<br>", ni)

		fmt.Fprintf(w, "====Net io counter====<br>")
		nioc, _ := net.IOCounters(true)
		fmt.Fprintf(w, "%+v<br>", nioc)

		fmt.Fprintf(w, "====net protocl counters====<br>")
		npc, _ := net.ProtoCounters([]string{})
		fmt.Fprintf(w, "%+v<br>", npc)

		fmt.Fprintf(w, "====process pids====<br>")
		ppi, _ := pprocess.Pids()
		fmt.Fprintf(w, "%+v<br>", ppi)
		fmt.Fprintf(w, "====process processes====<br>")
		pps, _ := pprocess.Processes()
		fmt.Fprintf(w, "%+v<br>", pps)

		w.Flush()

		f.Close()
		time.Sleep(5 * time.Second)

	}

}
func printJson(data interface{}, title string) string {
	pretty, _ := json.MarshalIndent(data, "", "    ")
	return (fmt.Sprintf("====================%s======================\n %s", title, pretty))
}

func init() {
	rootCmd.AddCommand(runCmd)
	runCmd.Flags().StringVarP(&runcommand, "command", "c", "", "Command to execute")
}
