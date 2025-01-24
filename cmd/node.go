/*
Copyright © 2020 Border0 Inc.

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

// NOTE: this package is hidden from the public and
// only used for internal testing at the moment.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/device"
	"github.com/borderzero/border0-cli/internal/device/config"
	"github.com/borderzero/border0-cli/internal/device/daemon"
	"github.com/borderzero/border0-cli/internal/device/server"
	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-cli/internal/logging"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/kardianos/service"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

const (
	b0Dir         = ".border0"
	stateFileName = "device.state.yaml"
)

var (
	forceReAuth     = false
	homeDirFlag     = ""
	waitForAuthFlag = false
)

// nodeCmd represents the node command
var nodeCmd = &cobra.Command{
	Use:    "node",
	Short:  "Border0 network node commands",
	Hidden: true,
}

// nodeStartCmd represents the node start command
var nodeStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start the node",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger, err := logging.BuildProduction()
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %v", err)
		}
		defer logger.Sync()

		SetRlimit()

		svcDaemon, err := daemon.GetDeviceService()
		if err != nil {
			logger.Error("failed to acquire device service daemon", zap.Error(err))
		}

		config, err := config.GetConfiguration()
		if err != nil {
			return fmt.Errorf("failed to load device management configuration: %v", err)
		}

		// running as amdinistrator will use /var/root as home directory
		homeDir := ""

		// prefer the home directory flag if set
		if homeDirFlag != "" {
			homeDir = homeDirFlag
		} else if util.RunningAsAdministrator() {
			// if running as administrator, the $HOME directory is not set
			// so we need to set the home directory manually
			if runtime.GOOS == "darwin" {
				homeDir = "/var/root"
			} else if runtime.GOOS == "linux" {
				homeDir = "/root"
			}
		} else {
			homeDir, err = util.GetUserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to determine current OS user home directory: %v", err)
			}
		}

		state, err := state.Load(logger, filepath.Join(homeDir, b0Dir, stateFileName))
		if err != nil {
			return fmt.Errorf("failed to load device state: %v", err)
		}

		httpListener, err := server.GetHTTPListener()
		if err != nil {
			return fmt.Errorf("failed to initialize HTTP listener: %v", err)
		}
		defer httpListener.Close()

		// Set up a context to listen for OS interrupt signals
		ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
		defer stop()

		var svc device.Service

		// Create the HTTP server
		srv := server.New(logger, svc, state, internal.Version)

		// if auth is needed and the wait-for-auth flag is set
		//   - run only the http server
		//   - periodically check if the auth has been completed
		//   - if auth is completed
		//     > force re-auth so that the device can be registered
		//     > temporarily shutdown the http server
		//     > recreate the http listener
		//     > continue with the normal flow
		if state.NeedsAuth() && waitForAuthFlag {
			// start the http server and notify windows that the service is running
			if runtime.GOOS == "windows" {
				go func(svcDaemon service.Service) {
					if err := svcDaemon.Run(); err != nil {
						logger.Error("failed to run device service daemon", zap.Error(err))
					}
				}(svcDaemon)
			}

			httpListener, err = waitForAuth(ctx, logger, homeDir, srv, httpListener)
			if err != nil {
				if errors.Is(err, errInteruptSignalReceived) {
					// if the interrupt signal was received, return nil to exit gracefully
					return nil
				}
				return err
			}
		}

		if state.NeedsAuth() || forceReAuth {
			// get a name for the device in case its new
			hostname, _ := os.Hostname()
			if hostname == "" {
				hostname = uuid.NewString()
			}

			logger.Info("registering device with Border0", zap.String("hostname", hostname))

			valid, token, _, claims, err := client.IsExistingClientTokenValid(homeDir)
			if !valid {
				logger.Info("existing client token is invalid")
				return fmt.Errorf("existing client token is invalid: %v", err)
			}

			deviceID, keyExpiry, addresses, err := client.RegisterDevice(state.GetPublicKey().B64(), hostname, token)
			if err != nil {
				logger.Error("failed to register device with Border0", zap.Error(err))
				return fmt.Errorf("failed to register device with Border0: %v", err)
			}

			logger.Info("device registered", zap.String("deviceID", deviceID), zap.Timep("keyExpiry", keyExpiry))

			err = state.
				SetDeviceID(deviceID).
				SetKeyExpiry(keyExpiry).
				SetProfile(profileFromClaims(claims)).
				SetNetworkIPs(
					fmt.Sprintf("%s/32", addresses.IPv4),
					fmt.Sprintf("%s/32", addresses.IPv6),
					addresses.NetworkCIDRv4,
					addresses.NetworkCIDRv6,
					addresses.ResourcesCIDRv4,
					addresses.ResourcesCIDRv6,
				).
				Commit()
			if err != nil {
				logger.Error("failed to commit state to disk", zap.Error(err))
				return fmt.Errorf("failed to commit state to disk: %v", err)
			}
		}

		// Initialize the device service
		svc, err = device.NewService(internal.Version, logger, config, state)
		if err != nil {
			return fmt.Errorf("failed to initialize node: %v", err)
		}

		// Start the service
		serviceDone := make(chan struct{})
		go func() {
			defer close(serviceDone)
			svc.Start()
		}()

		// Create the HTTP server
		srv = server.New(logger, svc, state, internal.Version)

		// run the service daemon on windows this is a necessary step to keep the service running and notify windows
		go func(svcDaemon service.Service) {
			if runtime.GOOS == "windows" {
				if err := svcDaemon.Run(); err != nil {
					logger.Error("failed to run device service daemon", zap.Error(err))
				}
			}
		}(svcDaemon)

		// Serve the HTTP server
		go func() {
			defer stop()
			if err := srv.Serve(httpListener); err != nil && err != http.ErrServerClosed {
				logger.Error("HTTP server error", zap.Error(err))
			}
		}()

		select {
		case <-serviceDone: // Wait for service to be closed by server
			logger.Info("Service is done, shutting down...")
		case <-ctx.Done(): // Wait for context cancellation (Ctrl+C)
			logger.Info("Received interrupt signal, shutting down...")

		}

		// Stop the device service daemon
		dService, err := daemon.GetDeviceService()
		if err != nil {
			logger.Error("failed to acquire device service daemon", zap.Error(err))
		} else {
			dService.Stop()
		}

		// Shutdown HTTP server gracefully
		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("failed to close http server gracefully", zap.Error(err))

		}

		if err := svc.Close(); err != nil {
			logger.Error("failed to close node service gracefully", zap.Error(err))
		}

		return nil
	},
}

var errInteruptSignalReceived = fmt.Errorf("interrupt signal received")

// while waiting for auth:
//   - run only the http server
//   - periodically check if the auth has been completed
//   - if auth is completed
//     > force re-auth so that the device can be registered
//     > temporarily shutdown the http server
//     > recreate the http listener
func waitForAuth(
	ctx context.Context,
	logger *zap.Logger,
	homeDir string,
	srv server.Server,
	httpListener net.Listener,
) (
	net.Listener,
	error,
) {
	// start the HTTP server, so that the macOS app can communicate with the go service
	go func() {
		logger.Info("running the service with only the HTTP server")
		if err := srv.Serve(httpListener); err != nil && err != http.ErrServerClosed {
			logger.Error("HTTP server error", zap.Error(err))
		}
	}()

	// periodically check client token until the token is valid or context is cancelled
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("received interrupt signal, shutting down...")
			srv.Shutdown(ctx)
			return nil, errInteruptSignalReceived
		case <-ticker.C:
			valid, _, _, _, err := client.IsExistingClientTokenValid(homeDir)
			if err != nil || !valid {
				continue
			}

			logger.Info("found valid client token")

			// force re-auth will trigger device registration
			forceReAuth = true
			// shutdown the http server and later we will start it again
			srv.Shutdown(ctx)
			// recreate the HTTP listener
			httpListener, err = server.GetHTTPListener()
			if err != nil {
				return nil, fmt.Errorf("failed to initialize HTTP listener: %v", err)
			}

			return httpListener, nil
		}
	}
}

// nodeVersionCmd represents the node version command tree.
var nodeVersionCmd = &cobra.Command{
	Use:    "version",
	Short:  "Border0 network node version commands",
	Hidden: false,
}

// nodeVersionShowCmd represents the node version show command
var nodeVersionShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show device version",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost/%s", server.PathVersion))
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		fmt.Println(string(body))

		return nil
	},
}

// nodeExitNodeCmd represents the node exit node command tree.
var nodeExitNodeCmd = &cobra.Command{
	Use:    "exitnode",
	Short:  "Border0 node exit node commands",
	Hidden: false,
}

// nodeExitNodeListCmd represents the node exitnode list command
var nodeExitNodeListCmd = &cobra.Command{
	Use:   "list",
	Short: "list exit nodes",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost/%s", server.PathExitNodes))
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		if jsonOutput {
			fmt.Println(string(body))
			return nil
		}

		var exitNodes struct {
			ExitNodes []string `json:"exit_nodes,omitempty"`
			Error     string   `json:"error,omitempty"`
		}

		if err := json.Unmarshal(body, &exitNodes); err != nil {
			return fmt.Errorf("failed to decode response body: %v", err)
		}

		if exitNodes.Error != "" {
			return fmt.Errorf("failed to retrieve exit nodes: %s", exitNodes.Error)
		}

		tbl := table.NewWriter()
		tbl.AppendHeader(table.Row{"Exit Node"})
		tbl.SetColumnConfigs([]table.ColumnConfig{
			{Name: "Exit Node", Align: text.AlignLeft, AlignHeader: text.AlignCenter},
		})

		for _, node := range exitNodes.ExitNodes {
			tbl.AppendRow([]interface{}{node})
		}

		fmt.Println(tbl.Render())

		return nil
	},
}

// nodeExitNodeListCmd represents the node exitnode list command
var nodeExitNodeShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show active exit node",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost/%s", server.PathExitNode))
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		if jsonOutput {
			fmt.Println(string(body))
			return nil
		}

		var exitNode struct {
			ExitNode string `json:"exit_node,omitempty"`
			Error    string `json:"error,omitempty"`
		}

		if err := json.Unmarshal(body, &exitNode); err != nil {
			return fmt.Errorf("failed to decode response body: %v", err)
		}

		if exitNode.Error != "" {
			return fmt.Errorf("failed to retrieve exit node: %s", exitNode.Error)
		}

		if exitNode.ExitNode == "" {
			fmt.Println("no exit node set")
			return nil
		}

		fmt.Println(exitNode.ExitNode)
		return nil
	},
}

// nodeExitNodeSetCmd represents the node exitnode set command
var nodeExitNodeSetCmd = &cobra.Command{
	Use:   "set [node]",
	Short: "set exit node",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("usage: border0 node exitnode set [node]")
		}

		node := args[0]

		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		byt, err := json.Marshal(server.PayloadExitNode{ExitNode: node})
		if err != nil {
			return fmt.Errorf("failed to JSON-encode exit node request: %v", err)
		}

		req, err := http.NewRequest(
			http.MethodPut,
			fmt.Sprintf("http://localhost/%s", server.PathExitNode),
			bytes.NewBuffer(byt),
		)
		if err != nil {
			return fmt.Errorf("failed to build exit node http request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		if resp.StatusCode == http.StatusNoContent {
			if jsonOutput {
				fmt.Println(`{"message":"exit node set successfully"}`)
			} else {
				fmt.Println("exit node set successfully")
			}
			return nil
		}

		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("a non 200 response code was received and failed to read error message from request body: %v", err)
		}

		if jsonOutput {
			fmt.Println(string(bodyBytes))
			return nil
		}

		var errorResp struct {
			Error string `json:"error,omitempty"`
		}

		if err := json.Unmarshal(bodyBytes, &errorResp); err != nil {
			return fmt.Errorf("failed to decode response body: %v", err)
		}

		if errorResp.Error != "" {
			return fmt.Errorf("failed to set exit node: %s", errorResp.Error)
		}

		return fmt.Errorf("failed to set exit node %v", bodyBytes)
	},
}

// nodeExitNodeUnsetCmd represents the node exitnode unset command
var nodeExitNodeUnsetCmd = &cobra.Command{
	Use:   "unset",
	Short: "unset exit node",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		byt, err := json.Marshal(server.PayloadExitNode{ExitNode: ""})
		if err != nil {
			return fmt.Errorf("failed to JSON-encode exit node request: %v", err)
		}

		req, err := http.NewRequest(
			http.MethodPut,
			fmt.Sprintf("http://localhost/%s", server.PathExitNode),
			bytes.NewBuffer(byt),
		)
		if err != nil {
			return fmt.Errorf("failed to build exit node http request: %v", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		if resp.StatusCode == http.StatusNoContent {
			if jsonOutput {
				fmt.Println(`{"message":"exit node unset successfully"}`)
			} else {
				fmt.Println("exit node unset successfully")
			}
			return nil
		}

		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("a non 200 response code was received and failed to read error message from request body: %v", err)
		}

		if jsonOutput {
			fmt.Println(string(bodyBytes))
			return nil
		}

		var errorResp struct {
			Error string `json:"error,omitempty"`
		}

		if err := json.Unmarshal(bodyBytes, &errorResp); err != nil {
			return fmt.Errorf("failed to decode response body: %v", err)
		}

		if errorResp.Error != "" {
			return fmt.Errorf("failed to unset exit node: %s", errorResp.Error)
		}

		return fmt.Errorf("failed to unset exit node %v", bodyBytes)
	},
}

// nodeStateCmd represents the node state command tree.
var nodeStateCmd = &cobra.Command{
	Use:    "state",
	Short:  "Border0 network node state commands",
	Hidden: false,
}

// nodeStateShowCmd represents the node state show command
var nodeStateShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show device state",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost/%s", server.PathState))
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		fmt.Println(string(body))

		return nil
	},
}

var nodeServiceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "display the service status",
	Run: func(cmd *cobra.Command, args []string) {
		displayServiceStatus("border0-device")
	},
}

var nodeWireGuardCmd = &cobra.Command{
	Use:   "wg",
	Short: "display the status of WireGuard configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost/%s", server.PathVpnWGStatus))
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to retrieve WireGuard configuration from server: %s", string(bodyBytes))
		}

		fmt.Println(string(bodyBytes))
		return nil
	},
}

var nodePeersCmd = &cobra.Command{
	Use:   "peers",
	Short: "display the status of peer-to-peer connectivity",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost/%s", server.PathVpnPeersStatus))
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to retrieve peers from server: %s", string(bodyBytes))
		}

		if jsonOutput {
			fmt.Println(string(bodyBytes))
			return nil
		}

		var peersResp server.PayloadVPNPeersStatus
		if err := json.Unmarshal(bodyBytes, &peersResp); err != nil {
			return fmt.Errorf("failed to decode response body: %v", err)
		}

		tbl := table.NewWriter()
		tbl.AppendHeader(table.Row{"Alias", "Private IPv4", "Private IPv6", "Public Addresses", "Method", "RTT", "Loss", "MTU", "Score", "Latest Reply", "Active"})
		tbl.SetColumnConfigs([]table.ColumnConfig{
			{Name: "Alias", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Private IPv4", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Private IPv6", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Public Addresses", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Method", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "RTT", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Loss", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "MTU", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Score", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Latest Reply", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Active", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
		})

		// sort peers by public key
		sort.Slice(peersResp.Peers, func(i, j int) bool {
			return peersResp.Peers[i].PublicKey < peersResp.Peers[j].PublicKey
		})

		for _, peer := range peersResp.Peers {
			// since the introduction of selective connection methods via the env BORDER0_ALLOWED_METHODS
			// it is possible that a peer may have no connection methods to a remote peer. In that case
			// we still show the peer in the table with all fields set to N/A.
			nConns := len(peer.Connections)
			if nConns == 0 {
				tbl.AppendRow(table.Row{
					peer.Alias,
					peer.PrivateIPv4,
					peer.PrivateIPv6,
					peer.PublicKey,
					"N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A",
				})
				tbl.AppendSeparator()
				continue
			}
			// sort connections by method name
			sort.Slice(peer.Connections, func(i, j int) bool {
				return peer.Connections[i].Method < peer.Connections[j].Method
			})
			// determine identifiers index e.g. the index of the table row where
			// we print the identifiers (alias, private IPv4, and private IPv6)
			identifiersIndex := (nConns / 2) - 1
			if nConns%2 != 0 {
				identifiersIndex++
			}
			for i, conn := range peer.Connections {
				aliasColumn, ipv4Column, ipv6Column := "", "", ""
				if i == identifiersIndex {
					aliasColumn, ipv4Column, ipv6Column = peer.Alias, peer.PrivateIPv4, peer.PrivateIPv6
				}
				lastProbeReceived := "-"
				if !conn.LastProbe.IsZero() {
					lastProbeReceived = fmt.Sprintf("%.0fs ago (unix:%d)", time.Since(conn.LastProbe).Seconds(), conn.LastProbe.Unix())
				}
				active := ""
				if conn.Active {
					active = "*"
				}
				// NOTE: omit the public key in the connection rows
				tbl.AppendRow(table.Row{
					aliasColumn,
					ipv4Column,
					ipv6Column,
					conn.Address,
					conn.Method,
					conn.RTT,
					conn.Loss,
					conn.MTU,
					conn.Score,
					lastProbeReceived,
					active,
				})
			}
			tbl.AppendSeparator()
		}
		fmt.Println(tbl.Render())
		return nil
	},
}

var nodeStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "display the stats of the underlying WireGuard device",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := server.GetHTTPClient()
		if err != nil {
			return err
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost/%s", server.PathVpnStats))
		if err != nil {
			return fmt.Errorf("failed to execute http request: %v", err)
		}
		defer resp.Body.Close()

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to retrieve peers from server: %s", string(bodyBytes))
		}

		if jsonOutput {
			fmt.Println(string(bodyBytes))
			return nil
		}

		var statsResp stats.Stats
		if err := json.Unmarshal(bodyBytes, &statsResp); err != nil {
			return fmt.Errorf("failed to decode response body: %v", err)
		}

		tbl := table.NewWriter()
		tbl.AppendHeader(table.Row{"Metric", "Count"})
		tbl.SetColumnConfigs([]table.ColumnConfig{
			{Name: "Metric", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
			{Name: "Count", Align: text.AlignCenter, AlignHeader: text.AlignCenter},
		})

		tbl.AppendRow([]any{"RX Bytes", statsResp.BytesIn})
		tbl.AppendRow([]any{"TX Bytes", statsResp.BytesOut})
		tbl.AppendRow([]any{"RX Packets", statsResp.PacketsIn})
		tbl.AppendRow([]any{"TX Packets", statsResp.PacketsOut})

		fmt.Println(tbl.Render())
		return nil
	},
}

// nodeStateShowCmd represents the node state show command
var nodeStateInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "install the service",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger, err := logging.BuildProduction()
		if err != nil {
			return fmt.Errorf("failed to initialize logger: %v", err)
		}

		opts := []daemon.Option{}
		if homeDirFlag != "" {
			opts = append(opts, daemon.WithHomeDir(homeDirFlag))
		}
		if waitForAuthFlag {
			opts = append(opts, daemon.WithWaitForAuth())
		}

		svc, err := daemon.GetDeviceService(opts...)
		if err != nil {
			return fmt.Errorf("failed to build device service object: %v", err)
		}
		if serviceFlag != "" {
			err = service.Control(svc, serviceFlag)
			if err != nil {
				logger.Error("failed to handle OS service control message", zap.Error(err))
				return err
			}
		}
		if err != nil {
			return fmt.Errorf("failed to initialize new connector service object: %v", err)
		}

		if err = svc.Install(); err != nil {
			if !strings.Contains(err.Error(), "Init already exists") {
				return fmt.Errorf("failed to install service: %v", err)
			}
		}
		fmt.Println("🚀 Border0 device service installed successfully!")

		if err = svc.Start(); err != nil {
			if strings.Contains(err.Error(), "already running") {
				fmt.Println("🚀 Border0 device service already running!")
				return nil
			} else {
				return fmt.Errorf("failed to start service: %v", err)
			}
		}
		fmt.Println("🚀 Border0 device service started successfully!")

		return nil
	},
}

var nodeStateUnInstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "uninstall the device service from the machine",
	Run: func(cmd *cobra.Command, args []string) {
		if !util.RunningAsAdministrator() {
			log.Println("Error: command must be ran as system administrator")
			os.Exit(1)
		}

		if err := daemon.Uninstall(); err != nil {
			log.Printf("Failed to uninstall service: %v", err)
			os.Exit(1)
		}
	},
}

// nodeVpnCmd represents the node vpn command tree.
var nodeVpnCmd = &cobra.Command{
	Use:    "vpn",
	Short:  "Border0 network node vpn commands",
	Hidden: false,
}

// nodeVpnStartCmd represents the node vpn start command.
var nodeVpnStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start the vpn",
	RunE:  func(cmd *cobra.Command, args []string) error { return nodeServiceReq(true) },
}

// nodeVPNStopCmd represents the node vpn stop command.
var nodeServiceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop the vpn",
	RunE:  func(cmd *cobra.Command, args []string) error { return nodeServiceReq(false) },
}

// nodeDebugCmd represents the node debug command tree.
var nodeDebugCmd = &cobra.Command{
	Use:   "debug",
	Short: "Border0 network node debug commands",
}

func nodeServiceReq(start bool) error {
	client, err := server.GetHTTPClient()
	if err != nil {
		return err
	}

	byt, err := json.Marshal(server.PayloadServiceStatus{Running: start})
	if err != nil {
		return fmt.Errorf("failed to JSON-encode service status request: %v", err)
	}

	req, err := http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("http://localhost/%s", server.PathVpnStatus),
		bytes.NewBuffer(byt),
	)
	if err != nil {
		return fmt.Errorf("failed to build service status http request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to execute http request: %v", err)
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}

	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("a non 200 response code was received and failed to read error message from request body: %v", err)
	}

	fmt.Println(string(bodyBytes))
	return nil
}

func profileFromClaims(claims jwt.MapClaims) *state.Profile {
	return &state.Profile{
		ImageURL:     fmt.Sprint(claims["picture"]),
		Name:         fmt.Sprint(claims["name"]),
		Email:        fmt.Sprint(claims["user_email"]),
		OrgID:        fmt.Sprint(claims["org_id"]),
		OrgSubdomain: fmt.Sprint(claims["org_subdomain"]),
	}
}

func init() {
	nodeStartCmd.Flags().BoolVar(&forceReAuth, "force-reauth", false, "Force re-authentication to extend the lifetime of an existing device key")
	nodeStartCmd.Flags().StringVar(&homeDirFlag, "home-dir", "", "Home directory for the device service")
	nodeStartCmd.Flags().BoolVar(&waitForAuthFlag, "wait-for-auth", false, "Run the minimum service with only the HTTP server")
	nodeStateInstallCmd.Flags().StringVar(&homeDirFlag, "home-dir", "", "Home directory for the device service")
	nodeStateInstallCmd.Flags().BoolVar(&waitForAuthFlag, "wait-for-auth", false, "Run the minimum service with only the HTTP server")
	nodePeersCmd.Flags().BoolVar(&jsonOutput, "json", false, "Print output as JSON")

	nodeCmd.AddCommand(nodeStartCmd)
	nodeVersionCmd.AddCommand(nodeVersionShowCmd)
	nodeCmd.AddCommand(nodeVersionCmd)
	nodeCmd.AddCommand(nodeStateInstallCmd)
	nodeCmd.AddCommand(nodeStateUnInstallCmd)

	nodeStateCmd.AddCommand(nodeStateShowCmd)

	nodeCmd.AddCommand(nodeStateCmd)

	nodeExitNodeCmd.AddCommand(nodeExitNodeListCmd)
	nodeExitNodeCmd.AddCommand(nodeExitNodeShowCmd)
	nodeExitNodeCmd.AddCommand(nodeExitNodeSetCmd)
	nodeExitNodeCmd.AddCommand(nodeExitNodeUnsetCmd)
	nodeCmd.AddCommand(nodeExitNodeCmd)

	nodeVpnCmd.AddCommand(nodeVpnStartCmd)
	nodeVpnCmd.AddCommand(nodeServiceStopCmd)
	nodeCmd.AddCommand(nodeVpnCmd)
	nodeCmd.AddCommand(nodeServiceStatusCmd)

	nodeDebugCmd.AddCommand(nodePeersCmd)
	nodeDebugCmd.AddCommand(nodeStatsCmd)
	nodeDebugCmd.AddCommand(nodeWireGuardCmd)
	nodeCmd.AddCommand(nodeDebugCmd)

	rootCmd.AddCommand(nodeCmd)
}
