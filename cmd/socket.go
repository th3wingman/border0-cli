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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"

	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal"
	"github.com/borderzero/border0-cli/internal/api"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/cloudsql"
	"github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/httpproxylib"
	"github.com/borderzero/border0-cli/internal/sqlauthproxy"
	"github.com/borderzero/border0-cli/internal/ssh"
	"github.com/borderzero/border0-cli/internal/ssh/config"
	"github.com/borderzero/border0-cli/internal/ssh/server"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/borderzero/border0-cli/internal/vpnlib"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	gossh "golang.org/x/crypto/ssh"
)

// socketCmd represents the socket command
var socketCmd = &cobra.Command{
	Use:   "socket",
	Short: "Manage your global sockets",
}

// socketsListCmd represents the socket ls command
var socketsListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List your sockets",
	Run: func(cmd *cobra.Command, args []string) {
		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		sockets := []models.Socket{}
		err = client.Request("GET", "connect", &sockets, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		var portsStr string

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		t := table.NewWriter()
		t.AppendHeader(table.Row{"Socket ID", "Name", "DNS Name", "Port(s)", "Type", "Description"})

		for _, s := range sockets {
			portsStr = ""
			for _, p := range s.SocketTcpPorts {
				i := strconv.Itoa(p)
				if portsStr == "" {
					portsStr = i
				} else {
					portsStr = portsStr + ", " + i
				}
			}

			t.AppendRow(table.Row{s.SocketID, s.Name, s.Dnsname, portsStr, s.SocketType, s.Description})
		}
		t.SetStyle(table.StyleLight)
		fmt.Printf("%s\n", t.Render())
	},
}

// socketCreateCmd represents the socket create command
var socketCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new socket",
	Run: func(cmd *cobra.Command, args []string) {
		if name == "" {
			log.Fatalf("error: empty name not allowed")
		}

		var allowedEmailAddresses []string
		var allowedEmailDomains []string
		var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

		for _, a := range strings.Split(cloudauth_addresses, ",") {
			email := strings.TrimSpace(a)
			if emailRegex.MatchString(email) {
				allowedEmailAddresses = append(allowedEmailAddresses, email)
			} else {
				if email != "" {
					log.Printf("Warning: ignoring invalid email %s", email)
				}
			}
		}

		for _, d := range strings.Split(cloudauth_domains, ",") {
			domain := strings.TrimSpace(d)
			if domain != "" {
				allowedEmailDomains = append(allowedEmailDomains, domain)
			}
		}

		socketType := strings.ToLower(socketType)
		if socketType != "http" && socketType != "https" && socketType != "tls" && socketType != "ssh" && socketType != "database" {
			log.Fatalf("error: --type should be either http, https, ssh, database or tls")
		}

		upstreamType := strings.ToLower(upstream_type)
		if socketType == "http" || socketType == "https" {
			if upstreamType != "http" && upstreamType != "https" && upstreamType != "" {
				log.Fatalf("error: --upstream_type should be either http, https")
			}
		}

		var upstream_cert, upstream_key, upstream_ca *string
		if socketType == "database" {
			if upstreamType != "mysql" && upstreamType != "postgres" && upstreamType != "mssql" && upstreamType != "" {
				log.Fatalf("error: --upstream_type should be mysql, mssql or postgres, defaults to mysql")
			}

			if upstream_cert_file != "" {
				byt, err := os.ReadFile(upstream_cert_file)
				if err != nil {
					util.FailPretty("failed to read the upstream certificate file: %s", err)
				}

				cert := string(byt)
				upstream_cert = &cert
			}

			if upstream_key_file != "" {
				byt, err := os.ReadFile(upstream_key_file)
				if err != nil {
					util.FailPretty("failed to read the upstream key file: %s", err)
				}

				key := string(byt)
				upstream_key = &key
			}

			if upstream_ca_file != "" {
				byt, err := os.ReadFile(upstream_ca_file)
				if err != nil {
					util.FailPretty("failed to read the upstream ca file: %s", err)
				}

				ca := string(byt)
				upstream_ca = &ca
			}

		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		s := models.Socket{}
		newSocket := &models.Socket{
			Name:                           name,
			Description:                    description,
			SocketType:                     socketType,
			AllowedEmailAddresses:          allowedEmailAddresses,
			AllowedEmailDomains:            allowedEmailDomains,
			UpstreamUsername:               &upstream_username,
			UpstreamPassword:               &upstream_password,
			UpstreamHttpHostname:           &upstream_http_hostname,
			UpstreamType:                   upstreamType,
			CloudAuthEnabled:               true,
			ConnectorAuthenticationEnabled: connectorAuthEnabled,
			OrgCustomDomain:                orgCustomDomain,
			UpstreamCert:                   upstream_cert,
			UpstreamKey:                    upstream_key,
			UpstreamCa:                     upstream_ca,
		}
		err = client.WithVersion(internal.Version).Request("POST", "socket", &s, newSocket)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		// Now also get all Org wide Policies
		orgWidePolicies := []models.Policy{}
		err = client.Request("GET", "policies/?org_wide=true", &orgWidePolicies, nil)

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Print(print_socket(s, orgWidePolicies))
	},
}

// socketDeleteCmd represents the socket delete command
var socketDeleteCmd = &cobra.Command{
	Use:               "delete [socket]",
	Short:             "Delete a socket",
	ValidArgsFunction: AutocompleteSocket,
	RunE: func(cmd *cobra.Command, args []string) error {
		if socketID == "" && (len(args) == 0) {
			return fmt.Errorf("error: no socket provided")
		}

		if len(args) > 0 {
			socketID = args[0]
		}

		client, err := http.NewClient()

		if err != nil {
			log.Fatalf("error: %v", err)
		}

		err = client.Request("DELETE", "socket/"+socketID, nil, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		fmt.Println("Socket deleted")
		return nil
	},
}

// socketShowCmd represents the socket delete command
var socketShowCmd = &cobra.Command{
	Use:               "show [socket]",
	Short:             "Show socket details",
	ValidArgsFunction: AutocompleteSocket,
	RunE: func(cmd *cobra.Command, args []string) error {
		if socketID == "" && (len(args) == 0) {
			return fmt.Errorf("error: no socket provided")
		}

		if len(args) > 0 {
			socketID = args[0]
		}

		client, err := http.NewClient()
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		socket := models.Socket{}
		err = client.Request("GET", "socket/"+socketID, &socket, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}
		// Now also get all Org wide Policies
		orgWidePolicies := []models.Policy{}
		err = client.Request("GET", "policies/?org_wide=true", &orgWidePolicies, nil)
		if err != nil {
			log.Fatalf(fmt.Sprintf("Error: %v", err))
		}

		if err != nil {
			log.Fatalf("Error: %v", err)
		}

		fmt.Print(print_socket(socket, orgWidePolicies))
		return nil
	},
}
var socketConnectProxyCmd = &cobra.Command{
	Use:               "proxy",
	Short:             "start a forward proxy on the TLS socket",
	ValidArgsFunction: AutocompleteSocket,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		border0API := api.NewAPI(api.WithVersion(internal.Version))

		if socketID == "" && (len(args) == 0) {
			return fmt.Errorf("error: no socket provided")
		}
		if len(args) > 0 {
			socketID = args[0]
		}

		socket, err := border0.NewSocket(ctx, border0API, socketID, logger.Logger)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		if socket.Socket.ConnectorLocalData == nil {
			socket.Socket.ConnectorLocalData = &models.ConnectorLocalData{}
		}

		if socket.Socket.ConnectorData == nil {
			socket.Socket.ConnectorData = &models.ConnectorData{}
		}

		socket.WithVersion(internal.Version)

		if proxyHost != "" {
			if err := socket.WithProxy(proxyHost); err != nil {
				log.Fatalf("error: %v", err)
			}
		}

		if socket.EndToEndEncryptionEnabled {
			certificate, err := util.GetEndToEndEncryptionCertificate(socket.Organization.ID, "")
			if err != nil {
				log.Printf("failed to get connector certificate: %s", err)
			}

			if certificate == nil {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return fmt.Errorf("failed to generate private key: %w", err)
				}

				csrTemplate := x509.CertificateRequest{
					Subject:            pkix.Name{CommonName: "border0"},
					SignatureAlgorithm: x509.PureEd25519,
				}

				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
				if err != nil {
					return fmt.Errorf("failed to create certificate request: %w", err)
				}

				csrPem := pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csrBytes,
				}

				var name string
				hostname, err := os.Hostname()
				if err != nil {
					name = "border0-cli"
				} else {
					name = hostname
				}

				cert, err := border0API.ServerOrgCertificate(ctx, name, pem.EncodeToMemory(&csrPem))
				if err != nil {
					return fmt.Errorf("failed to get certificate: %w", err)
				}

				privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
				if err != nil {
					return fmt.Errorf("failed to marshal private key: %w", err)
				}

				privKeyPem := &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: privKeyBytes,
				}

				tlsCert, err := tls.X509KeyPair(cert, pem.EncodeToMemory(privKeyPem))
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}

				certificate = &tlsCert

				if err := util.StoreConnectorCertifcate(pem.EncodeToMemory(privKeyPem), cert, orgID, ""); err != nil {
					log.Printf("failed to store certificate: %s", err)
				}
			}

			socket.WithCertificate(certificate)
		}

		SetRlimit()

		border0API.StartRefreshAccessTokenJob(ctx)

		l, err := socket.Listen()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		defer l.Close()

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for {
				<-c
				os.Exit(0)
			}
		}()

		err = httpproxylib.StartHttpProxy(l, allowedProxyHosts)
		if err != nil {
			log.Fatalf("Proxy stopped with error: %v", err)
		} else {
			fmt.Println("Proxy stopped")
		}
		return nil

	},
}

var socketConnectVpnCmd = &cobra.Command{
	Use:               "vpn",
	Short:             "Connect a VPN socket (TLS under-the-hood)",
	ValidArgsFunction: AutocompleteSocket,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := logger.Logger

		if !util.RunningAsAdministrator() {
			return errors.New("command must be ran as system administrator in order to connect vpn sockets")
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		border0API := api.NewAPI(api.WithVersion(internal.Version))

		if socketID == "" && (len(args) == 0) {
			return fmt.Errorf("no socket provided")
		}
		if len(args) > 0 {
			socketID = args[0]
		}

		socket, err := border0.NewSocket(ctx, border0API, socketID, logger)
		if err != nil {
			return fmt.Errorf("failed to create socket %v", err)
		}

		if socket.Socket.ConnectorLocalData == nil {
			socket.Socket.ConnectorLocalData = &models.ConnectorLocalData{}
		}

		if socket.Socket.ConnectorData == nil {
			socket.Socket.ConnectorData = &models.ConnectorData{}
		}

		socket.WithVersion(internal.Version)

		if proxyHost != "" {
			if err := socket.WithProxy(proxyHost); err != nil {
				return fmt.Errorf("failed to set proxy host: %s", err)
			}
		}

		if socket.EndToEndEncryptionEnabled {
			certificate, err := util.GetEndToEndEncryptionCertificate(socket.Organization.ID, "")
			if err != nil {
				return fmt.Errorf("failed to get connector certificate: %s", err)
			}

			if certificate == nil {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return fmt.Errorf("failed to generate private key: %w", err)
				}

				csrTemplate := x509.CertificateRequest{
					Subject:            pkix.Name{CommonName: "border0"},
					SignatureAlgorithm: x509.PureEd25519,
				}

				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
				if err != nil {
					return fmt.Errorf("failed to create certificate request: %w", err)
				}

				csrPem := pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csrBytes,
				}

				var name string
				hostname, err := os.Hostname()
				if err != nil {
					name = "border0-cli"
				} else {
					name = hostname
				}

				cert, err := border0API.ServerOrgCertificate(ctx, name, pem.EncodeToMemory(&csrPem))
				if err != nil {
					return fmt.Errorf("failed to get certificate: %w", err)
				}

				privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
				if err != nil {
					return fmt.Errorf("failed to marshal private key: %w", err)
				}

				privKeyPem := &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: privKeyBytes,
				}

				tlsCert, err := tls.X509KeyPair(cert, pem.EncodeToMemory(privKeyPem))
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}

				certificate = &tlsCert

				if err := util.StoreConnectorCertifcate(pem.EncodeToMemory(privKeyPem), cert, orgID, ""); err != nil {
					logger.Warn("failed to store certificate", zap.Error(err))
				}
			}

			socket.WithCertificate(certificate)
		}

		SetRlimit()

		border0API.StartRefreshAccessTokenJob(ctx)

		l, err := socket.Listen()
		if err != nil {
			return fmt.Errorf("failed to listen for connections over socket: %v", err)
		}
		defer l.Close()

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)

		go func() {
			<-c
			fmt.Println("shutdown signal received")
			cancel()
		}()

		// blocks until context done
		return vpnlib.RunServer(ctx, logger, l, vpnSubnet, routes)
	},
}

var socketConnectCmd = &cobra.Command{
	Use:               "connect [socket]",
	Short:             "Connect a socket",
	ValidArgsFunction: AutocompleteSocket,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		border0API := api.NewAPI(api.WithVersion(internal.Version))

		if socketID == "" && (len(args) == 0) {
			return fmt.Errorf("error: no socket provided")
		}

		if len(args) > 0 {
			socketID = args[0]
		}

		socket, err := border0.NewSocket(ctx, border0API, socketID, logger.Logger)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		if socket.Socket.ConnectorLocalData == nil {
			socket.Socket.ConnectorLocalData = &models.ConnectorLocalData{}
		}

		if socket.Socket.ConnectorData == nil {
			socket.Socket.ConnectorData = &models.ConnectorData{}
		}

		socket.WithVersion(internal.Version)

		if proxyHost != "" {
			if err := socket.WithProxy(proxyHost); err != nil {
				log.Fatalf("error: %v", err)
			}
		}

		if socket.EndToEndEncryptionEnabled {
			certificate, err := util.GetEndToEndEncryptionCertificate(socket.Organization.ID, "")
			if err != nil {
				log.Printf("failed to get connector certificate: %s", err)
			}

			if certificate == nil {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return fmt.Errorf("failed to generate private key: %w", err)
				}

				csrTemplate := x509.CertificateRequest{
					Subject:            pkix.Name{CommonName: "border0"},
					SignatureAlgorithm: x509.PureEd25519,
				}

				csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
				if err != nil {
					return fmt.Errorf("failed to create certificate request: %w", err)
				}

				csrPem := pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csrBytes,
				}

				var name string
				hostname, err := os.Hostname()
				if err != nil {
					name = "border0-cli"
				} else {
					name = hostname
				}

				cert, err := border0API.ServerOrgCertificate(ctx, name, pem.EncodeToMemory(&csrPem))
				if err != nil {
					return fmt.Errorf("failed to get certificate: %w", err)
				}

				privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
				if err != nil {
					return fmt.Errorf("failed to marshal private key: %w", err)
				}

				privKeyPem := &pem.Block{
					Type:  "PRIVATE KEY",
					Bytes: privKeyBytes,
				}

				tlsCert, err := tls.X509KeyPair(cert, pem.EncodeToMemory(privKeyPem))
				if err != nil {
					return fmt.Errorf("failed to parse certificate: %w", err)
				}

				certificate = &tlsCert

				if err := util.StoreConnectorCertifcate(pem.EncodeToMemory(privKeyPem), cert, orgID, ""); err != nil {
					log.Printf("failed to store certificate: %s", err)
				}
			}

			socket.WithCertificate(certificate)
		}

		SetRlimit()

		if socket.SocketType != "http" && httpserver {
			return fmt.Errorf("can not use httpserver with non http socket type")
		}

		if socket.SocketType != "ssh" && localssh {
			return fmt.Errorf("can not use sshserver with non ssh socket type")
		}

		if localssh && socket.UpstreamType != "ssh" {
			return fmt.Errorf("can not use sshserver with non ssh upstream type")
		}

		if socket.SocketType == "database" && cloudSqlConnector {
			if cloudSqlInstance == "" {
				return fmt.Errorf("no cloudsql instance provided")
			}
		}

		if socket.SocketType == "database" && rdsIAM {
			if awsRegion == "" {
				return fmt.Errorf("no AWS region provided")
			}
		}

		var sqlAuthProxy bool
		var handlerConfig sqlauthproxy.Config
		if socket.SocketType == "database" && (upstream_username != "" || upstream_password != "" || rdsIAM || upstream_cert_file != "" || upstream_key_file != "" || socket.EndToEndEncryptionEnabled) {
			handlerConfig = sqlauthproxy.Config{
				Hostname:             hostname,
				Port:                 port,
				RdsIam:               rdsIAM,
				Username:             upstream_username,
				Password:             upstream_password,
				UpstreamType:         socket.UpstreamType,
				AwsRegion:            awsRegion,
				UpstreamCAFile:       upstream_ca_file,
				UpstreamCertFile:     upstream_cert_file,
				UpstreamKeyFile:      upstream_key_file,
				UpstreamTLS:          upstream_tls,
				Logger:               logger.Logger,
				E2eEncryptionEnabled: socket.EndToEndEncryptionEnabled,
				Socket:               *socket.Socket,
				Border0API:           border0API,
				AzureAD:              azureAD,
				Kerberos:             kerberos,
			}

			if cloudSqlConnector {
				dialer, err := cloudsql.NewDialer(ctx, cloudSqlInstance, cloudSqlCredentialsFile, nil, cloudSqlIAM)
				if err != nil {
					return fmt.Errorf("failed to create dialer for cloudSQL: %s", err)
				}

				handlerConfig.DialerFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
					return dialer.Dial(ctx, cloudSqlInstance)
				}
			}

			sqlAuthProxy = true
		}

		var sshAuthProxy bool
		var sshProxyConfig config.ProxyConfig

		if socket.SocketType == "ssh" && (upstream_username != "" || upstream_password != "" || upstream_identify_file != "" || awsEc2InstanceId != "" || socket.UpstreamType == "aws-ssm" || socket.UpstreamType == "aws-ec2connect" || awsEc2InstanceConnect || socket.EndToEndEncryptionEnabled) {
			sshProxyConfig = config.ProxyConfig{
				Logger:             logger.Logger,
				Recording:          socket.RecordingEnabled,
				EndToEndEncryption: socket.EndToEndEncryptionEnabled,
				Socket:             socket.Socket,
				Border0API:         border0API,
			}

			if socket.EndToEndEncryptionEnabled {
				hostkeySigner, err := util.Hostkey()
				if err != nil {
					if hostkeySigner == nil {
						return fmt.Errorf("failed to get hostkey: %s", err)
					} else {
						logger.Logger.Warn("failed to store hostkey", zap.Error(err))
					}
				}

				sshProxyConfig.Hostkey = hostkeySigner

				if orgSshCA, ok := socket.Organization.Certificates["ssh_public_key"]; ok {
					orgCa, _, _, _, err := gossh.ParseAuthorizedKey([]byte(orgSshCA))
					if err != nil {
						return fmt.Errorf("failed to parse org ssh ca: %s", err)
					}

					sshProxyConfig.OrgSshCA = orgCa
				}
			}

			switch {
			case socket.UpstreamType == "aws-ssm":
				if awsECSCluster == "" && awsEc2InstanceId == "" {
					return fmt.Errorf("aws_ecs_cluster flag or aws ec2 instance id is required for aws-ssm upstream services")
				}

				sshProxyConfig.AwsSSMTarget = awsEc2InstanceId
				sshProxyConfig.AWSRegion = awsRegion
				sshProxyConfig.AWSProfile = awsProfile
				sshProxyConfig.AwsUpstreamType = "aws-ssm"

				if awsECSCluster != "" {
					sshProxyConfig.ECSSSMProxy = &config.ECSSSMProxy{
						Cluster:    awsECSCluster,
						Services:   awsECSServices,
						Tasks:      awsECSTasks,
						Containers: awsECSContainers,
					}
				}
			case socket.UpstreamType == "aws-ec2connect" || awsEc2InstanceConnect:
				if awsEc2InstanceId == "" {
					return fmt.Errorf("aws ec2 instance id is required for EC2 Instance Connect based upstream services")
				}

				sshProxyConfig.AwsEC2InstanceId = awsEc2InstanceId
				sshProxyConfig.AWSRegion = awsRegion
				sshProxyConfig.AWSProfile = awsProfile
				sshProxyConfig.Hostname = hostname
				sshProxyConfig.Port = port
				sshProxyConfig.Username = upstream_username
				sshProxyConfig.AwsUpstreamType = "aws-ec2connect"

			default:
				if awsECSCluster != "" || awsEc2InstanceId != "" {
					return fmt.Errorf("aws_ecs_cluster flag or aws ec2 instance id is defined but socket is not configured with aws-ssm upstream type")
				}

				sshProxyConfig.Hostname = hostname
				sshProxyConfig.Port = port
				sshProxyConfig.Username = upstream_username
				sshProxyConfig.Password = upstream_password
				sshProxyConfig.IdentityFile = upstream_identify_file
			}

			if localssh {
				sshProxyConfig.Socket.SSHServer = true
			}
			sshAuthProxy = true
		}

		if socket.SocketType == "ssh" && !localssh && !sshAuthProxy {
			if port < 1 {
				port = 22
			}
		}

		if socket.SocketType != "database" && cloudSqlConnector {
			cloudSqlConnector = false
		}

		border0API.StartRefreshAccessTokenJob(ctx)

		l, err := socket.Listen()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		defer l.Close()

		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		go func() {
			for {
				<-c
				os.Exit(0)
			}
		}()

		switch {
		case httpserver:
			if err := http.StartLocalHTTPServer(httpserver_dir, l); err != nil {
				return err
			}
		case localssh && !socket.EndToEndEncryptionEnabled:
			opts := []server.Option{}
			if socket.UpstreamUsername != "" {
				opts = append(opts, server.WithUsername(socket.UpstreamUsername))
			}
			sshServer, err := server.NewServer(logger.Logger, socket.Organization.Certificates["ssh_public_key"], opts...)
			if err != nil {
				return err
			}

			if err := sshServer.Serve(l); err != nil {
				return err
			}
		case sqlAuthProxy:
			if err := sqlauthproxy.Serve(l, handlerConfig); err != nil {
				return err
			}
		case cloudSqlConnector:
			if err := cloudsql.Serve(l, cloudSqlInstance, cloudSqlCredentialsFile, nil, cloudSqlIAM); err != nil {
				return err
			}
		case sshAuthProxy:
			if err := ssh.Proxy(l, sshProxyConfig); err != nil {
				return err
			}
		default:
			if port < 1 {
				return fmt.Errorf("error: port not specified")
			}
			if err := border0.Serve(logger.Logger, l, hostname, port); err != nil {
				return err
			}
		}

		return nil
	},
}

func getSockets(toComplete string) []string {
	var socketIDs []string

	client, err := http.NewClient()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	sockets := []models.Socket{}
	err = client.Request("GET", "socket", &sockets, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	for _, s := range sockets {
		if strings.HasPrefix(s.SocketID, toComplete) {
			socketIDs = append(socketIDs, s.SocketID)
		}
	}

	return socketIDs
}

func AutocompleteSocket(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) != 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	var socketNames []string

	client, err := http.NewClient()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	sockets := []models.Socket{}
	err = client.Request("GET", "socket", &sockets, nil)
	if err != nil {
		log.Fatalf(fmt.Sprintf("Error: %v", err))
	}

	for _, s := range sockets {
		if strings.HasPrefix(s.Name, toComplete) {
			socketNames = append(socketNames, s.Name)
		}
	}

	return socketNames, cobra.ShellCompDirectiveNoFileComp
}

func init() {

	socketConnectProxyCmd.Flags().StringSliceVarP(&allowedProxyHosts, "allowed-host", "", []string{}, "Allowed host to proxy to, if ommited all proxy requests are allowed")
	socketConnectCmd.AddCommand(socketConnectProxyCmd)

	socketConnectVpnCmd.Flags().StringVarP(&vpnSubnet, "vpn-subnet", "", "10.42.0.0/22", "Ip range used to allocate to vpn clients")
	socketConnectVpnCmd.Flags().StringSliceVarP(&routes, "route", "", []string{}, "Routes to advertise to clients")
	socketConnectCmd.AddCommand(socketConnectVpnCmd)

	rootCmd.AddCommand(socketCmd)
	socketCmd.AddCommand(socketsListCmd)
	socketCmd.AddCommand(socketCreateCmd)
	socketCmd.AddCommand(socketDeleteCmd)
	socketCmd.AddCommand(socketShowCmd)
	socketCmd.AddCommand(socketConnectCmd)

	socketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	socketCreateCmd.Flags().StringVarP(&description, "description", "r", "", "Socket description")
	socketCreateCmd.Flags().StringVarP(&upstream_username, "upstream_username", "j", "", "Upstream username used to connect to upstream database")
	socketCreateCmd.Flags().StringVarP(&upstream_password, "upstream_password", "k", "", "Upstream password used to connect to upstream database")
	socketCreateCmd.Flags().StringVarP(&upstream_http_hostname, "upstream_http_hostname", "", "", "Upstream http hostname")
	socketCreateCmd.Flags().StringVarP(&upstream_type, "upstream_type", "", "", "Upstream type: http, https for http sockets or mysql, mssql, postgres for database sockets and aws-ssm for ssh sockets")
	socketCreateCmd.Flags().StringVarP(&socketType, "type", "t", "http", "Socket type: http, https, ssh, tls, database")
	socketCreateCmd.Flags().BoolVarP(&connectorAuthEnabled, "connector_auth", "c", false, "Enables connector authentication")
	socketCreateCmd.Flags().StringVarP(&orgCustomDomain, "domain", "o", "", "Use custom domain for socket")
	socketCreateCmd.Flags().StringVarP(&upstream_cert_file, "upstream_certificate_filename", "f", "", "path to file from where to read the upstream client certificate")
	socketCreateCmd.Flags().StringVarP(&upstream_key_file, "upstream_key_filename", "y", "", "path to file from where to read the upstream client key")
	socketCreateCmd.Flags().StringVarP(&upstream_ca_file, "upstream_ca_filename", "a", "", "path to file from where to read the upstream ca certificate")

	socketCreateCmd.MarkFlagRequired("name")

	socketDeleteCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	socketDeleteCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	socketShowCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	socketShowCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	var policyCmd = &cobra.Command{
		Use:   "policy",
		Short: "Manage your global Policies",
	}

	var policyShowCmd = &cobra.Command{
		Use:   "show",
		Short: "Show a policy",
		Run:   policyShow,
	}

	policyShowCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	policyShowCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")

	var policyAttachCmd = &cobra.Command{
		Use:   "attach",
		Short: "Attach a policy",
		Run:   policyAttach,
	}

	policyAttachCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	policyAttachCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")

	var policyDettachCmd = &cobra.Command{
		Use:   "detach",
		Short: "Detach a policy",
		Run:   policyDettach,
	}

	policyDettachCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	policyDettachCmd.Flags().StringVarP(&policyName, "name", "n", "", "Policy Name")

	var policysListCmd = &cobra.Command{
		Use:   "ls",
		Short: "List your Policies",
		Run:   policysList,
	}

	policysListCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")

	policyCmd.AddCommand(policysListCmd)
	policyCmd.AddCommand(policyAttachCmd)
	policyCmd.AddCommand(policyDettachCmd)
	policyCmd.AddCommand(policyShowCmd)

	socketCmd.AddCommand(policyCmd)

	socketConnectCmd.Flags().StringVarP(&socketID, "socket_id", "s", "", "Socket ID")
	socketConnectCmd.Flags().StringVarP(&identityFile, "identity_file", "i", "", "Identity File")
	socketConnectCmd.Flags().IntVarP(&port, "port", "p", 0, "Port number")
	socketConnectCmd.Flags().StringVarP(&hostname, "host", "", "127.0.0.1", "Target host: Control where inbound traffic goes. Default localhost")
	socketConnectCmd.Flags().StringVarP(&proxyHost, "proxy", "", "", "Proxy host used for connection to border0.com")
	socketConnectCmd.Flags().BoolVarP(&localssh, "localssh", "", false, "Start a local SSH server to accept SSH sessions on this host")
	socketConnectCmd.Flags().BoolVarP(&localssh, "sshserver", "l", false, "Start a local SSH server to accept SSH sessions on this host")
	socketConnectCmd.Flags().MarkDeprecated("localssh", "use --sshserver instead")
	socketConnectCmd.Flags().BoolVarP(&httpserver, "httpserver", "", false, "Start a local http server to accept http connections on this host")
	socketConnectCmd.Flags().StringVarP(&httpserver_dir, "httpserver_dir", "", "", "Directory to serve http connections on this host")
	socketConnectCmd.Flags().StringVarP(&cloudSqlCredentialsFile, "cloudsql-credentials-file", "", "", "Use service account key file as a source of IAM credentials")
	socketConnectCmd.Flags().StringVarP(&cloudSqlInstance, "cloudsql-instance", "", "", "Google Cloud SQL instance")
	socketConnectCmd.Flags().BoolVarP(&cloudSqlIAM, "cloudsql-with-iam", "", false, "Use automatic IAM authentication for Google Cloud SQL instance")
	socketConnectCmd.Flags().BoolVarP(&cloudSqlConnector, "cloudsql-connector", "", false, "Use Google Cloud SQL connector")
	socketConnectCmd.Flags().BoolVarP(&rdsIAM, "rds-with-iam", "", false, "Use IAM authentication for AWS RDS instance")
	socketConnectCmd.Flags().StringVarP(&awsRegion, "aws-region", "", "", "AWS region for RDS instance")
	socketConnectCmd.Flags().StringVarP(&upstream_username, "upstream_username", "", "", "Upstream username")
	socketConnectCmd.Flags().StringVarP(&upstream_password, "upstream_password", "", "", "Upstream password")
	socketConnectCmd.Flags().StringVarP(&upstream_cert_file, "upstream_certificate_filename", "f", "", "path to file from where to read the upstream client certificate")
	socketConnectCmd.Flags().StringVarP(&upstream_key_file, "upstream_key_filename", "y", "", "path to file from where to read the upstream client key")
	socketConnectCmd.Flags().StringVarP(&upstream_ca_file, "upstream_ca_filename", "a", "", "path to file from where to read the upstream ca certificate")
	socketConnectCmd.Flags().BoolVarP(&upstream_tls, "upstream_tls", "", true, "Use TLS for upstream connection")
	socketConnectCmd.Flags().StringVarP(&upstream_identify_file, "upstream_identity_file", "", "", "Upstream identity file")
	socketConnectCmd.Flags().StringVarP(&awsEc2InstanceId, "aws_ec2_target", "", "", "Aws EC2 target identifier") // kept for backwards compatibility
	socketConnectCmd.Flags().StringVarP(&awsEc2InstanceId, "aws-ec2-instance-id", "", "", "Instance id of the target AWS EC2 Instance")
	socketConnectCmd.Flags().BoolVarP(&awsEc2InstanceConnect, "aws-ec2-instance-connect", "", false, "Use AWS EC2 Instance Connect to connect to the target")
	socketConnectCmd.Flags().StringVarP(&awsRegion, "region", "", "", "AWS region to use")
	socketConnectCmd.Flags().StringVarP(&awsProfile, "profile", "", "", "AWS profile to use")
	socketConnectCmd.Flags().StringVarP(&awsECSCluster, "aws_ecs_cluster", "", "", "The aws cluster to connect to, Required if upstream type is asw-ssm")
	socketConnectCmd.Flags().StringSliceVarP(&awsECSServices, "aws_ecs_service", "", []string{}, "If specified, the list will only show service that has the specified service names")
	socketConnectCmd.Flags().StringSliceVarP(&awsECSTasks, "aws_ecs_task", "", []string{}, "If specified, the list will only show tasks that starts with the specified task names")
	socketConnectCmd.Flags().StringSliceVarP(&awsECSContainers, "aws_ecs_container", "", []string{}, "If specified, the list will only show containers that has the specified container names")
	socketConnectCmd.Flags().BoolVarP(&azureAD, "azure_ad", "", false, "Use Azure Active Directory authentication")
	socketConnectCmd.Flags().BoolVarP(&kerberos, "kerberos", "", false, "Use Kerberos authentication")

	socketConnectCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	socketConnectCmd.Flags().MarkDeprecated("identity_file", "identity file is no longer used")
}
