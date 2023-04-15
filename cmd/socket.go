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
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/borderzero/border0-cli/internal/api"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/cloudsql"
	"github.com/borderzero/border0-cli/internal/http"
	"github.com/borderzero/border0-cli/internal/sqlauthproxy"
	"github.com/borderzero/border0-cli/internal/ssh"
	"github.com/borderzero/border0-cli/internal/util"
	"github.com/jedib0t/go-pretty/table"
	"github.com/spf13/cobra"
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
			if upstreamType != "mysql" && upstreamType != "postgres" && upstreamType != "" {
				log.Fatalf("error: --upstream_type should be mysql or postgres, defaults to mysql")
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
			UpstreamHttpHostname:           upstream_http_hostname,
			UpstreamType:                   upstreamType,
			CloudAuthEnabled:               true,
			ConnectorAuthenticationEnabled: connectorAuthEnabled,
			OrgCustomDomain:                orgCustomDomain,
			UpstreamCert:                   upstream_cert,
			UpstreamKey:                    upstream_key,
			UpstreamCa:                     upstream_ca,
		}
		err = client.WithVersion(version).Request("POST", "socket", &s, newSocket)
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

var socketConnectCmd = &cobra.Command{
	Use:               "connect [socket]",
	Short:             "Connect a socket",
	ValidArgsFunction: AutocompleteSocket,
	RunE: func(cmd *cobra.Command, args []string) error {
		if socketID == "" && (len(args) == 0) {
			return fmt.Errorf("error: no socket provided")
		}

		if len(args) > 0 {
			socketID = args[0]
		}

		socket, err := border0.NewSocket(context.Background(), api.NewAPI(api.WithVersion(version)), socketID)
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		socket.WithVersion(version)

		if proxyHost != "" {
			if err := socket.WithProxy(proxyHost); err != nil {
				log.Fatalf("error: %v", err)
			}
		}

		SetRlimit()

		if socket.SocketType != "http" && httpserver {
			httpserver = false
		}

		if socket.SocketType != "ssh" && localssh {
			localssh = false
		}

		if socket.SocketType == "database" && cloudSqlConnector {
			if cloudSqlInstance == "" {
				return fmt.Errorf("error: no cloudsql instance provided")
			}
		}

		if socket.SocketType == "database" && rdsIAM {
			if awsRegion == "" {
				return fmt.Errorf("error: no AWS region provided")
			}
		}

		var sqlAuthProxy bool
		var handlerConfig sqlauthproxy.Config
		if socket.SocketType == "database" && (upstream_username != "" || upstream_password != "" || rdsIAM || upstream_cert_file != "" || upstream_key_file != "") {
			handlerConfig = sqlauthproxy.Config{
				Hostname:         hostname,
				Port:             port,
				RdsIam:           rdsIAM,
				Username:         upstream_username,
				Password:         upstream_password,
				UpstreamType:     socket.UpstreamType,
				AwsRegion:        awsRegion,
				UpstreamCAFile:   upstream_ca_file,
				UpstreamCertFile: upstream_cert_file,
				UpstreamKeyFile:  upstream_key_file,
				UpstreamTLS:      upstream_tls,
			}

			if cloudSqlConnector {
				ctx := context.Background()
				dialer, err := cloudsql.NewDialer(ctx, cloudSqlInstance, cloudSqlCredentialsFile, cloudSqlIAM)
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
		var sshProxyConfig ssh.ProxyConfig
		if socket.SocketType == "ssh" && (upstream_username != "" || upstream_password != "" || upstream_identify_file != "" || awsEC2Target != "") {
			sshProxyConfig = ssh.ProxyConfig{
				Hostname:     hostname,
				Port:         port,
				Username:     upstream_username,
				Password:     upstream_password,
				IdentityFile: upstream_identify_file,
				AwsEC2Target: awsEC2Target,
			}
			sshAuthProxy = true
		}

		if socket.SocketType != "database" && cloudSqlConnector {
			cloudSqlConnector = false
		}

		if socket.SocketType == "ssh" && !localssh && !sshAuthProxy {
			if port < 1 {
				port = 22
			}
		}

		l, err := socket.Listen()
		if err != nil {
			log.Fatalf("error: %v", err)
		}

		defer l.Close()

		switch {
		case httpserver:
			if err := http.StartLocalHTTPServer(httpserver_dir, l); err != nil {
				return err
			}
		case localssh:
			sshServer := ssh.NewServer(socket.Organization.Certificates["ssh_public_key"])
			if err := sshServer.Serve(l); err != nil {
				return err
			}
		case sqlAuthProxy:
			if err := sqlauthproxy.Serve(l, handlerConfig); err != nil {
				return err
			}
		case cloudSqlConnector:
			if err := cloudsql.Serve(l, cloudSqlInstance, cloudSqlCredentialsFile, cloudSqlIAM); err != nil {
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
			if err := border0.Serve(l, hostname, port); err != nil {
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
	socketCreateCmd.Flags().StringVarP(&upstream_type, "upstream_type", "", "", "Upstream type: http, https for http sockets or mysql, postgres for database sockets")
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
	socketConnectCmd.Flags().StringVarP(&awsEC2Target, "aws_ec2_target", "", "", "Aws EC2 target identifier")

	socketConnectCmd.RegisterFlagCompletionFunc("socket_id", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getSockets(toComplete), cobra.ShellCompDirectiveNoFileComp
	})

	socketConnectCmd.Flags().MarkDeprecated("identity_file", "identity file is no longer used")
}
