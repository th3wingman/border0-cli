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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"slices"
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
	"github.com/borderzero/border0-go/client"
	"github.com/borderzero/border0-go/types/common"
	"github.com/borderzero/border0-go/types/service"
	"github.com/google/uuid"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	sdk "github.com/borderzero/border0-go"

	gossh "golang.org/x/crypto/ssh"
)

// socketCmd represents the socket command
var socketCmd = &cobra.Command{
	Use:   "socket",
	Short: "Manage your sockets",
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
		fmt.Println("Deprecated: Use 'socket create <http|ssh|database|tls|vpn|rdp|vnc|kubernetes>' instead")

		if name == "" {
			log.Fatalf("error: empty name not allowed")
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

// httpSocketCreateCmd represents the socket create command for http sockets
var httpSocketCreateCmd = &cobra.Command{
	Use:   "http",
	Short: "Create a new http socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		if strings.ToLower(upstream_type) != "http" && strings.ToLower(upstream_type) != "https" {
			log.Fatalf("error: --upstream_type should be either http, https")
		}

		if http_hostname == "" {
			http_hostname = host
		}

		token, err := http.GetToken()
		if err != nil {
			return err
		}

		api := sdk.NewAPIClient(
			client.WithAuthToken(token),
		)

		if connector != "" {
			// if connector is not a uuid, tranlate it to a uuid
			if _, err := uuid.Parse(connector); err != nil {
				var connectorUUID string
				connectors, err := api.Connectors(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to get connector UUID: %w", err)
				}

				for _, c := range connectors.List {
					if c.Name == connector {
						connectorUUID = c.ConnectorID
						break
					}
				}

				if connectorUUID == "" {
					return fmt.Errorf("connector not found")
				}

				connector = connectorUUID
			}
		}

		// create socket
		socket := client.Socket{
			Name:                 name,
			SocketType:           "http",
			Description:          description,
			UpstreamType:         strings.ToLower(upstream_type),
			UpstreamHTTPHostname: http_hostname,
			RecordingEnabled:     recordingEnabled,
			Tags:                 tags,
			ConnectorID:          connector,
			UpstreamConfig: &service.Configuration{
				ServiceType: "http",
				HttpServiceConfiguration: &service.HttpServiceConfiguration{
					HttpServiceType: "standard",
					StandardHttpServiceConfiguration: &service.StandardHttpServiceConfiguration{
						HostnameAndPort: service.HostnameAndPort{
							Hostname: host,
							Port:     uint16(port),
						},
						HostHeader: http_hostname,
					},
				},
			},
		}

		if err := socket.UpstreamConfig.Validate(); err != nil {
			return err
		}

		if jsonInput {
			fmt.Println("Socket create request JSON:")
			if err := prettyPrintJSON(socket); err != nil {
				return err
			}
		}

		created, err := api.CreateSocket(cmd.Context(), &socket)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		if jsonOutput {
			return prettyPrintJSON(created)
		}

		var orgPolicies []client.Policy
		policies, _ := api.Policies(cmd.Context())
		for _, p := range policies {
			if p.OrgWide {
				orgPolicies = append(orgPolicies, p)
			}
		}

		connectors, _ := api.SocketConnectors(cmd.Context(), created.SocketID)

		fmt.Print(print_sdk_socket(created, orgPolicies, connectors))
		return nil
	},
}

// sshSocketCreateCmd represents the socket create command for ssh sockets
var sshSocketCreateCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Create a new ssh socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := http.GetToken()
		if err != nil {
			return err
		}

		api := sdk.NewAPIClient(
			client.WithAuthToken(token),
		)

		if connector != "" {
			// if connector is not a uuid, tranlate it to a uuid
			if _, err := uuid.Parse(connector); err != nil {
				var connectorUUID string
				connectors, err := api.Connectors(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to get connector UUID: %w", err)
				}

				for _, c := range connectors.List {
					if c.Name == connector {
						connectorUUID = c.ConnectorID
						break
					}
				}

				if connectorUUID == "" {
					return fmt.Errorf("connector not found")
				}

				connector = connectorUUID
			}
		}

		socket := client.Socket{
			Name:             name,
			SocketType:       "ssh",
			Description:      description,
			RecordingEnabled: recordingEnabled,
			Tags:             tags,
			ConnectorID:      connector,
			UpstreamConfig: &service.Configuration{
				ServiceType: "ssh",
			},
		}

		switch upstream_type {
		case "standard":
			if host == "" {
				return fmt.Errorf("error: --host is required")
			}

			if sshPort == 0 {
				return fmt.Errorf("error: --port is required")
			}

			switch authType {
			case "username_and_password":
				if username == "" {
					return fmt.Errorf("error: --username is required when --auth_type is username_and_password")
				}

				if password == "" {
					return fmt.Errorf("error: --password is required when --auth_type is username_and_password")
				}

				socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
					SshServiceType: "standard",
					StandardSshServiceConfiguration: &service.StandardSshServiceConfiguration{
						SshAuthenticationType: "username_and_password",
						HostnameAndPort: service.HostnameAndPort{
							Hostname: host,
							Port:     sshPort,
						},
						UsernameAndPasswordAuthConfiguration: &service.UsernameAndPasswordAuthConfiguration{
							Username:         username,
							Password:         password,
							UsernameProvider: "defined",
						},
					},
				}
			case "private_key":
				if username == "" {
					return fmt.Errorf("error: --username is required when --auth_type is username_and_password")
				}

				if sshKey == "" {
					return fmt.Errorf("error: --ssh_key is required when --auth_type is private_key")
				}

				socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
					SshServiceType: "standard",
					StandardSshServiceConfiguration: &service.StandardSshServiceConfiguration{
						SshAuthenticationType: "private_key",
						HostnameAndPort: service.HostnameAndPort{
							Hostname: host,
							Port:     sshPort,
						},
						PrivateKeyAuthConfiguration: &service.PrivateKeyAuthConfiguration{
							PrivateKey:       sshKey,
							Username:         username,
							UsernameProvider: "defined",
						},
					},
				}
			case "border0_certificate":
				switch usernameType {
				case "defined":
					if username == "" {
						return fmt.Errorf("error: --username is required when --username_type is defined")
					}
				case "prompt_client":
				default:
					return fmt.Errorf("error: --username_type should be prompt_client or defined")
				}

				socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
					SshServiceType: "standard",
					StandardSshServiceConfiguration: &service.StandardSshServiceConfiguration{
						SshAuthenticationType: "border0_certificate",
						HostnameAndPort: service.HostnameAndPort{
							Hostname: host,
							Port:     sshPort,
						},
						Border0CertificateAuthConfiguration: &service.Border0CertificateAuthConfiguration{
							Username:         username,
							UsernameProvider: usernameType,
						},
					},
				}
			default:
				return fmt.Errorf("error: --auth_type should be username_and_password, private_key or border0_certificate")
			}
		case "aws_ssm":
			switch ssmTargetType {
			case "ecs":
				if awsECSRegion == "" {
					return fmt.Errorf("error: --ecs_region is required for aws_ssm ecs")
				}

				if awsECSCluster == "" {
					return fmt.Errorf("error: --ecs_cluster is required for aws_ssm ecs")
				}

				if awsECSService == "" {
					return fmt.Errorf("error: --ecs_service is required for aws_ssm ecs")
				}

				socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
					SshServiceType: "aws_ssm",
					AwsSsmSshServiceConfiguration: &service.AwsSsmSshServiceConfiguration{
						SsmTargetType: "ecs",
						AwsSsmEcsTargetConfiguration: &service.AwsSsmEcsTargetConfiguration{
							EcsClusterRegion: awsECSRegion,
							EcsClusterName:   awsECSCluster,
							EcsServiceName:   awsECSService,
							AwsCredentials:   &common.AwsCredentials{},
						},
					},
				}

				if awsAccessKeyId != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEcsTargetConfiguration.AwsCredentials.AwsAccessKeyId = &awsAccessKeyId
				}
				if awsSecretAccessKey != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEcsTargetConfiguration.AwsCredentials.AwsSecretAccessKey = &awsSecretAccessKey
				}
				if awsSessionToken != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEcsTargetConfiguration.AwsCredentials.AwsSessionToken = &awsSessionToken
				}
				if awsProfile != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEcsTargetConfiguration.AwsCredentials.AwsProfile = &awsProfile
				}
			case "ec2":
				if awsEC2InstanceID == "" {
					return fmt.Errorf("error: --ec2_instance_id is required for aws_ssm ec2")
				}

				if awsEC2Region == "" {
					return fmt.Errorf("error: --ec2_region is required for aws_ssm ec2")
				}

				socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
					SshServiceType: "aws_ssm",
					AwsSsmSshServiceConfiguration: &service.AwsSsmSshServiceConfiguration{
						SsmTargetType: "ec2",
						AwsSsmEc2TargetConfiguration: &service.AwsSsmEc2TargetConfiguration{
							Ec2InstanceId:     awsEC2InstanceID,
							Ec2InstanceRegion: awsEC2Region,
							AwsCredentials:    &common.AwsCredentials{},
						},
					},
				}

				if awsAccessKeyId != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEc2TargetConfiguration.AwsCredentials.AwsAccessKeyId = &awsAccessKeyId
				}
				if awsSecretAccessKey != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEc2TargetConfiguration.AwsCredentials.AwsSecretAccessKey = &awsSecretAccessKey
				}
				if awsSessionToken != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEc2TargetConfiguration.AwsCredentials.AwsSessionToken = &awsSessionToken
				}
				if awsProfile != "" {
					socket.UpstreamConfig.SshServiceConfiguration.AwsSsmSshServiceConfiguration.AwsSsmEc2TargetConfiguration.AwsCredentials.AwsProfile = &awsProfile
				}
			default:
				return fmt.Errorf("error: --ssm_target_type should be ecs or ec2")
			}
		case "aws_ec2_instance_connect":
			if host == "" {
				return fmt.Errorf("error: --host is required for aws_ec2_instance_connect")
			}

			if port == 0 {
				return fmt.Errorf("error: --port is required for aws_ec2_instance_connect")
			}

			if awsEC2InstanceID == "" {
				return fmt.Errorf("error: --aws_ec2_instance_id is required for aws_ec2_instance_connect")
			}

			if awsEC2Region == "" {
				return fmt.Errorf("error: --aws_ec2_region is required for aws_ec2_instance_connect")
			}

			switch usernameType {
			case "defined":
				if username == "" {
					return fmt.Errorf("error: --username is required when --username_type is defined")
				}
			case "prompt_client":
			default:
				return fmt.Errorf("error: --username_type should be prompt_client or defined")
			}

			socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
				SshServiceType: "aws_ec2_instance_connect",
				AwsEc2ICSshServiceConfiguration: &service.AwsEc2ICSshServiceConfiguration{
					HostnameAndPort: service.HostnameAndPort{
						Hostname: host,
						Port:     sshPort,
					},
					UsernameProvider:  usernameType,
					Username:          username,
					Ec2InstanceId:     awsEC2InstanceID,
					Ec2InstanceRegion: awsEC2Region,
					AwsCredentials:    &common.AwsCredentials{},
				},
			}

			if awsAccessKeyId != "" {
				socket.UpstreamConfig.SshServiceConfiguration.AwsEc2ICSshServiceConfiguration.AwsCredentials.AwsAccessKeyId = &awsAccessKeyId
			}
			if awsSecretAccessKey != "" {
				socket.UpstreamConfig.SshServiceConfiguration.AwsEc2ICSshServiceConfiguration.AwsCredentials.AwsSecretAccessKey = &awsSecretAccessKey
			}
			if awsSessionToken != "" {
				socket.UpstreamConfig.SshServiceConfiguration.AwsEc2ICSshServiceConfiguration.AwsCredentials.AwsSessionToken = &awsSessionToken
			}
			if awsProfile != "" {
				socket.UpstreamConfig.SshServiceConfiguration.AwsEc2ICSshServiceConfiguration.AwsCredentials.AwsProfile = &awsProfile
			}
		case "connector_built_in_ssh_service":
			switch usernameType {
			case "defined":
				if username == "" {
					return fmt.Errorf("error: --username is required when --username_type is defined")
				}
			case "prompt_client", "use_connector_user":
			default:
				return fmt.Errorf("error: --username_type should be use_connector_user, prompt_client or defined")
			}

			socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
				SshServiceType: "connector_built_in_ssh_service",
				BuiltInSshServiceConfiguration: &service.BuiltInSshServiceConfiguration{
					Username:         username,
					UsernameProvider: usernameType,
				},
			}
		case "docker_exec":
			socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
				SshServiceType:                    "docker_exec",
				DockerExecSshServiceConfiguration: &service.DockerExecSshServiceConfiguration{},
			}

			if len(allowedDockerContainers) > 0 {
				socket.UpstreamConfig.SshServiceConfiguration.DockerExecSshServiceConfiguration.ContainerNameAllowlist = allowedDockerContainers
			}
		case "kubectl_exec":
			socket.UpstreamConfig.SshServiceConfiguration = &service.SshServiceConfiguration{
				SshServiceType: "kubectl_exec",
			}

			namespaceSelectorsAllowMap := make(map[string]map[string][]string)
			if namespaceSelectorsAllowlist != "" {
				// Parse namespace selectors allowlist
				err := json.Unmarshal([]byte(namespaceSelectorsAllowlist), &namespaceSelectorsAllowMap)
				if err != nil {
					return fmt.Errorf("invalid namespace_selectors_allowlist: %v", err)
				}
			}

			switch kubectlExecType {
			case "standard":
				socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration = &service.KubectlExecSshServiceConfiguration{
					KubectlExecTargetType:              "standard",
					BaseKubectlExecTargetConfiguration: service.BaseKubectlExecTargetConfiguration{},
					StandardKubectlExecTargetConfiguration: &service.StandardKubectlExecTargetConfiguration{
						MasterUrl:      kubectlExecMasterUrl,
						KubeconfigPath: kubectlExecKubeConfigPath,
					},
				}
				if len(allowedNamespaces) > 0 {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.BaseKubectlExecTargetConfiguration.NamespaceAllowlist = allowedNamespaces
				}

				if namespaceSelectorsAllowlist != "" {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.BaseKubectlExecTargetConfiguration.NamespaceSelectorsAllowlist = namespaceSelectorsAllowMap
				}
			case "aws-eks":
				if awsEKSCluster == "" || awsEKSRegion == "" {
					return fmt.Errorf("error: --eks_cluster and --eks_region are required for aws-eks kubectl exec")
				}

				socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration = &service.KubectlExecSshServiceConfiguration{
					KubectlExecTargetType:              "aws_eks",
					BaseKubectlExecTargetConfiguration: service.BaseKubectlExecTargetConfiguration{},
					AwsEksKubectlExecTargetConfiguration: &service.AwsEksKubectlExecTargetConfiguration{
						EksClusterName:   awsEKSCluster,
						EksClusterRegion: awsEKSRegion,
						AwsCredentials:   &common.AwsCredentials{},
					},
				}

				if awsAccessKeyId != "" {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.AwsEksKubectlExecTargetConfiguration.AwsCredentials.AwsAccessKeyId = &awsAccessKeyId
				}
				if awsSecretAccessKey != "" {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.AwsEksKubectlExecTargetConfiguration.AwsCredentials.AwsSecretAccessKey = &awsSecretAccessKey
				}
				if awsSessionToken != "" {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.AwsEksKubectlExecTargetConfiguration.AwsCredentials.AwsSessionToken = &awsSessionToken
				}
				if awsProfile != "" {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.AwsEksKubectlExecTargetConfiguration.AwsCredentials.AwsProfile = &awsProfile
				}

				if len(allowedNamespaces) > 0 {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.BaseKubectlExecTargetConfiguration.NamespaceAllowlist = allowedNamespaces
				}

				if namespaceSelectorsAllowlist != "" {
					socket.UpstreamConfig.SshServiceConfiguration.KubectlExecSshServiceConfiguration.BaseKubectlExecTargetConfiguration.NamespaceSelectorsAllowlist = namespaceSelectorsAllowMap
				}
			default:
				return fmt.Errorf("error: --kubectl_exec_type should be standard or aws-eks")
			}
		default:
			return fmt.Errorf("error: --upstream_type should be standard, aws_ssm, aws_ec2_instance_connect, connector_built_in_ssh_service, docker_exec or kubectl_exec")
		}

		if err := socket.UpstreamConfig.Validate(); err != nil {
			return err
		}

		if jsonInput {
			fmt.Println("Socket create request JSON:")
			if err := prettyPrintJSON(socket); err != nil {
				return err
			}
		}

		created, err := api.CreateSocket(cmd.Context(), &socket)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		if jsonOutput {
			return prettyPrintJSON(created)
		}

		var orgPolicies []client.Policy
		policies, _ := api.Policies(cmd.Context())
		for _, p := range policies {
			if p.OrgWide {
				orgPolicies = append(orgPolicies, p)
			}
		}

		connectors, _ := api.SocketConnectors(cmd.Context(), created.SocketID)

		fmt.Print(print_sdk_socket(created, orgPolicies, connectors))
		return nil
	},
}

// databaseSocketCreateCmd represents the socket create command for database sockets
var databaseSocketCreateCmd = &cobra.Command{
	Use:   "database",
	Short: "Create a new database socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := http.GetToken()
		if err != nil {
			return err
		}

		api := sdk.NewAPIClient(
			client.WithAuthToken(token),
		)

		if connector != "" {
			// if connector is not a uuid, tranlate it to a uuid
			if _, err := uuid.Parse(connector); err != nil {
				var connectorUUID string
				connectors, err := api.Connectors(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to get connector UUID: %w", err)
				}

				for _, c := range connectors.List {
					if c.Name == connector {
						connectorUUID = c.ConnectorID
						break
					}
				}

				if connectorUUID == "" {
					return fmt.Errorf("connector not found")
				}

				connector = connectorUUID
			}
		}

		socket := client.Socket{
			Name:             name,
			SocketType:       "database",
			Description:      description,
			RecordingEnabled: recordingEnabled,
			Tags:             tags,
			ConnectorID:      connector,
			UpstreamConfig: &service.Configuration{
				ServiceType: "database",
			},
		}

		if !slices.Contains([]string{"mysql", "postgres", "mssql"}, upstream_type) {
			return fmt.Errorf("error: --upstream_type should be mysql, postgres or mssql")
		}

		var hostnameAndPort service.HostnameAndPort
		socket.UpstreamConfig.DatabaseServiceConfiguration = &service.DatabaseServiceConfiguration{}
		if !slices.Contains([]string{"cloudsql_connector", "cloudsql_connector_iam"}, authType) {
			if host == "" {
				return fmt.Errorf("error: --host is required")
			}

			if port == 0 {
				switch upstream_type {
				case "mysql":
					port = 3306
				case "postgres":
					port = 5432
				case "mssql":
					port = 1433
				}
			}

			hostnameAndPort = service.HostnameAndPort{
				Hostname: host,
				Port:     uint16(port),
			}
		}

		switch {
		case authType == "username_and_password" && slices.Contains([]string{"mysql", "postgres"}, upstream_type):
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if password == "" {
				return fmt.Errorf("error: --password is required")
			}

			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "standard"
			socket.UpstreamConfig.DatabaseServiceConfiguration.Standard = &service.StandardDatabaseServiceConfiguration{
				HostnameAndPort:    hostnameAndPort,
				DatabaseProtocol:   upstream_type,
				AuthenticationType: "username_and_password",
				UsernameAndPasswordAuth: &service.DatabaseUsernameAndPasswordAuthConfiguration{
					UsernameAndPassword: service.UsernameAndPassword{
						Username: username,
						Password: password,
					},
				},
			}
		case authType == "tls" && slices.Contains([]string{"mysql", "postgres"}, upstream_type):
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if password == "" {
				return fmt.Errorf("error: --password is required")
			}

			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "standard"
			socket.UpstreamConfig.DatabaseServiceConfiguration.Standard = &service.StandardDatabaseServiceConfiguration{
				HostnameAndPort:    hostnameAndPort,
				DatabaseProtocol:   upstream_type,
				AuthenticationType: "tls",
				TlsAuth: &service.DatabaseTlsAuthConfiguration{
					UsernameAndPassword: service.UsernameAndPassword{
						Username: username,
						Password: password,
					},
					TlsConfig: service.TlsConfig{
						CaCertificate: caCertificate,
						Certificate:   clientCertificate,
						Key:           clientKey,
					},
				},
			}
		case authType == "aws_iam" && slices.Contains([]string{"mysql", "postgres"}, upstream_type):
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if awsRdsRegion == "" {
				return fmt.Errorf("error: --rds_region is required")
			}

			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "aws_rds"
			socket.UpstreamConfig.DatabaseServiceConfiguration.AwsRds = &service.AwsRdsDatabaseServiceConfiguration{
				HostnameAndPort:  hostnameAndPort,
				DatabaseProtocol: upstream_type,
				IamAuth: &service.AwsRdsIamAuthConfiguration{
					Username:          username,
					RdsInstanceRegion: awsRdsRegion,
				},
			}

			if awsAccessKeyId != "" {
				socket.UpstreamConfig.DatabaseServiceConfiguration.AwsRds.IamAuth.AwsCredentials.AwsAccessKeyId = &awsAccessKeyId
			}
			if awsSecretAccessKey != "" {
				socket.UpstreamConfig.DatabaseServiceConfiguration.AwsRds.IamAuth.AwsCredentials.AwsSecretAccessKey = &awsSecretAccessKey
			}
			if awsSessionToken != "" {
				socket.UpstreamConfig.DatabaseServiceConfiguration.AwsRds.IamAuth.AwsCredentials.AwsSessionToken = &awsSessionToken
			}
			if awsProfile != "" {
				socket.UpstreamConfig.DatabaseServiceConfiguration.AwsRds.IamAuth.AwsCredentials.AwsProfile = &awsProfile
			}

			if caCertificate != "" {
				socket.UpstreamConfig.DatabaseServiceConfiguration.AwsRds.IamAuth.CaCertificate = caCertificate
			}

		case authType == "cloudsql_connector" && slices.Contains([]string{"mysql", "postgres", "mssql"}, upstream_type):
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if password == "" {
				return fmt.Errorf("error: --password is required")
			}

			if gcpCloudSQLInstanceID == "" {
				return fmt.Errorf("error: --cloudsql_instance_id is required")
			}

			if gcpCredentialsJson == "" {
				return fmt.Errorf("error: --gcp_credentials_json is required")
			}

			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "gcp_cloudsql"
			socket.UpstreamConfig.DatabaseServiceConfiguration.GcpCloudSql = &service.GcpCloudSqlDatabaseServiceConfiguration{
				DatabaseProtocol: upstream_type,
				GcpCloudSQLConnectorAuth: &service.GcpCloudSqlConnectorAuthConfiguration{
					Username:           username,
					Password:           password,
					InstanceId:         gcpCloudSQLInstanceID,
					GcpCredentialsJson: gcpCredentialsJson,
				},
			}
		case authType == "cloudsql_connector_iam" && slices.Contains([]string{"mysql", "postgres"}, upstream_type):
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if gcpCloudSQLInstanceID == "" {
				return fmt.Errorf("error: --cloudsql_instance_id is required")
			}

			if gcpCredentialsJson == "" {
				return fmt.Errorf("error: --gcp_credentials_json is required")
			}
			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "gcp_cloudsql"
			socket.UpstreamConfig.DatabaseServiceConfiguration.GcpCloudSql = &service.GcpCloudSqlDatabaseServiceConfiguration{
				DatabaseProtocol: upstream_type,
				GcpCloudSQLConnectorIAMAuth: &service.GcpCloudSqlConnectorIamAuthConfiguration{
					Username:           username,
					InstanceId:         gcpCloudSQLInstanceID,
					GcpCredentialsJson: gcpCredentialsJson,
				},
			}
		case authType == "sql_authentication" && upstream_type == "mssql":
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if password == "" {
				return fmt.Errorf("error: --password is required")
			}

			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "standard"
			socket.UpstreamConfig.DatabaseServiceConfiguration.Standard = &service.StandardDatabaseServiceConfiguration{
				HostnameAndPort:    hostnameAndPort,
				DatabaseProtocol:   upstream_type,
				AuthenticationType: "sql_authentication",
				SqlAuthentication: &service.DatabaseSqlAuthConfiguration{
					UsernameAndPassword: service.UsernameAndPassword{
						Username: username,
						Password: password,
					},
				},
			}
		case authType == "kerberos" && upstream_type == "mssql":
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if password == "" {
				return fmt.Errorf("error: --password is required")
			}

			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "standard"
			socket.UpstreamConfig.DatabaseServiceConfiguration.Standard = &service.StandardDatabaseServiceConfiguration{
				HostnameAndPort:    hostnameAndPort,
				DatabaseProtocol:   upstream_type,
				AuthenticationType: "kerberos",
				Kerberos: &service.DatabaseKerberosAuthConfiguration{
					UsernameAndPassword: service.UsernameAndPassword{
						Username: username,
						Password: password,
					},
				},
			}
		case authType == "azure_ad_password" && upstream_type == "mssql":
			if username == "" {
				return fmt.Errorf("error: --username is required")
			}

			if password == "" {
				return fmt.Errorf("error: --password is required")
			}

			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "azure_sql"
			socket.UpstreamConfig.DatabaseServiceConfiguration.AzureSql = &service.AzureSqlDatabaseServiceConfiguration{
				HostnameAndPort:  hostnameAndPort,
				DatabaseProtocol: upstream_type,
				AzureActiveDirectoryPassword: &service.DatabaseUsernameAndPasswordAuthConfiguration{
					UsernameAndPassword: service.UsernameAndPassword{
						Username: username,
						Password: password,
					},
				},
			}
		case authType == "azure_ad_integrated" && upstream_type == "mssql":
			socket.UpstreamConfig.DatabaseServiceConfiguration.DatabaseServiceType = "azure_sql"
			socket.UpstreamConfig.DatabaseServiceConfiguration.AzureSql = &service.AzureSqlDatabaseServiceConfiguration{
				HostnameAndPort:                hostnameAndPort,
				DatabaseProtocol:               upstream_type,
				AzureActiveDirectoryIntegrated: new(struct{}),
			}
		default:
			if upstream_type == "mssql" {
				return fmt.Errorf("error: --auth_type should be sql_authentication, kerberos, azure_ad_password, cloudsql_connector or azure_ad_integrated")
			}
			return fmt.Errorf("error: --auth_type should be username_and_password, tls, aws_iam, cloudsql_connector or cloudsql_connector_iam")
		}

		if err := socket.UpstreamConfig.Validate(); err != nil {
			return err
		}

		if jsonInput {
			fmt.Println("Socket create request JSON:")
			if err := prettyPrintJSON(socket); err != nil {
				return err
			}
		}

		created, err := api.CreateSocket(cmd.Context(), &socket)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		if jsonOutput {
			return prettyPrintJSON(created)
		}

		var orgPolicies []client.Policy
		policies, _ := api.Policies(cmd.Context())
		for _, p := range policies {
			if p.OrgWide {
				orgPolicies = append(orgPolicies, p)
			}
		}

		connectors, _ := api.SocketConnectors(cmd.Context(), created.SocketID)

		fmt.Print(print_sdk_socket(created, orgPolicies, connectors))
		return nil
	},
}

// tlsSocketCreateCmd represents the socket create command for TLS sockets
var tlsSocketCreateCmd = &cobra.Command{
	Use:   "tls",
	Short: "Create a new tls socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := http.GetToken()
		if err != nil {
			return err
		}

		api := sdk.NewAPIClient(
			client.WithAuthToken(token),
		)

		if connector != "" {
			// if connector is not a uuid, tranlate it to a uuid
			if _, err := uuid.Parse(connector); err != nil {
				var connectorUUID string
				connectors, err := api.Connectors(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to get connector UUID: %w", err)
				}

				for _, c := range connectors.List {
					if c.Name == connector {
						connectorUUID = c.ConnectorID
						break
					}
				}

				if connectorUUID == "" {
					return fmt.Errorf("connector not found")
				}

				connector = connectorUUID
			}
		}

		socket := client.Socket{
			Name:        name,
			SocketType:  "tls",
			Description: description,
			Tags:        tags,
			ConnectorID: connector,
			UpstreamConfig: &service.Configuration{
				ServiceType: "tls",
			},
		}

		if host == "" {
			return fmt.Errorf("error: --host is required")
		}

		if port == 0 {
			return fmt.Errorf("error: --port is required")
		}

		socket.UpstreamConfig.TlsServiceConfiguration = &service.TlsServiceConfiguration{
			TlsServiceType: "standard",
			StandardTlsServiceConfiguration: &service.StandardTlsServiceConfiguration{
				HostnameAndPort: service.HostnameAndPort{
					Hostname: host,
					Port:     uint16(port),
				},
			},
		}

		if err := socket.UpstreamConfig.Validate(); err != nil {
			return err
		}

		if jsonInput {
			fmt.Println("Socket create request JSON:")
			if err := prettyPrintJSON(socket); err != nil {
				return err
			}
		}

		created, err := api.CreateSocket(cmd.Context(), &socket)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		if jsonOutput {
			return prettyPrintJSON(created)
		}

		var orgPolicies []client.Policy
		policies, _ := api.Policies(cmd.Context())
		for _, p := range policies {
			if p.OrgWide {
				orgPolicies = append(orgPolicies, p)
			}
		}

		connectors, _ := api.SocketConnectors(cmd.Context(), created.SocketID)

		fmt.Print(print_sdk_socket(created, orgPolicies, connectors))
		return nil
	},
}

// vncSocketCreateCmd represents the socket create command for VNC sockets
var vncSocketCreateCmd = &cobra.Command{
	Use:   "vnc",
	Short: "Create a new vnc socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := http.GetToken()
		if err != nil {
			return err
		}

		api := sdk.NewAPIClient(
			client.WithAuthToken(token),
		)

		if connector != "" {
			// if connector is not a uuid, tranlate it to a uuid
			if _, err := uuid.Parse(connector); err != nil {
				var connectorUUID string
				connectors, err := api.Connectors(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to get connector UUID: %w", err)
				}

				for _, c := range connectors.List {
					if c.Name == connector {
						connectorUUID = c.ConnectorID
						break
					}
				}

				if connectorUUID == "" {
					return fmt.Errorf("connector not found")
				}

				connector = connectorUUID
			}
		}

		socket := client.Socket{
			Name:        name,
			SocketType:  "vnc",
			Description: description,
			Tags:        tags,
			ConnectorID: connector,
			UpstreamConfig: &service.Configuration{
				ServiceType: "vnc",
			},
		}

		socket.UpstreamConfig.VncServiceConfiguration = &service.VncServiceConfiguration{
			HostnameAndPort: service.HostnameAndPort{
				Hostname: host,
				Port:     vncPort,
			},
		}

		if err := socket.UpstreamConfig.Validate(); err != nil {
			return err
		}

		if jsonInput {
			fmt.Println("Socket create request JSON:")
			if err := prettyPrintJSON(socket); err != nil {
				return err
			}
		}

		created, err := api.CreateSocket(cmd.Context(), &socket)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		if jsonOutput {
			return prettyPrintJSON(created)
		}

		var orgPolicies []client.Policy
		policies, _ := api.Policies(cmd.Context())
		for _, p := range policies {
			if p.OrgWide {
				orgPolicies = append(orgPolicies, p)
			}
		}

		connectors, _ := api.SocketConnectors(cmd.Context(), created.SocketID)

		fmt.Print(print_sdk_socket(created, orgPolicies, connectors))
		return nil
	},
}

// rdpSocketCreateCmd represents the socket create command for RDP sockets
var rdpSocketCreateCmd = &cobra.Command{
	Use:   "rdp",
	Short: "Create a new rdp socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := http.GetToken()
		if err != nil {
			return err
		}

		api := sdk.NewAPIClient(
			client.WithAuthToken(token),
		)

		if connector != "" {
			// if connector is not a uuid, tranlate it to a uuid
			if _, err := uuid.Parse(connector); err != nil {
				var connectorUUID string
				connectors, err := api.Connectors(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to get connector UUID: %w", err)
				}

				for _, c := range connectors.List {
					if c.Name == connector {
						connectorUUID = c.ConnectorID
						break
					}
				}

				if connectorUUID == "" {
					return fmt.Errorf("connector not found")
				}

				connector = connectorUUID
			}
		}

		socket := client.Socket{
			Name:        name,
			SocketType:  "rdp",
			Description: description,
			Tags:        tags,
			ConnectorID: connector,
			UpstreamConfig: &service.Configuration{
				ServiceType: "rdp",
			},
		}

		if port == 0 {
			return fmt.Errorf("error: --port is required")
		}

		socket.UpstreamConfig.RdpServiceConfiguration = &service.RdpServiceConfiguration{
			HostnameAndPort: service.HostnameAndPort{
				Hostname: host,
				Port:     rdpPort,
			},
		}

		if err := socket.UpstreamConfig.Validate(); err != nil {
			return err
		}

		if jsonInput {
			fmt.Println("Socket create request JSON:")
			if err := prettyPrintJSON(socket); err != nil {
				return err
			}
		}

		created, err := api.CreateSocket(cmd.Context(), &socket)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		if jsonOutput {
			return prettyPrintJSON(created)
		}

		var orgPolicies []client.Policy
		policies, _ := api.Policies(cmd.Context())
		for _, p := range policies {
			if p.OrgWide {
				orgPolicies = append(orgPolicies, p)
			}
		}

		connectors, _ := api.SocketConnectors(cmd.Context(), created.SocketID)

		fmt.Print(print_sdk_socket(created, orgPolicies, connectors))
		return nil
	},
}

// vpnSocketCreateCmd represents the socket create command for VPN sockets
var vpnSocketCreateCmd = &cobra.Command{
	Use:   "vpn",
	Short: "Create a new vpn socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := http.GetToken()
		if err != nil {
			return err
		}

		api := sdk.NewAPIClient(
			client.WithAuthToken(token),
		)

		if connector != "" {
			// if connector is not a uuid, tranlate it to a uuid
			if _, err := uuid.Parse(connector); err != nil {
				var connectorUUID string
				connectors, err := api.Connectors(cmd.Context())
				if err != nil {
					return fmt.Errorf("failed to get connector UUID: %w", err)
				}

				for _, c := range connectors.List {
					if c.Name == connector {
						connectorUUID = c.ConnectorID
						break
					}
				}

				if connectorUUID == "" {
					return fmt.Errorf("connector not found")
				}

				connector = connectorUUID
			}
		}

		socket := client.Socket{
			Name:        name,
			SocketType:  "vpn",
			Description: description,
			Tags:        tags,
			ConnectorID: connector,
			UpstreamConfig: &service.Configuration{
				ServiceType: "vpn",
			},
		}

		socket.UpstreamConfig.VpnServiceConfiguration = &service.VpnServiceConfiguration{
			DHCPPoolSubnet:   dhcpPoolSubnet,
			AdvertisedRoutes: advertisedRoutes,
		}

		if err := socket.UpstreamConfig.Validate(); err != nil {
			return err
		}

		if jsonInput {
			fmt.Println("Socket create request JSON:")
			if err := prettyPrintJSON(socket); err != nil {
				return err
			}
		}

		created, err := api.CreateSocket(cmd.Context(), &socket)
		if err != nil {
			return fmt.Errorf("failed to create socket: %w", err)
		}

		if jsonOutput {
			return prettyPrintJSON(created)
		}

		var orgPolicies []client.Policy
		policies, _ := api.Policies(cmd.Context())
		for _, p := range policies {
			if p.OrgWide {
				orgPolicies = append(orgPolicies, p)
			}
		}

		connectors, _ := api.SocketConnectors(cmd.Context(), created.SocketID)

		fmt.Print(print_sdk_socket(created, orgPolicies, connectors))
		return nil
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

				if err := util.StoreConnectorCertificate(pem.EncodeToMemory(privKeyPem), cert, orgID, ""); err != nil {
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

				if err := util.StoreConnectorCertificate(pem.EncodeToMemory(privKeyPem), cert, orgID, ""); err != nil {
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
		return vpnlib.RunServer(ctx, logger, l, vpnSubnet, routes, border0API, *socket.Socket)
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

				if err := util.StoreConnectorCertificate(pem.EncodeToMemory(privKeyPem), cert, orgID, ""); err != nil {
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
			if err := border0.Serve(logger.Logger, l, hostname, port, socket.SocketType, border0API, socket.Socket); err != nil {
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

func getConnectors(ctx context.Context, toComplete string) []string {
	token, err := http.GetToken()
	if err != nil {
		return nil
	}

	api := sdk.NewAPIClient(
		client.WithAuthToken(token),
	)

	knownConnectors, err := api.Connectors(ctx)
	if err != nil {
		return nil
	}

	var connectors []string
	for _, c := range knownConnectors.List {
		if strings.HasPrefix(c.Name, toComplete) {
			connectors = append(connectors, c.Name)
		}

		if strings.HasPrefix(c.ConnectorID, toComplete) {
			connectors = append(connectors, c.ConnectorID)
		}
	}

	return connectors
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
	socketCreateCmd.AddCommand(httpSocketCreateCmd)
	socketCreateCmd.AddCommand(sshSocketCreateCmd)
	socketCreateCmd.AddCommand(databaseSocketCreateCmd)
	socketCreateCmd.AddCommand(tlsSocketCreateCmd)
	socketCreateCmd.AddCommand(vncSocketCreateCmd)
	socketCreateCmd.AddCommand(rdpSocketCreateCmd)
	socketCreateCmd.AddCommand(vpnSocketCreateCmd)

	socketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	socketCreateCmd.Flags().StringVarP(&description, "description", "r", "", "Socket description")
	socketCreateCmd.Flags().StringVarP(&upstream_type, "upstream_type", "", "", "Upstream type: http, https for http sockets or mysql, mssql, postgres for database sockets and aws-ssm for ssh sockets")
	socketCreateCmd.Flags().StringVarP(&socketType, "type", "t", "http", "Socket type: http, https, ssh, tls, database")
	socketCreateCmd.Flags().StringVarP(&orgCustomDomain, "domain", "o", "", "Use custom domain for socket")
	socketCreateCmd.Flags().StringVarP(&upstream_username, "upstream_username", "j", "", "Upstream username used to connect to upstream database")
	socketCreateCmd.Flags().StringVarP(&upstream_password, "upstream_password", "k", "", "Upstream password used to connect to upstream database")
	socketCreateCmd.Flags().StringVarP(&upstream_http_hostname, "upstream_http_hostname", "", "", "Upstream http hostname")
	socketCreateCmd.Flags().StringVarP(&upstream_cert_file, "upstream_certificate_filename", "f", "", "path to file from where to read the upstream client certificate")
	socketCreateCmd.Flags().StringVarP(&upstream_key_file, "upstream_key_filename", "y", "", "path to file from where to read the upstream client key")
	socketCreateCmd.Flags().StringVarP(&upstream_ca_file, "upstream_ca_filename", "a", "", "path to file from where to read the upstream ca certificate")
	socketCreateCmd.Flags().BoolVarP(&connectorAuthEnabled, "connector_auth", "c", false, "Enables connector authentication")
	socketCreateCmd.Flags().MarkHidden("name")
	socketCreateCmd.Flags().MarkHidden("description")
	socketCreateCmd.Flags().MarkHidden("type")
	socketCreateCmd.Flags().MarkHidden("upstream_type")
	socketCreateCmd.Flags().MarkHidden("upstream_username")
	socketCreateCmd.Flags().MarkHidden("upstream_password")
	socketCreateCmd.Flags().MarkHidden("upstream_http_hostname")
	socketCreateCmd.Flags().MarkHidden("upstream_certificate_filename")
	socketCreateCmd.Flags().MarkHidden("upstream_key_filename")
	socketCreateCmd.Flags().MarkHidden("upstream_ca_filename")
	socketCreateCmd.Flags().MarkHidden("connector_auth")
	socketCreateCmd.Flags().MarkHidden("domain")

	// http socket create
	httpSocketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	httpSocketCreateCmd.Flags().StringVarP(&description, "description", "d", "", "Socket description")
	httpSocketCreateCmd.Flags().StringVar(&upstream_type, "upstream_type", "http", "Protocol type to use to connect upstream: http or https")
	httpSocketCreateCmd.Flags().StringVar(&http_hostname, "http_hostname", "", "Http host/sni header")
	httpSocketCreateCmd.Flags().StringVar(&host, "host", "", "Target host: Control where inbound traffic goes")
	httpSocketCreateCmd.Flags().IntVar(&port, "port", 0, "Target port: the port where inbound traffic goes")
	httpSocketCreateCmd.Flags().StringToStringVar(&tags, "tag", map[string]string{}, "Tags for the socket (key=value)")
	httpSocketCreateCmd.Flags().BoolVar(&recordingEnabled, "recording_enabled", false, "Enables session recording")
	httpSocketCreateCmd.Flags().StringVar(&connector, "connector", "", "Connector to attach to the socket, UUID or name of the connector")
	httpSocketCreateCmd.RegisterFlagCompletionFunc("connector", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getConnectors(cmd.Context(), toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	httpSocketCreateCmd.MarkFlagRequired("name")
	httpSocketCreateCmd.MarkFlagRequired("host")
	httpSocketCreateCmd.MarkFlagRequired("port")

	// ssh socket create
	sshSocketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	sshSocketCreateCmd.Flags().StringVarP(&description, "description", "d", "", "Socket description")
	sshSocketCreateCmd.Flags().StringVar(&upstream_type, "upstream_type", "standard", "Upstream type to use to connect upstream: standard, aws_ssm, aws_ec2_instance_connect, connector_built_in_ssh_service, docker_exec or kubectl_exec")
	sshSocketCreateCmd.Flags().StringVar(&host, "host", "", "Target host: Control where inbound traffic goes")
	sshSocketCreateCmd.Flags().Uint16Var(&sshPort, "port", 22, "Target port: the port where inbound traffic goes")
	sshSocketCreateCmd.Flags().StringToStringVar(&tags, "tag", map[string]string{}, "Tags for the socket (key=value)")
	sshSocketCreateCmd.Flags().BoolVar(&recordingEnabled, "recording_enabled", true, "Enables session recording")
	sshSocketCreateCmd.Flags().StringVar(&connector, "connector", "", "Connector to attach to the socket, UUID or name of the connector")
	sshSocketCreateCmd.RegisterFlagCompletionFunc("connector", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getConnectors(cmd.Context(), toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	sshSocketCreateCmd.Flags().StringVar(&authType, "auth_type", "", "Authentication type (for standard upstream_type) to use to connect to the target: username_and_password, ssh_key or border0_certificate")
	sshSocketCreateCmd.Flags().StringVar(&username, "username", "", "Username used to connect to target")
	sshSocketCreateCmd.Flags().StringVar(&password, "password", "", "Password used to connect to target")
	sshSocketCreateCmd.Flags().StringVar(&sshKey, "ssh_key", "", "Ssh key used to connect to target")
	sshSocketCreateCmd.Flags().StringVar(&usernameType, "username_type", "", "Username type (for builtin-sshserver upstream_type and border0_certificate auth_type): use_connector_user, prompt_client or defined")
	sshSocketCreateCmd.Flags().StringVar(&ssmTargetType, "ssm_target_type", "", "AWS SSM target type: ec2 or ecs")
	sshSocketCreateCmd.Flags().StringVar(&awsECSCluster, "ecs_cluster", "", "AWS ECS Cluster")
	sshSocketCreateCmd.Flags().StringVar(&awsECSRegion, "ecs_region", "", "AWS ECS Cluster")
	sshSocketCreateCmd.Flags().StringVar(&awsECSService, "ecs_service", "", "AWS ECS Cluster")
	sshSocketCreateCmd.Flags().StringVar(&awsAccessKeyId, "aws_access_key_id", "", "AWS Access Key ID")
	sshSocketCreateCmd.Flags().StringVar(&awsSecretAccessKey, "aws_secret_access_key", "", "AWS Secret Access Key")
	sshSocketCreateCmd.Flags().StringVar(&awsSessionToken, "aws_session_token", "", "AWS Session Token")
	sshSocketCreateCmd.Flags().StringVar(&awsProfile, "aws_profile", "", "AWS Profile")
	sshSocketCreateCmd.Flags().StringVar(&awsEC2InstanceID, "ec2_instance_id", "", "AWS EC2 Instance ID")
	sshSocketCreateCmd.Flags().StringVar(&awsEC2Region, "ec2_region", "", "AWS EC2 region")
	sshSocketCreateCmd.Flags().StringSliceVar(&allowedDockerContainers, "allowed_docker_container", []string{}, "Allowed docker container to connect to")
	sshSocketCreateCmd.Flags().StringVar(&kubectlExecType, "kubectl_exec_type", "standard", "Kubectl exec type: standard or aws-eks")
	sshSocketCreateCmd.Flags().StringVar(&awsEKSCluster, "eks_cluster", "", "AWS EKS Cluster")
	sshSocketCreateCmd.Flags().StringVar(&awsEKSRegion, "eks_region", "", "AWS EKS Cluster")
	sshSocketCreateCmd.Flags().StringVar(&kubectlExecMasterUrl, "kubectl_exec_master_url", "", "Kubectl exec master url")
	sshSocketCreateCmd.Flags().StringVar(&kubectlExecKubeConfigPath, "kubectl_exec_kube_config_path", "", "Kubectl exec kube config path")
	sshSocketCreateCmd.Flags().StringSliceVar(&allowedNamespaces, "allowed_namespace", []string{}, "Allowed namespace to connect to")
	sshSocketCreateCmd.Flags().StringVar(&namespaceSelectorsAllowlist, "namespace_selectors_allowlist", "", "JSON string of namespace selectors allowlist: {\"namespace\": {\"key\": [\"value\"]}}")
	sshSocketCreateCmd.MarkFlagRequired("name")

	// database socket create
	databaseSocketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	databaseSocketCreateCmd.Flags().StringVarP(&description, "description", "d", "", "Socket description")
	databaseSocketCreateCmd.Flags().StringVar(&upstream_type, "upstream_type", "", "Upstream type to use to connect upstream: mysql, postgres or mssql")
	databaseSocketCreateCmd.Flags().StringVar(&host, "host", "", "Target host: Control where inbound traffic goes")
	databaseSocketCreateCmd.Flags().IntVar(&port, "port", 0, "Target port: the port where inbound traffic goes")
	databaseSocketCreateCmd.Flags().StringToStringVar(&tags, "tag", map[string]string{}, "Tags for the socket (key=value)")
	databaseSocketCreateCmd.Flags().BoolVar(&recordingEnabled, "recording_enabled", true, "Enables session recording")
	databaseSocketCreateCmd.Flags().StringVar(&connector, "connector", "", "Connector to attach to the socket, UUID or name of the connector")
	databaseSocketCreateCmd.RegisterFlagCompletionFunc("connector", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getConnectors(cmd.Context(), toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	databaseSocketCreateCmd.Flags().StringVar(&authType, "auth_type", "", "Authentication type to use to connect to the target: username_and_password, tls, aws_iam, cloudsql_connector, cloudsql_connector_iam, sql_authentication, kerberos, azure_ad_password or azure_ad_integrated")
	databaseSocketCreateCmd.Flags().StringVar(&caCertificate, "ca_certificate", "", "CA certificate used to connect to target")
	databaseSocketCreateCmd.Flags().StringVar(&clientCertificate, "client_certificate", "", "Client certificate used to connect to target")
	databaseSocketCreateCmd.Flags().StringVar(&clientKey, "client_key", "", "Client key used to connect to target")
	databaseSocketCreateCmd.Flags().StringVar(&username, "username", "", "Username used to connect to target")
	databaseSocketCreateCmd.Flags().StringVar(&password, "password", "", "Password used to connect to target")
	databaseSocketCreateCmd.Flags().StringVar(&awsRdsRegion, "rds_region", "", "AWS RDS region")
	databaseSocketCreateCmd.Flags().StringVar(&gcpCloudSQLInstanceID, "cloudsql_instance_id", "", "Google Cloud SQL instance ID")
	databaseSocketCreateCmd.Flags().StringVar(&gcpCredentialsJson, "gcp_credentials_json", "", "Google Cloud SQL credentials JSON")
	databaseSocketCreateCmd.MarkFlagRequired("name")

	// tls socket create
	tlsSocketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	tlsSocketCreateCmd.Flags().StringVarP(&description, "description", "d", "", "Socket description")
	tlsSocketCreateCmd.Flags().StringVar(&host, "host", "", "Target host: Control where inbound traffic goes")
	tlsSocketCreateCmd.Flags().IntVar(&port, "port", 0, "Target port: the port where inbound traffic goes")
	tlsSocketCreateCmd.Flags().StringToStringVar(&tags, "tag", map[string]string{}, "Tags for the socket (key=value)")
	tlsSocketCreateCmd.Flags().StringVar(&connector, "connector", "", "Connector to attach to the socket, UUID or name of the connector")
	tlsSocketCreateCmd.RegisterFlagCompletionFunc("connector", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getConnectors(cmd.Context(), toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	tlsSocketCreateCmd.MarkFlagRequired("name")
	tlsSocketCreateCmd.MarkFlagRequired("host")
	tlsSocketCreateCmd.MarkFlagRequired("port")

	// vnc socket create
	vncSocketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	vncSocketCreateCmd.Flags().StringVarP(&description, "description", "d", "", "Socket description")
	vncSocketCreateCmd.Flags().StringVar(&host, "host", "", "Target host: Control where inbound traffic goes")
	vncSocketCreateCmd.Flags().Uint16Var(&vncPort, "port", 5900, "Target port: the port where inbound traffic goes")
	vncSocketCreateCmd.Flags().StringToStringVar(&tags, "tag", map[string]string{}, "Tags for the socket (key=value)")
	vncSocketCreateCmd.Flags().StringVar(&connector, "connector", "", "Connector to attach to the socket, UUID or name of the connector")
	vncSocketCreateCmd.RegisterFlagCompletionFunc("connector", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getConnectors(cmd.Context(), toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	vncSocketCreateCmd.MarkFlagRequired("name")
	vncSocketCreateCmd.MarkFlagRequired("host")

	// rdp socket create
	rdpSocketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	rdpSocketCreateCmd.Flags().StringVarP(&description, "description", "d", "", "Socket description")
	rdpSocketCreateCmd.Flags().StringVar(&host, "host", "", "Target host: Control where inbound traffic goes")
	rdpSocketCreateCmd.Flags().Uint16Var(&rdpPort, "port", 3389, "Target port: the port where inbound traffic goes")
	rdpSocketCreateCmd.Flags().StringToStringVar(&tags, "tag", map[string]string{}, "Tags for the socket (key=value)")
	rdpSocketCreateCmd.Flags().StringVar(&connector, "connector", "", "Connector to attach to the socket, UUID or name of the connector")
	rdpSocketCreateCmd.RegisterFlagCompletionFunc("connector", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getConnectors(cmd.Context(), toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	rdpSocketCreateCmd.MarkFlagRequired("name")
	rdpSocketCreateCmd.MarkFlagRequired("host")

	// vpn socket create
	vpnSocketCreateCmd.Flags().StringVarP(&name, "name", "n", "", "Socket name")
	vpnSocketCreateCmd.Flags().StringVarP(&description, "description", "d", "", "Socket description")
	vpnSocketCreateCmd.Flags().StringVar(&dhcpPoolSubnet, "dhcp_pool_subnet", "", "VPN Client DHCP pool subnet. ie 10.42.0.0/22")
	vpnSocketCreateCmd.Flags().StringSliceVar(&advertisedRoutes, "advertised_route", []string{}, "Routes to advertise to clients")
	vpnSocketCreateCmd.Flags().StringToStringVar(&tags, "tag", map[string]string{}, "Tags for the socket (key=value)")
	vpnSocketCreateCmd.Flags().StringVar(&connector, "connector", "", "Connector to attach to the socket, UUID or name of the connector")
	vpnSocketCreateCmd.RegisterFlagCompletionFunc("connector", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return getConnectors(cmd.Context(), toComplete), cobra.ShellCompDirectiveNoFileComp
	})
	vpnSocketCreateCmd.MarkFlagRequired("name")
	vpnSocketCreateCmd.MarkFlagRequired("dhcp_pool_subnet")

	// socket delete
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
