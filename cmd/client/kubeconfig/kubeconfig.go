package kubeconfig

// When a client wants to configure their local kubeconfig to be
// able to talk to this socket, they will run the command:
//
// `border0 client kubeconfig set
//
// This will modify the local ~/.kube/config as follows (for each socket):
//
// Add a cluster the "clusters" section:
// ----------------------------------------------------------------------------------
// - cluster:
//   name: ${SOCKET_DNS_NAME}
// 	   certificate-authority: ${PATH_TO_PROXY_PUBLIC_AND_ORG_WIDE_CA_CERT}
// 	   server: https://${SOCKET_DNS_NAME}
// 	   proxy-url: https://${SOCKET_DNS_NAME}:${BORDER0_PROXY_HTTP_LISTENER_PORT}
// ----------------------------------------------------------------------------------
//
// Add a user in the "users" section:
// ----------------------------------------------------------------------------------
// - name: border0-${SOCKET_DNS_NAME}
//   user:
//     client-certificate: ${PATH_TO_ORG_WIDE_CA_SIGNED_CLIENT_CERT}
//     client-key: ${PATH_TO_ORG_WIDE_CA_SIGNED_CLIENT_CERT_KEY}
// ----------------------------------------------------------------------------------
//
// Add a context in the "contexts" section:
// ----------------------------------------------------------------------------------
// - context:
//     cluster: ${SOCKET_DNS_NAME}
//     user: border0-${SOCKET_DNS_NAME}
//   name: border0-${SOCKET_DNS_NAME}
// ----------------------------------------------------------------------------------

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/borderzero/border0-cli/cmd/logger"
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/client"
	"github.com/borderzero/border0-cli/internal/enum"
	"github.com/spf13/cobra"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/clientcmd/api"
)

var (
	service string
)

const defaultBorder0HTTPProxyPort = "1443"

// kubeconfigCmd represents the kubeconfig command tree
var kubeconfigCmd = &cobra.Command{
	Use:   "kubeconfig",
	Short: "Manage kubeconfig for a Kubernetes socket",
}

// getCmd represents the kubeconfig get command
var getCmd = &cobra.Command{
	Use:               "get",
	Short:             "Print the kubernetes configuration for access to a Kubernetes socket",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {

		var sockets []models.ClientResource
		if service == "" {
			// get all kubernetes sockets for which the client
			// is authorized in the current organization
			k8sSockets, err := client.ListOrgSockets(enum.KubernetesSocket)
			if err != nil {
				return err
			}
			// collect dns names
			sockets = k8sSockets
		} else {
			info, err := client.GetOrgSocket(service)
			if err != nil {
				log.Fatalf("failed to service info: %v", err)
			}
			sockets = []models.ClientResource{*info}
		}

		config := api.NewConfig()

		if len(sockets) > 0 {
			// get a client cert and key using the first socket...
			// the client and cert is valid for all sockets.
			info, err := client.GetResourceInfo(logger.Logger, sockets[0].Hostname())
			if err != nil {
				log.Fatalf("failed to get certificate: %v", err)
			}

			updateKubeconfig(
				config,
				sockets,
				info.ProxyAndOrgCaCertificatesPath,
				info.CertificatePath,
				info.PrivateKeyPath,
				service != "",
			)
		}

		configBytes, err := clientcmd.Write(*config)
		if err != nil {
			log.Fatalf("failed to encode kubeconfig data: %v", err)
		}

		fmt.Println(string(configBytes))
		return nil
	},
}

// setCmd represents the kubeconfig set command
var setCmd = &cobra.Command{
	Use:               "set",
	Short:             "Update your ~/.kube/config for access to a Kubernetes socket",
	ValidArgsFunction: client.AutocompleteHost,
	RunE: func(cmd *cobra.Command, args []string) error {

		var sockets []models.ClientResource
		if service == "" {
			// get all kubernetes sockets for which the client
			// is authorized in the current organization
			k8sSockets, err := client.ListOrgSockets(enum.KubernetesSocket)
			if err != nil {
				return err
			}
			// collect dns names
			sockets = k8sSockets
		} else {
			info, err := client.GetOrgSocket(service)
			if err != nil {
				log.Fatalf("failed to service info: %v", err)
			}
			sockets = []models.ClientResource{*info}
		}

		// exit if there are no sockets to update kubeconfig for exit early
		if len(sockets) == 0 {
			fmt.Println("Updated kubeconfig for 0 socket(s)!")
			return nil
		}

		// get a client cert and key using the first socket...
		// the client and cert is valid for all sockets.
		info, err := client.GetResourceInfo(logger.Logger, sockets[0].Hostname())
		if err != nil {
			log.Fatalf("failed to get certificate: %v", err)
		}

		if err := updateKubeconfigFile(
			sockets,
			info.ProxyAndOrgCaCertificatesPath,
			info.CertificatePath,
			info.PrivateKeyPath,
			service != "",
		); err != nil {
			log.Fatalf("failed to update kubeconfig file: %v", err)
		}

		if len(sockets) > 1 {
			fmt.Printf("Updated kubeconfig for %d sockets!\n", len(sockets))
		} else {
			fmt.Println("Updated kubeconfig for 1 socket!")
		}

		if service != "" {
			fmt.Printf("\nYour current Kubernetes context is now \"%s\"!\n", socketDnsToContext(service))
		} else {
			fmt.Println("\nDon't forget to set your current kubernetes context with:\n  kubectl config use-context [ CONTEXT-NAME ]")
			fmt.Println("\nHint: You can lists all contexts with:\n  kubectl config get-contexts")
		}
		return nil
	},
}

func updateKubeconfigFile(
	sockets []models.ClientResource,
	proxyAndOrgCaCertificatesPath string,
	clientCertPath string,
	clientKeyPath string,
	setFirstAsCurrentContext bool,
) error {
	// determine kubeconfig filepath
	configLoadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	kubeconfigFilename := configLoadingRules.GetDefaultFilename()

	// stat kubeconfig file and create an empty file if it does not exist
	if _, err := os.Stat(kubeconfigFilename); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("unexpected error while attempting to locate kubeconfig at %s: %v", kubeconfigFilename, err)
		}
		if err = os.MkdirAll(filepath.Dir(kubeconfigFilename), 0755); err != nil {
			return fmt.Errorf("failed to create .kube directory at %s: %v", filepath.Dir(kubeconfigFilename), err)
		}
		if err = os.WriteFile(kubeconfigFilename, nil, 0600); err != nil {
			return fmt.Errorf("failed to create kubeconfig file at %s: %v", kubeconfigFilename, err)
		}
	}

	// load the existing kubeconfig
	config, err := clientcmd.LoadFromFile(kubeconfigFilename)
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %v", err)
	}

	// update it
	updateKubeconfig(config, sockets, proxyAndOrgCaCertificatesPath, clientCertPath, clientKeyPath, setFirstAsCurrentContext)

	// write it to the kubeconfig file
	if err := clientcmd.WriteToFile(*config, kubeconfigFilename); err != nil {
		return fmt.Errorf("failed to write updated kubeconfig to file: %v", err)
	}

	return nil
}

func updateKubeconfig(
	config *api.Config,
	sockets []models.ClientResource,
	proxyAndOrgCaCertificatePath string,
	clientCertPath string,
	clientKeyPath string,
	setFirstAsCurrentContxt bool,
) {
	// determine the port of the border0 proxy's http listener for kubernetes sockets
	proxyPort := os.Getenv("BORDER0_HTTPPROXY_PORT")
	if proxyPort == "" {
		proxyPort = defaultBorder0HTTPProxyPort
	}

	for _, socket := range sockets {
		// define cluster, user, and context names
		clusterName := socket.Hostname()
		authInfo := fmt.Sprintf("border0-%s", socket.Hostname())
		contextName := socketDnsToContext(socket.Hostname())

		// add new cluster to kubeconfig
		if socket.PrivateNetworkEnabled {
			config.Clusters[clusterName] = &api.Cluster{
				Server: fmt.Sprintf("http://%s", socket.PrivateNetworkIP()),
			}

			// add new context to kubeconfig
			config.Contexts[contextName] = &api.Context{
				Cluster: clusterName,
			}
		} else {
			config.Clusters[clusterName] = &api.Cluster{
				Server:               fmt.Sprintf("https://%s", socket.Hostname()),
				ProxyURL:             fmt.Sprintf("https://%s:%s", socket.Hostname(), proxyPort),
				CertificateAuthority: proxyAndOrgCaCertificatePath,
			}

			// add new user to kubeconfig
			config.AuthInfos[authInfo] = &api.AuthInfo{
				ClientCertificate: clientCertPath,
				ClientKey:         clientKeyPath,
			}

			// add new context to kubeconfig
			config.Contexts[contextName] = &api.Context{
				Cluster:  clusterName,
				AuthInfo: authInfo,
			}
		}
	}

	// set the current context if applicable
	if setFirstAsCurrentContxt {
		if len(sockets) > 0 {
			config.CurrentContext = socketDnsToContext(sockets[0].Hostname())
		}
	}
}

func AddCommandsTo(client *cobra.Command) {
	setCmd.Flags().StringVarP(&service, "service", "", "", "The border0 socket to set kubeconfig for")
	getCmd.Flags().StringVarP(&service, "service", "", "", "The border0 socket to get kubeconfig for")
	kubeconfigCmd.AddCommand(getCmd, setCmd)
	client.AddCommand(kubeconfigCmd)
}

func socketDnsToContext(dns string) string {
	return fmt.Sprintf("border0-%s", dns)
}
