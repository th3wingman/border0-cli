package config

import (
	"fmt"
	"os"
	"strconv"
)

const (
	envNameDeviceManagementServer                      = "BORDER0_DEVICE_MANAGEMENT_SERVER"
	envNameDeviceManagementInsecureTransport           = "BORDER0_DEVICE_MANAGEMENT_INSECURE_TRANSPORT"
	envNameDeviceManagementManagedNetworkInterfaceName = "BORDER0_DEVICE_MANAGEMENT_MANAGED_NETWORKING_INTERFACE_NAME"
	envNameRelayURL                                    = "BORDER0_RELAY_URL"

	defaultDeviceManagementServer            = "capi.border0.com:443"
	defaultDeviceManagementInsecureTransport = false
	defaultManagedNetworkingIfaceName        = "utun9"
	defaultRelayURL                          = "wss://relay.border0.com"
)

// Configuration represents (static) node configuration
type Configuration struct {
	DeviceManagementServer            string `yaml:"device_management_server,omitempty"`
	DeviceManagementInsecureTransport bool   `yaml:"device_management_insecure_transport,omitempty"`
	ManagedNetworkingInterfaceName    string `yaml:"managed_networking_interface_name,omitempty"`
	RelayURL                          string `yaml:"relay_url,omitempty"`
}

// GetConfiguration looks for credentials and variables in the standard variable chain.
func GetConfiguration() (*Configuration, error) {
	config := &Configuration{
		DeviceManagementServer:            defaultDeviceManagementServer,
		DeviceManagementInsecureTransport: defaultDeviceManagementInsecureTransport,
		ManagedNetworkingInterfaceName:    defaultManagedNetworkingIfaceName,
		RelayURL:                          defaultRelayURL,
	}

	if os.Getenv(envNameDeviceManagementServer) != "" {
		config.DeviceManagementServer = os.Getenv(envNameDeviceManagementServer)
	}

	if os.Getenv(envNameDeviceManagementInsecureTransport) != "" {
		deviceManagementInsecureTransport, err := strconv.ParseBool(os.Getenv(envNameDeviceManagementInsecureTransport))
		if err != nil {
			return nil, fmt.Errorf("failed to parse device management server insecure transport value: %v", err)
		}
		config.DeviceManagementInsecureTransport = deviceManagementInsecureTransport
	}

	if os.Getenv(envNameDeviceManagementManagedNetworkInterfaceName) != "" {
		config.ManagedNetworkingInterfaceName = os.Getenv(envNameDeviceManagementManagedNetworkInterfaceName)
	}

	relayURL := os.Getenv(envNameRelayURL)
	if relayURL != "" {
		config.RelayURL = relayURL
	}

	return config, nil
}
