package daemon

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/kardianos/service"
)

const (
	defaultServiceName        = "border0-device"
	defaultServiceDisplayName = "Border0 device management service"
	defaultServiceDescription = "Border0 Device Management Service"
	defaultBinaryName         = "border0"
)

// Option represents a configuration option for the Border0 device service.
type Option func(*configuration)

// WithServiceName overrides the default service name.
func WithServiceName(serviceName string) Option {
	return func(c *configuration) { c.serviceName = serviceName }
}

// WithServiceDisplayName overrides the default service display name.
func WithServiceDisplayName(serviceDisplayName string) Option {
	return func(c *configuration) { c.serviceDisplayName = serviceDisplayName }
}

// WithServiceDescription overrides the default service description.
func WithServiceDescription(serviceDescription string) Option {
	return func(c *configuration) { c.serviceDescription = serviceDescription }
}

// WithBinaryName overrides the default binary name.
func WithBinaryName(binary string) Option {
	return func(c *configuration) { c.binaryName = binary }
}

func WithNetworkInterface(networkInterface string) Option {
	return func(c *configuration) { c.networkInterface = networkInterface }
}

func WithHomeDir(homeDir string) Option {
	return func(c *configuration) { c.homeDir = homeDir }
}

func WithWaitForAuth() Option {
	return func(c *configuration) { c.waitForAuth = true }
}

type configuration struct {
	serviceName        string
	serviceDisplayName string
	serviceDescription string
	binaryName         string
	networkInterface   string
	homeDir            string
	waitForAuth        bool
}

// GetDeviceService returns the service.Service
// that wraps the Border0 Device daemon service.
func GetDeviceService(opts ...Option) (service.Service, error) {
	// initialize config and apply options
	config := &configuration{
		serviceName:        defaultServiceName,
		serviceDisplayName: defaultServiceDisplayName,
		serviceDescription: defaultServiceDescription,
		binaryName:         defaultBinaryName,
	}

	// setup the border0cli name for windows to avoid conflict with desktop app name
	if runtime.GOOS == "windows" {
		config.binaryName = "border0cli.exe"
	}

	for _, opt := range opts {
		opt(config)
	}
	// define internal service config
	internalService := &daemon{}

	executablePath, err := os.Executable()
	if err != nil {
		executablePath = config.binaryName
	}

	// define arguments
	args := []string{"node", "start"}

	// used to setup the home folder to store the device state file and client_token
	if config.homeDir != "" {
		args = append(args, "--home-dir", config.homeDir)
	}

	// used to instruct the service to run with only the HTTP server
	if config.waitForAuth {
		args = append(args, "--wait-for-auth")
	}

	// define system service config (abstracts away OS specifics)
	systemService := &service.Config{
		Name:        config.serviceName,
		DisplayName: config.serviceDisplayName,
		Description: config.serviceDescription,
		Executable:  executablePath,
		Arguments:   args,
	}

	// initialize new service object
	svc, err := service.New(internalService, systemService)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize border0 device service object: %v", err)
	}
	return svc, nil
}

// IsInstalled returns true if the Border0 device service is already installed.
func IsInstalled() (bool, error) {
	svc, err := GetDeviceService()
	if err != nil {
		return false, fmt.Errorf("failed to initialize new device service object: %v", err)
	}
	if _, err = svc.Status(); err != nil {
		if strings.Contains(err.Error(), "the service is not installed") {
			return false, nil
		}
		return false, fmt.Errorf("failed to get device service status: %v", err)
	}
	return true, nil
}

// Uninstall uninstalls the Border0 device service.
func Uninstall() error {
	installed, err := IsInstalled()
	if err != nil {
		return fmt.Errorf("failed to check whether service is already installed: %v", err)
	}
	if !installed {
		log.Print("The service is NOT installed")
		return nil
	}

	svc, err := GetDeviceService()
	if err != nil {
		return fmt.Errorf("failed to build device service object: %v", err)
	}

	// best effort attempt at stopping gracefully
	status, err := svc.Status()
	if err == nil {
		if status == service.StatusRunning {
			if err = svc.Stop(); err != nil {
				log.Printf("failed to stop device service: %v", err)
			}
		}
	}

	if err = svc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall device service: %v", err)
	}

	return nil
}
