package daemon

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/kardianos/service"
)

const (
	defaultServiceName        = "border0"
	defaultServiceDisplayName = "Border0 Connector"
	defaultServiceDescription = "Border0 Connector Service"
	defaultBinaryName         = "border0"
)

// Option represents a configuration option for the Border0 Connector service.
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

// WithConfigurationFilePath sets the configuration file path.
func WithConfigurationFilePath(path string) Option {
	return func(c *configuration) { c.configFilePath = path }
}

type configuration struct {
	serviceName        string
	serviceDisplayName string
	serviceDescription string
	binaryName         string
	configFilePath     string
}

// GetConnectorService returns the service.Service
// that wraps the Border0 Connector daemon service.
func GetConnectorService(opts ...Option) (service.Service, error) {
	// initialize config and apply options
	config := &configuration{
		serviceName:        defaultServiceName,
		serviceDisplayName: defaultServiceDisplayName,
		serviceDescription: defaultServiceDescription,
		binaryName:         defaultBinaryName,
	}
	for _, opt := range opts {
		opt(config)
	}
	// define internal service config
	internalService := &daemon{}
	// (try) look for binary in binaries $PATH/%PATH%
	executablePath, err := exec.LookPath(config.binaryName)
	if err != nil {
		executablePath = config.binaryName
	}
	// define arguments
	args := []string{"connector", "start"}
	if config.configFilePath != "" {
		args = append(args, "--config", config.configFilePath)
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
		return nil, fmt.Errorf("failed to initialize border0 connector service object: %v", err)
	}
	return svc, nil
}

// IsInstalled returns true if the Border0 Connector service is already installed.
func IsInstalled() (bool, error) {
	connectorSvc, err := GetConnectorService()
	if err != nil {
		return false, fmt.Errorf("failed to initialize new connector service object: %v", err)
	}
	if _, err = connectorSvc.Status(); err != nil {
		if strings.Contains(err.Error(), "the service is not installed") {
			return false, nil
		}
		return false, fmt.Errorf("failed to get connector service status: %v", err)
	}
	return true, nil
}

// Uninstall uninstalls the Border0 Connector service.
func Uninstall() error {
	installed, err := IsInstalled()
	if err != nil {
		return fmt.Errorf("failed to check whether service is already installed: %v", err)
	}
	if !installed {
		log.Print("The service is NOT installed")
		return nil
	}

	connectorSvc, err := GetConnectorService()
	if err != nil {
		return fmt.Errorf("failed to build connector service object: %v", err)
	}

	// best effort attempt at stopping gracefully
	status, err := connectorSvc.Status()
	if err == nil {
		if status == service.StatusRunning {
			if err = connectorSvc.Stop(); err != nil {
				log.Printf("failed to stop connector service: %v", err)
			}
		}
	}

	if err = connectorSvc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall connector service: %v", err)
	}

	return nil
}
