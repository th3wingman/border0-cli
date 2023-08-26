package upstreamdata

import (
	"errors"
	"fmt"
	"os/user"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForSshService(s *models.Socket, config *service.SshServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got ssh service with no ssh service configuration")
	}

	switch config.SshServiceType {
	case service.SshServiceTypeAwsEc2InstanceConnect:
		return u.buildUpstreamDataForSshServiceAwsEc2Ic(s, config.AwsEc2ICSshServiceConfiguration)
	case service.SshServiceTypeAwsSsm:
		return u.buildUpstreamDataForSshServiceAwsSsm(s, config.AwsSsmSshServiceConfiguration)
	case service.SshServiceTypeConnectorBuiltIn:
		return u.buildUpstreamDataForSshServiceBuiltIn(s, config.BuiltInSshServiceConfiguration)
	case service.SshServiceTypeStandard:
		return u.buildUpstreamDataForSshServiceStandard(s, config.StandardSshServiceConfiguration)
	default:
		return fmt.Errorf("unsupported ssh service type: %s", config.SshServiceType)
	}
}

func (u *UpstreamDataBuilder) buildUpstreamDataForSshServiceAwsEc2Ic(s *models.Socket, config *service.AwsEc2ICSshServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got aws ec2 instance-connect ssh service with no aws ec2 instance-connect ssh service configuration")
	}

	s.ConnectorData.TargetHostname = u.fetchVariableFromSource(config.Hostname)
	s.ConnectorData.Port = int(config.Port)
	s.UpstreamType = UpstreamTypeAwsEC2Conn
	s.ConnectorLocalData.AwsEC2InstanceId = config.Ec2InstanceId
	s.AWSRegion = config.Ec2InstanceRegion
	s.ConnectorLocalData.AWSEC2InstanceConnectEnabled = true
	s.ConnectorLocalData.AwsCredentials = config.AwsCredentials

	switch config.UsernameProvider {
	case service.UsernameProviderDefined, "":
		s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.Username)
	case service.UsernameProviderPromptClient:
		// do nothing
	default:
		return fmt.Errorf("username provider \"%s\" is not supported", config.UsernameProvider)
	}
	return nil
}

func (u *UpstreamDataBuilder) buildUpstreamDataForSshServiceAwsSsm(s *models.Socket, config *service.AwsSsmSshServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got aws ssm ssh service with no aws ssm ssh service configuration")
	}

	switch config.SsmTargetType {
	case service.SsmTargetTypeEc2:
		if config.AwsSsmEc2TargetConfiguration == nil {
			return errors.New("got an ssm ssh service with an ec2 target but had empty ec2 target configuration")
		}
		s.UpstreamType = UpstreamTypeAwsSSM
		s.ConnectorLocalData.AwsEC2InstanceId = config.AwsSsmEc2TargetConfiguration.Ec2InstanceId
		s.AWSRegion = config.AwsSsmEc2TargetConfiguration.Ec2InstanceRegion
		s.ConnectorLocalData.AwsCredentials = config.AwsSsmEc2TargetConfiguration.AwsCredentials
		return nil

	case service.SsmTargetTypeEcs:
		if config.AwsSsmEcsTargetConfiguration == nil {
			return errors.New("got an ssm ssh service with an ecs target but had empty ecs target configuration")
		}

		s.UpstreamType = UpstreamTypeAwsSSM
		s.ConnectorLocalData.AWSECSCluster = config.AwsSsmEcsTargetConfiguration.EcsClusterName
		s.AWSRegion = config.AwsSsmEcsTargetConfiguration.EcsClusterRegion
		s.ConnectorLocalData.AWSECSServices = []string{config.AwsSsmEcsTargetConfiguration.EcsServiceName}
		s.ConnectorLocalData.AwsCredentials = config.AwsSsmEcsTargetConfiguration.AwsCredentials
		return nil

	default:
		return fmt.Errorf("unsupported ssm target type: %s", config.SsmTargetType)

	}
}

func (u *UpstreamDataBuilder) buildUpstreamDataForSshServiceStandard(s *models.Socket, config *service.StandardSshServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got standard ssh service with no standard ssh service configuration")
	}

	hostname, port := u.fetchVariableFromSource(config.Hostname), int(config.Port)

	s.UpstreamType = UpstreamTypeSSH
	s.ConnectorData.TargetHostname = hostname
	s.ConnectorData.Port = port
	s.TargetHostname = hostname
	s.TargetPort = port

	switch config.SshAuthenticationType {
	case service.StandardSshServiceAuthenticationTypeBorder0Certificate:
		if config.Border0CertificateAuthConfiguration == nil {
			return fmt.Errorf("got border0 certificate standard ssh service with no border0 certificate ssh service configuration")
		}

		switch config.Border0CertificateAuthConfiguration.UsernameProvider {
		case service.UsernameProviderDefined, "":
			// NOTE: for border0 certificate sockets, the role of the connector is to just forward bytes
			// between the proxy and the origin. The signed certificate comes directly from the proxy, and
			// username from clients (e.g. the web client). Which is why we do not populate the username here.

			// s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.Border0CertificateAuthConfiguration.Username)
		case service.UsernameProviderPromptClient:
			// do nothing
		default:
			return fmt.Errorf("username provider \"%s\" is not supported", config.Border0CertificateAuthConfiguration.UsernameProvider)
		}

		return nil
	case service.StandardSshServiceAuthenticationTypePrivateKey:
		if config.PrivateKeyAuthConfiguration == nil {
			return fmt.Errorf("got private key standard ssh service with no private key ssh service configuration")
		}

		switch config.PrivateKeyAuthConfiguration.UsernameProvider {
		case service.UsernameProviderDefined, "":
			s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.PrivateKeyAuthConfiguration.Username)
		case service.UsernameProviderPromptClient:
			// do nothing
		default:
			return fmt.Errorf("username provider \"%s\" is not supported", config.PrivateKeyAuthConfiguration.UsernameProvider)
		}

		s.ConnectorLocalData.UpstreamIdentityPrivateKey = []byte(u.fetchVariableFromSource(config.PrivateKeyAuthConfiguration.PrivateKey))
		return nil
	case service.StandardSshServiceAuthenticationTypeUsernameAndPassword:
		if config.UsernameAndPasswordAuthConfiguration == nil {
			return fmt.Errorf("got username and password standard ssh service with no username and password standard ssh service configuration")
		}

		switch config.UsernameAndPasswordAuthConfiguration.UsernameProvider {
		case service.UsernameProviderDefined, "":
			s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.UsernameAndPasswordAuthConfiguration.Username)
		case service.UsernameProviderPromptClient:
			// do nothing
		default:
			return fmt.Errorf("username provider \"%s\" is not supported", config.UsernameAndPasswordAuthConfiguration.UsernameProvider)
		}

		s.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.UsernameAndPasswordAuthConfiguration.Password)
		return nil
	default:
		return fmt.Errorf("unsupported standard ssh service authentication type: %s", config.SshAuthenticationType)
	}
}

func (u *UpstreamDataBuilder) buildUpstreamDataForSshServiceBuiltIn(s *models.Socket, config *service.BuiltInSshServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got built-in ssh service with no built-in ssh service configuration")
	}

	s.SSHServer = true

	switch config.UsernameProvider {
	case service.UsernameProviderDefined, "":
		s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.Username)
		return nil
	case service.UsernameProviderUseConnectorUser:
		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("failed to get the current user: %v", err)
		}
		s.ConnectorLocalData.UpstreamUsername = currentUser.Username
		return nil
	case service.UsernameProviderPromptClient:
		return nil
	default:
		return fmt.Errorf("unsupported built-in ssh service username provider: %s", config.UsernameProvider)
	}
}
