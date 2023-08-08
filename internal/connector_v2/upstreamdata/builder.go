package upstreamdata

import (
	"context"
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/lib/varsource"
	"github.com/borderzero/border0-go/service/connector/types"
)

const (
	UpstreamTypeSSH        = "ssh"
	UpstreamTypeAwsSSM     = "aws-ssm"
	UpstreamTypeAwsEC2Conn = "aws-ec2connect"
)

type UpstreamDataBuilder struct {
	vs varsource.VariableSource
}

func NewUpstreamDataBuilder() *UpstreamDataBuilder {
	vs := varsource.NewDefaultVariableSource()
	return &UpstreamDataBuilder{vs}
}

func (u *UpstreamDataBuilder) Build(s *models.Socket, config types.ConnectorServiceUpstreamConfig) error {
	s.ConnectorData.TargetHostname = u.fetchVariableFromSource(config.Hostname)
	s.ConnectorData.Port = config.Port

	switch s.SocketType {
	case "ssh":
		return u.setupSSHUpstreamValues(s, config)
	default:
		return fmt.Errorf("unsupported socket type: %s", s.SocketType)
	}
}

func (u *UpstreamDataBuilder) setupSSHUpstreamValues(s *models.Socket, configMap types.ConnectorServiceUpstreamConfig) error {
	switch configMap.UpstreamConnectionType {
	case types.UpstreamConnectionTypeSSH:
		u.setupSSH(s, configMap)
	case types.UpstreamConnectionTypeAwsSSM:
		u.setupAWSSSM(s, *configMap.SSHConfiguration.AwsSSMDetails)
	case types.UpstreamConnectionTypeAwsEC2Connection:
		u.setupEc2Connect(s, *configMap.SSHConfiguration.AwsEC2ConnectDetails)
	case types.UpstreamAuthenticationTypeBorder0Cert:
		u.setupBorder0Certificate(s, configMap.SSHConfiguration.Border0CertificateDetails)
	case types.UpstreamConnectionTypeBuiltInSshServer:
		u.setupBuiltInSshServer(s)
	default:
		return fmt.Errorf("unknown upstream connection type: %s", configMap.UpstreamConnectionType)
	}

	return nil
}

func (u *UpstreamDataBuilder) setupSSH(s *models.Socket, configMap types.ConnectorServiceUpstreamConfig) error {
	s.ConnectorData.TargetHostname = configMap.Hostname
	s.ConnectorData.Port = configMap.Port
	s.TargetHostname = configMap.Hostname
	s.TargetPort = configMap.Port
	s.UpstreamType = UpstreamTypeSSH

	if configMap.SSHConfiguration.UpstreamAuthenticationType == types.UpstreamAuthenticationTypeUsernamePassword {
		basicCreds := configMap.SSHConfiguration.BasicCredentials
		s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(basicCreds.Username)
		s.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(basicCreds.Password)
	}

	if configMap.SSHConfiguration.UpstreamAuthenticationType == types.UpstreamAuthenticationTypeSSHPrivateKey {
		details := configMap.SSHConfiguration.SSHPrivateKeyDetails
		keyInBytes := []byte(u.fetchVariableFromSource(details.Key))

		s.ConnectorLocalData.UpstreamIdentityPrivateKey = keyInBytes
		s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(details.Username)
	}

	return nil
}

func (u *UpstreamDataBuilder) setupAWSSSM(s *models.Socket, ssmDetails types.AwsSSMDetails) error {
	s.UpstreamType = UpstreamTypeAwsSSM
	s.ConnectorLocalData.AwsEC2InstanceId = u.fetchVariableFromSource(ssmDetails.InstanceID)
	s.ConnectorLocalData.AWSRegion = u.fetchVariableFromSource(ssmDetails.Region)
	s.AWSRegion = u.fetchVariableFromSource(ssmDetails.Region)

	return nil
}

func (u *UpstreamDataBuilder) setupBorder0Certificate(s *models.Socket, details *types.Border0CertificateDetails) error {
	if details != nil && details.Username != "" {
		s.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(details.Username)
	}

	return nil
}

func (u *UpstreamDataBuilder) setupEc2Connect(s *models.Socket, ec2Details types.AwsEC2ConnectDetails) error {
	s.UpstreamType = UpstreamTypeAwsEC2Conn
	s.ConnectorLocalData.AwsEC2InstanceId = u.fetchVariableFromSource(ec2Details.InstanceID)
	s.AWSRegion = u.fetchVariableFromSource(ec2Details.Region)
	s.ConnectorLocalData.AWSEC2InstanceConnectEnabled = true

	return nil
}

func (u *UpstreamDataBuilder) setupBuiltInSshServer(s *models.Socket) error {
	s.SSHServer = true
	return nil
}

func (u *UpstreamDataBuilder) fetchVariableFromSource(field string) string {
	val, err := u.vs.GetVariable(context.Background(), field)
	if err != nil {
		fmt.Printf("error evaluating variable %s: %v\n", field, err)
		return field
	}
	return val
}
