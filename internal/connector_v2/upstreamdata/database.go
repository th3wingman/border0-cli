package upstreamdata

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-go/lib/types/pointer"
	"github.com/borderzero/border0-go/types/service"
)

func (u *UpstreamDataBuilder) buildUpstreamDataForDatabaseService(socket *models.Socket, config *service.DatabaseServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got database service with no database service configuration")
	}

	switch config.DatabaseServiceType {
	case service.DatabaseServiceTypeStandard:
		return u.buildUpstreamDataForDatabaseServiceStandard(socket, config.Standard)
	case service.DatabaseServiceTypeAwsRds:
		return u.buildUpstreamDataForDatabaseServiceAwsRds(socket, config.AwsRds)
	case service.DatabaseServiceTypeGcpCloudSql:
		return u.buildUpstreamDataForDatabaseServiceGcpCloudSql(socket, config.GcpCloudSql)
	case service.DatabaseServiceTypeAzureSql:
		return u.buildUpstreamDataForDatabaseServiceAzureSql(socket, config.AzureSql)
	}

	return fmt.Errorf("unsupported database service type: %s", config.DatabaseServiceType)
}

func (u *UpstreamDataBuilder) buildUpstreamDataForDatabaseServiceStandard(socket *models.Socket, config *service.StandardDatabaseServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got database service with no standard database service configuration")
	}

	hostname, port := u.fetchVariableFromSource(config.Hostname), int(config.Port)

	socket.UpstreamType = config.DatabaseProtocol
	socket.ConnectorData.TargetHostname = hostname
	socket.ConnectorData.Port = port
	socket.TargetHostname = hostname
	socket.TargetPort = port

	switch config.AuthenticationType {
	case service.DatabaseAuthenticationTypeUsernameAndPassword:
		if config.UsernameAndPasswordAuth == nil {
			return fmt.Errorf("got database service with no username and password authentication configuration")
		}
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.UsernameAndPasswordAuth.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.UsernameAndPasswordAuth.Password)
		socket.ConnectorLocalData.UpstreamTLS = pointer.To(false)
	case service.DatabaseAuthenticationTypeTls:
		if config.TlsAuth == nil {
			return fmt.Errorf("got database service with no TLS authentication configuration")
		}
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.TlsAuth.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.TlsAuth.Password)
		socket.ConnectorLocalData.UpstreamCertBlock = []byte(u.fetchVariableFromSource(config.TlsAuth.Certificate))
		socket.ConnectorLocalData.UpstreamKeyBlock = []byte(u.fetchVariableFromSource(config.TlsAuth.Key))
		if config.TlsAuth.CaCertificate != "" {
			socket.ConnectorLocalData.UpstreamCACertBlock = []byte(u.fetchVariableFromSource(config.TlsAuth.CaCertificate))
		}
		socket.ConnectorLocalData.UpstreamTLS = pointer.To(true)
	case service.DatabaseAuthenticationTypeKerberos:
		if config.Kerberos == nil {
			return fmt.Errorf("got database service with no Kerberos authentication configuration")
		}

		socket.ConnectorLocalData.Kerberos = true
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.Kerberos.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.Kerberos.Password)
	case service.DatabaseAuthenticationTypeSqlAuthentication:
		if config.SqlAuthentication == nil {
			return fmt.Errorf("got database service with no SqlAuthentication authentication configuration")
		}

		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.SqlAuthentication.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.SqlAuthentication.Password)
	}

	return nil
}

func (u *UpstreamDataBuilder) buildUpstreamDataForDatabaseServiceAwsRds(socket *models.Socket, config *service.AwsRdsDatabaseServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got database service with no AWS RDS database service configuration")
	}

	hostname, port := u.fetchVariableFromSource(config.Hostname), int(config.Port)

	socket.UpstreamType = config.DatabaseProtocol
	socket.ConnectorData.TargetHostname = hostname
	socket.ConnectorData.Port = port
	socket.TargetHostname = hostname
	socket.TargetPort = port

	switch config.AuthenticationType {
	case service.DatabaseAuthenticationTypeUsernameAndPassword:
		if config.UsernameAndPasswordAuth == nil {
			return fmt.Errorf("got database service with no username and password authentication configuration")
		}
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.UsernameAndPasswordAuth.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.UsernameAndPasswordAuth.Password)
		socket.ConnectorLocalData.UpstreamTLS = pointer.To(false)
		if config.UsernameAndPasswordAuth.CaCertificate != "" {
			socket.ConnectorLocalData.UpstreamCACertBlock = []byte(u.fetchVariableFromSource(config.UsernameAndPasswordAuth.CaCertificate))
			socket.ConnectorLocalData.UpstreamTLS = pointer.To(true)
		}
	case service.DatabaseAuthenticationTypeIam:
		if config.IamAuth == nil {
			return fmt.Errorf("got database service with no IAM authentication configuration")
		}
		socket.ConnectorLocalData.RdsIAMAuth = true
		socket.ConnectorLocalData.UpstreamTLS = pointer.To(true)
		socket.ConnectorLocalData.AWSRegion = config.IamAuth.RdsInstanceRegion
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.IamAuth.Username)
		socket.ConnectorLocalData.AwsCredentials = config.IamAuth.AwsCredentials
		if config.IamAuth.CaCertificate != "" {
			socket.ConnectorLocalData.UpstreamCACertBlock = []byte(u.fetchVariableFromSource(config.IamAuth.CaCertificate))
		}
	}

	return nil
}

func (u *UpstreamDataBuilder) buildUpstreamDataForDatabaseServiceGcpCloudSql(socket *models.Socket, config *service.GcpCloudSqlDatabaseServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got database service with no Google Cloud SQL database service configuration")
	}

	hostname, port := u.fetchVariableFromSource(config.Hostname), int(config.Port)
	socket.UpstreamType = config.DatabaseProtocol
	socket.ConnectorData.TargetHostname = hostname
	socket.ConnectorData.Port = port
	socket.TargetHostname = hostname
	socket.TargetPort = port

	switch {
	case config.UsernameAndPasswordAuth != nil:
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.UsernameAndPasswordAuth.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.UsernameAndPasswordAuth.Password)
	case config.TlsAuth != nil:
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.TlsAuth.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.TlsAuth.Password)
		socket.ConnectorLocalData.UpstreamCertBlock = []byte(u.fetchVariableFromSource(config.TlsAuth.Certificate))
		socket.ConnectorLocalData.UpstreamKeyBlock = []byte(u.fetchVariableFromSource(config.TlsAuth.Key))
		if config.TlsAuth.CaCertificate != "" {
			socket.ConnectorLocalData.UpstreamCACertBlock = []byte(u.fetchVariableFromSource(config.TlsAuth.CaCertificate))
		}
	case config.GcpCloudSQLConnectorAuth != nil:
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.GcpCloudSQLConnectorAuth.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.GcpCloudSQLConnectorAuth.Password)
		socket.ConnectorLocalData.CloudSQLInstance = u.fetchVariableFromSource(config.GcpCloudSQLConnectorAuth.InstanceId)
		socket.ConnectorLocalData.GoogleCredentialsJSON = []byte(u.fetchVariableFromSource(config.GcpCloudSQLConnectorAuth.GcpCredentialsJson))
		socket.ConnectorLocalData.CloudSQLConnector = true
	case config.GcpCloudSQLConnectorIAMAuth != nil:
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.GcpCloudSQLConnectorIAMAuth.Username)
		socket.ConnectorLocalData.CloudSQLInstance = u.fetchVariableFromSource(config.GcpCloudSQLConnectorIAMAuth.InstanceId)
		socket.ConnectorLocalData.GoogleCredentialsJSON = []byte(u.fetchVariableFromSource(config.GcpCloudSQLConnectorIAMAuth.GcpCredentialsJson))
		socket.ConnectorLocalData.CloudSQLConnector = true
		socket.ConnectorLocalData.CloudSQLIAMAuth = true
	}

	return nil
}

func (u *UpstreamDataBuilder) buildUpstreamDataForDatabaseServiceAzureSql(socket *models.Socket, config *service.AzureSqlDatabaseServiceConfiguration) error {
	if config == nil {
		return fmt.Errorf("got database service with no Microsoft Azure SQL database service configuration")
	}

	hostname, port := u.fetchVariableFromSource(config.Hostname), int(config.Port)
	socket.UpstreamType = config.DatabaseProtocol
	socket.ConnectorData.TargetHostname = hostname
	socket.ConnectorData.Port = port
	socket.TargetHostname = hostname
	socket.TargetPort = port

	switch {
	case config.AzureActiveDirectoryIntegrated != nil:
		socket.ConnectorLocalData.AzureAD = true
	case config.AzureActiveDirectoryPassword != nil:
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.AzureActiveDirectoryPassword.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.AzureActiveDirectoryPassword.Password)
		socket.ConnectorLocalData.AzureAD = true
	case config.Kerberos != nil:
		socket.ConnectorLocalData.Kerberos = true
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.Kerberos.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.Kerberos.Password)
	case config.SqlAuthentication != nil:
		socket.ConnectorLocalData.UpstreamUsername = u.fetchVariableFromSource(config.SqlAuthentication.Username)
		socket.ConnectorLocalData.UpstreamPassword = u.fetchVariableFromSource(config.SqlAuthentication.Password)
	}

	return nil
}
