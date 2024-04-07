package sqlclientproxy

import (
	"crypto/tls"
	"fmt"

	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/client"
	"go.uber.org/zap"
)

type SqlClientProxy interface {
	Listen() error
}

type sqlClientProxy struct {
	port       int
	info       client.ResourceInfo
	resource   models.ClientResource
	tlsConfig  *tls.Config
	useWsProxy bool
}

func NewSqlClientProxy(logger *zap.Logger, port int, resource models.ClientResource, useWsProxy bool) (SqlClientProxy, error) {
	switch resource.DatabaseType {
	case "mysql":
		return newMysqlClientProxy(logger, port, resource, useWsProxy)
	case "postgres":
		return newPostgresClientProxy(logger, port, resource, useWsProxy)
	case "mssql":
		return newTcpProxy(logger, port, resource, useWsProxy)
	default:
		return nil, fmt.Errorf("unsupported database type: %s", resource.DatabaseType)
	}
}
