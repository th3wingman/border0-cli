package sqlauthproxy

import (
	"github.com/borderzero/border0-cli/internal/api/models"
	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/server"
	"go.uber.org/zap"
)

type mysqlEmptyHandler struct {
	logger *zap.Logger
	server.EmptyHandler
	database   string
	clientConn *client.Conn
	border0API border0.Border0API
}

var _ server.Handler = &mysqlEmptyHandler{}

func (h *mysqlEmptyHandler) UseDB(dbName string) error {
	h.database = dbName

	return h.clientConn.UseDB(dbName)
}

func (h *mysqlEmptyHandler) Database() string {
	return h.database
}

func (h *mysqlEmptyHandler) HandleConnection(serverConn *server.Conn) {
	border0.ProxyConnection(serverConn.Conn.Conn, h.clientConn.Conn.Conn)
}

func (h *mysqlEmptyHandler) ErrorEvent(eventType, message string) error {
	h.logger.Error("error event", zap.String("event", eventType), zap.String("message", message))
	return nil
}

func (h *mysqlEmptyHandler) ClientConn(clientConn *client.Conn) {
	h.clientConn = clientConn
}

func (h *mysqlEmptyHandler) CreateSessionEvent(e models.SessionEvent) error {
	return h.border0API.CreateSessionEvent(e)
}
