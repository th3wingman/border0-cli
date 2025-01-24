package sqlauthproxy

import (
	"net"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/jackc/pgconn"
	"go.uber.org/zap"
)

type postgresCopyyHandler struct {
	serverConn net.Conn
	logger     *zap.Logger
}

func (h *postgresCopyyHandler) HandleConnection(clientConn *pgconn.HijackedConn) {
	border0.ProxyConnection(h.serverConn, clientConn.Conn)
}

func (h *postgresCopyyHandler) ErrorEvent(eventType, message string) error {
	h.logger.Error("error event", zap.String("event", eventType), zap.String("message", message))
	return nil
}
