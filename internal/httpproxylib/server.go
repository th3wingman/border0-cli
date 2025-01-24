package httpproxylib

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"go.uber.org/zap"

	"github.com/borderzero/border0-cli/internal/border0"
)

// httpRequestContextKey represents a custom context key type.
type httpRequestContextKey string

const (
	connContextKey httpRequestContextKey = "connection"
)

// HttpProxyConfig represents http reverse proxy configuration.
type HttpProxyConfig struct {
	logger *zap.Logger
	socket *border0.Socket
	server *http.Server
}

// BuildProxyConfig builds the Kubernetes API reverse proxy configuration.
func BuildConfig(
	ctx context.Context,
	logger *zap.Logger,
	api border0.Border0API,
	socket *border0.Socket,
) (*HttpProxyConfig, error) {
	if !socket.PrivateNetworkEnabled {
		return nil, nil
	}

	handler, err := getHandler(logger, api, socket)
	if err != nil {
		return nil, fmt.Errorf("failed to build http reverse proxy handler: %v", err)
	}
	return &HttpProxyConfig{
		logger: logger,
		socket: socket,
		server: &http.Server{
			Handler: handler,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connContextKey, c)
			},
		},
	}, nil
}

// Serve serves the reverse proxy over the listener.
func Serve(listener net.Listener, config *HttpProxyConfig) error {
	return config.server.Serve(listener)
}
