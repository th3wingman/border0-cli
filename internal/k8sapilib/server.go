package k8sapilib

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/util/deaconn"
	"github.com/borderzero/border0-cli/internal/util/refresher"
	"go.uber.org/zap"

	proxyproto "github.com/pires/go-proxyproto"
)

const (
	certRefresherRetryPeriod            = time.Minute * 15
	policyEvaluatorCacheJanitorInterval = time.Minute * 5
	policyEvaluatorCacheTTL             = time.Second * 30
)

// KubernetesProxyConfig represents kubernetes api reverse proxy configuration.
type KubernetesProxyConfig struct {
	logger *zap.Logger
	socket *border0.Socket
	server *http.Server
}

// BuildProxyConfig builds the Kubernetes API reverse proxy configuration.
func BuildProxyConfig(
	ctx context.Context,
	logger *zap.Logger,
	api border0.Border0API,
	socket *border0.Socket,
	refresh refresher.RefreshFunc,
) (*KubernetesProxyConfig, error) {
	certRefresher, err := refresher.New(socket.GetContext(), logger, certRefresherRetryPeriod, refresh)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize certificate refresher: %v", err)
	}
	tlsConfig, err := tlsConfig(socket, certRefresher)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubernetes api reverse proxy TLS configuration: %v", err)
	}
	handler, err := getHandler(ctx, logger, api, socket, policyEvaluatorCacheJanitorInterval, policyEvaluatorCacheTTL)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes api reverse proxy handler: %v", err)
	}
	return &KubernetesProxyConfig{
		logger: logger,
		socket: socket,
		server: &http.Server{
			Handler:   handler,
			TLSConfig: tlsConfig,
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				return context.WithValue(ctx, connContextKey, c)
			},
		},
	}, nil
}

// Serve serves the reverse proxy over the listener.
func Serve(listener net.Listener, config *KubernetesProxyConfig) error {
	if config.socket.PrivateNetworkEnabled {
		return config.server.Serve(listener)
	}

	// TL;DR; need a dummy listener to make exec work...
	//
	// Without a dummy listener, the underlying net.Conn is an ssh.Conn (golang.org/x/crypto/ssh).
	// This is a problem because ssh.Conn does not pay attention to deadlines, resulting in an
	// inability for those connections to be hijacked via http.Hijacker (net/http), which means
	// they do not support WebSockets, which means we can't have a kubectl exec over them!
	//
	// More info:
	// - There's a generic open issue with Go upstream: https://github.com/golang/go/issues/65930
	// - There's a specific issue with Go upstream: https://github.com/golang/go/issues/67152
	// - The problematic code is in https://go.googlesource.com/crypto/+/master/ssh/tcpip.go
	// - There's a fix that works for us in https://go-review.googlesource.com/c/crypto/+/562756
	dummy := deaconn.NewListenerWithDeadlines(listener)
	defer dummy.Close()

	proxyListener := &proxyproto.Listener{Listener: dummy}
	defer proxyListener.Close()

	return config.server.ServeTLS(proxyListener, "", "")
}
