package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/borderzero/border0-cli/internal/device"
	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const (
	PathState          = "state"
	PathVersion        = "version"
	PathProfile        = "profile"
	PathVpnStatus      = "vpn/status"
	PathVpnStats       = "vpn/stats"
	PathVpnWGStatus    = "vpn/wg/status"
	PathVpnPeersStatus = "vpn/peers/status"
	PathExitNode       = "vpn/exit-node"
	PathExitNodes      = "vpn/exit-nodes"
)

type Server interface {
	Serve(net.Listener) error
	Shutdown(context.Context) error
}

type server struct {
	logger  *zap.Logger
	service device.Service
	server  *http.Server
}

func New(
	logger *zap.Logger,
	service device.Service,
	state state.State,
	version string,
) *server {
	ctrl := newController(logger, service, state, version)

	r := mux.NewRouter()

	// Define routes
	r.Path(fmt.Sprintf("/%s", PathState)).Methods(http.MethodGet).HandlerFunc(ctrl.getState)
	r.Path(fmt.Sprintf("/%s", PathVersion)).Methods(http.MethodGet).HandlerFunc(ctrl.getVersion)
	r.Path(fmt.Sprintf("/%s", PathProfile)).Methods(http.MethodGet).HandlerFunc(ctrl.getProfile)
	r.Path(fmt.Sprintf("/%s", PathVpnStatus)).Methods(http.MethodPut).HandlerFunc(ctrl.putVpnStatus)
	r.Path(fmt.Sprintf("/%s", PathVpnStatus)).Methods(http.MethodGet).HandlerFunc(ctrl.getVpnStatus)
	r.Path(fmt.Sprintf("/%s", PathVpnStats)).Methods(http.MethodGet).HandlerFunc(ctrl.getVpnStats)
	r.Path(fmt.Sprintf("/%s", PathVpnWGStatus)).Methods(http.MethodGet).HandlerFunc(ctrl.getVpnWireGuardStatus)
	r.Path(fmt.Sprintf("/%s", PathVpnPeersStatus)).Methods(http.MethodGet).HandlerFunc(ctrl.getVpnPeersStatus)
	r.Path(fmt.Sprintf("/%s", PathExitNode)).Methods(http.MethodGet).HandlerFunc(ctrl.getVpnExitNode)
	r.Path(fmt.Sprintf("/%s", PathExitNode)).Methods(http.MethodPut).HandlerFunc(ctrl.putVpnExitNode)
	r.Path(fmt.Sprintf("/%s", PathExitNodes)).Methods(http.MethodGet).HandlerFunc(ctrl.getVpnExitNodes)

	return &server{
		logger:  logger,
		service: service,
		server: &http.Server{
			Handler:           r,
			ReadTimeout:       20 * time.Second,
			WriteTimeout:      20 * time.Second,
			IdleTimeout:       30 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

func (s *server) Serve(l net.Listener) error {
	return s.server.Serve(l)
}

func (s *server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
