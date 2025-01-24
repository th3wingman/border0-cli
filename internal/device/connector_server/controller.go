package connector_server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-cli/internal/device/wgmgr"
	"go.uber.org/zap"
)

const (
	unknownErr = "an unknown error occurred... try again later"
)

type PayloadVPNPeersStatus struct {
	Peers []stats.Peer `json:"peers"`
}

type controller struct {
	logger  *zap.Logger
	wgmr    wgmgr.WireGuardManager
	state   state.State
	version string
}

func newController(
	logger *zap.Logger,
	wgmr wgmgr.WireGuardManager,
	state state.State,
	version string,
) *controller {
	return &controller{
		logger:  logger,
		wgmr:    wgmr,
		state:   state,
		version: version,
	}
}

func (ctrl *controller) getVersion(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"version":"%s"}`, ctrl.version)))
}

func (ctrl *controller) getState(w http.ResponseWriter, r *http.Request) {
	stateJSON, err := ctrl.state.MarshalJSON()
	if err != nil {
		ctrl.logger.Error("failed to marshal state json", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(stateJSON)
}

func (ctrl *controller) getVpnWireGuardStatus(w http.ResponseWriter, _ *http.Request) {
	if strings.ToLower(os.Getenv("BORDER0_EXPOSE_WG_CONFIG")) != "true" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("the node server must be ran with env BORDER0_EXPOSE_WG_CONFIG=true in order to expose WireGuard config"))
		return
	}

	data, err := ctrl.wgmr.GetWireGuardConfig()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to get VPN wireguard status from service: %v", err.Error())))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

func (ctrl *controller) getVpnPeersStatus(w http.ResponseWriter, _ *http.Request) {
	peers, err := ctrl.wgmr.GetPeerStats()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to get VPN peers from service: %v", err.Error())))
		return
	}
	respBytes, err := json.Marshal(PayloadVPNPeersStatus{Peers: peers})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to encode response: %v", err.Error())))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (ctrl *controller) getVpnStats(w http.ResponseWriter, _ *http.Request) {
	respBytes, err := json.Marshal(ctrl.wgmr.GetStats())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to encode response: %v", err.Error())))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// jsonError returns JSON for an error message.
func jsonError(msg string) []byte {
	return []byte(fmt.Sprintf(`{"error": "%s"}`, msg))
}
