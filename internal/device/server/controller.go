package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/borderzero/border0-cli/internal/device"
	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"go.uber.org/zap"
)

const (
	unknownErr = "an unknown error occurred... try again later"
)

type PayloadServiceStatus struct {
	Running bool `json:"running"`
}

type PayloadVPNPeersStatus struct {
	Peers []stats.Peer `json:"peers"`
}

type PayloadExitNode struct {
	ExitNode string `json:"exit_node"`
}

type controller struct {
	logger  *zap.Logger
	service device.Service
	state   state.State
	version string
}

func newController(
	logger *zap.Logger,
	service device.Service,
	state state.State,
	version string,
) *controller {
	return &controller{
		logger:  logger,
		service: service,
		state:   state,
		version: version,
	}
}

func (ctrl *controller) getVersion(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(`{"version":"%s"}`, ctrl.version)))
}

func (ctrl *controller) getProfile(w http.ResponseWriter, r *http.Request) {
	profile := ctrl.state.GetProfile()
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(
		fmt.Sprintf(
			`{"profileImageURL":"%s","profileName":"%s","profileEmail":"%s","profileOrgSubdomain":"%s"}`,
			profile.ImageURL,
			profile.Name,
			profile.Email,
			profile.OrgSubdomain,
		),
	))
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

func (ctrl *controller) putVpnStatus(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		ctrl.logger.Error("failed to read request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}

	var payload PayloadServiceStatus
	if err = json.Unmarshal(bodyBytes, &payload); err != nil {
		ctrl.logger.Error("failed to JSON-decode request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}

	if ctrl.service != nil {
		if payload.Running {
			if err := ctrl.service.StartVPN(); err != nil {
				ctrl.logger.Error("failed to start VPN service", zap.Error(err))
			}
		} else {
			if err := ctrl.service.StopVPN(); err != nil {
				ctrl.logger.Error("failed to start VPN service", zap.Error(err))
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

func (ctrl *controller) getVpnStatus(w http.ResponseWriter, _ *http.Request) {
	if ctrl.service == nil {
		w.Write([]byte(`{"running":false}`))
		return
	}

	running, err := ctrl.service.Status()
	if err != nil {
		ctrl.logger.Error("failed to get VPN status", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}

	w.Write([]byte(fmt.Sprintf(`{"running":%v}`, running)))
}

func (ctrl *controller) getVpnStats(w http.ResponseWriter, _ *http.Request) {
	respBytes, err := json.Marshal(ctrl.service.GetVpnStats())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to encode response: %v", err.Error())))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (ctrl *controller) getVpnWireGuardStatus(w http.ResponseWriter, _ *http.Request) {
	if strings.ToLower(os.Getenv("BORDER0_EXPOSE_WG_CONFIG")) != "true" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("the node server must be ran with env BORDER0_EXPOSE_WG_CONFIG=true in order to expose WireGuard config"))
		return
	}

	data, err := ctrl.service.GetWireGuardConfig()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to get VPN wireguard status from service: %v", err.Error())))
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

func (ctrl *controller) getVpnPeersStatus(w http.ResponseWriter, _ *http.Request) {
	peers, err := ctrl.service.GetVpnPeers()
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

func (ctrl *controller) getVpnExitNode(w http.ResponseWriter, _ *http.Request) {
	output := map[string]string{
		"exit_node": ctrl.service.GetExitNode(),
	}

	respBytes, err := json.Marshal(output)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to encode response: %v", err.Error())))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (ctrl *controller) getVpnExitNodes(w http.ResponseWriter, _ *http.Request) {
	if ctrl.service == nil {
		w.Write([]byte(`{"error":"VPN service is not running"}`))
		return
	}

	running, err := ctrl.service.Status()
	if err != nil {
		ctrl.logger.Error("failed to get VPN status", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}

	if !running {
		w.Write([]byte(`{"error":"VPN is not connected"}`))
		return
	}

	output := map[string][]string{
		"exit_nodes": ctrl.service.GetExitNodes(),
	}

	respBytes, err := json.Marshal(output)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed to encode response: %v", err.Error())))
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

func (ctrl *controller) putVpnExitNode(w http.ResponseWriter, r *http.Request) {
	if ctrl.service == nil {
		w.Write([]byte(`{"error":"VPN service is not running"}`))
		return
	}

	running, err := ctrl.service.Status()
	if err != nil {
		ctrl.logger.Error("failed to get VPN status", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}

	if !running {
		w.Write([]byte(`{"error":"VPN is not connected"}`))
		return
	}

	defer r.Body.Close()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		ctrl.logger.Error("failed to read request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}

	var payload PayloadExitNode
	if err = json.Unmarshal(bodyBytes, &payload); err != nil {
		ctrl.logger.Error("failed to JSON-decode request body", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(unknownErr))
		return
	}

	if err := ctrl.service.SetExitNode(payload.ExitNode); err != nil {
		ctrl.logger.Error("failed to set exit node", zap.Error(err))
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(jsonError(err.Error()))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
