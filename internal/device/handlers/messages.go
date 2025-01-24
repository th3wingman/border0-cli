package handlers

import (
	"fmt"

	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/device/wg/endpoint"
	"github.com/borderzero/border0-cli/internal/device/wgmgr"
	b0service "github.com/borderzero/border0-go/types/service"
	"github.com/borderzero/border0-proto/common"
	"github.com/borderzero/border0-proto/device"
	"go.uber.org/zap"
)

// HandlePeerOfflineMessage handles the "peer offline" message.
func HandlePeerOfflineMessage(
	logger *zap.Logger,
	state state.State,
	peerMap endpoint.Mapping,
	wgmgr wgmgr.WireGuardManager,
	message *common.PeerOfflineMessage,
) error {
	pub := message.GetPeerPublicKey()

	logger.Info(
		"got a peer offline",
		zap.String("network_id", message.GetNetworkId()),
		zap.String("public_key", pub),
	)
	var hadExitNode bool

	// remove from state last
	defer func() {
		err := state.
			RemoveWireGuardPeer(pub).
			Commit()
		if err != nil {
			logger.Error("failed to commit state after removing wireguard peer", zap.Error(err))
			// best effort commit, fallthrough
		}

		if hadExitNode {
			if err := wgmgr.UpdateExitNodeRoutes(); err != nil {
				logger.Sugar().Errorf("failed to update exit node: %v", err)
			}
		}
	}()

	// remove from mapping second to last
	defer func() {
		if present, ok := peerMap.GetByPub(pub); ok {
			peerMap.DeleteByPub(pub)
			endpoint.StopQOSChecks(present) // NOTE: without this line we have a memory leak!
		}
	}()

	if wgmgr.GetExitNode() != "" {
		peers := state.GetWireGuardPeers()
		for _, peer := range peers {
			if peer.PublicKey == pub {
				for _, service := range peer.Services {
					if service.Name == wgmgr.GetExitNode() && service.Type == b0service.ServiceTypeExitNode {
						hadExitNode = true
						break
					}
				}
				break
			}
		}
	}

	if err := wgmgr.RemovePeerIfRunning(pub); err != nil {
		return fmt.Errorf("failed to configure peers: %v", err)
	}

	return nil
}

// HandlePeerOnlineMessage handles the "peer online" message.
func HandlePeerOnlineMessage(
	logger *zap.Logger,
	state state.State,
	wgmgr wgmgr.WireGuardManager,
	message *common.PeerOnlineMessage,
) error {
	peer := message.GetPeer()

	logger.Info(
		"got new peer online",
		zap.String("network_id", message.GetNetworkId()),
		zap.String("endpoint_public_udp4", peer.GetPublicUdp4Endpoint()),
		zap.String("public_key", peer.GetPublicKey()),
		zap.String("ipv4", peer.GetIpv4()),
		zap.String("ipv6", peer.GetIpv6()),
		zap.Any("services", peer.GetServices()),
	)

	err := state.
		SetWireGuardPeer(peer).
		Commit()
	if err != nil {
		logger.Error("failed to commit state after adding wireguard peer", zap.Error(err))
		// best effort commit, fallthrough
	}

	if err := wgmgr.RefreshPeerIfRunning(peer.PublicKey); err != nil {
		return fmt.Errorf("failed to configure peers: %v", err)
	}
	return nil
}

// HandleNetworkStateMessage handles the "network state" message.
func HandleNetworkStateMessage(
	logger *zap.Logger,
	state state.State,
	wgmgr wgmgr.WireGuardManager,
	message *common.NetworkStateMessage,
) error {
	logger.Info(
		"got network state",
		zap.String("network_id", message.GetNetworkId()),
		zap.String("ipv4", message.GetSelfIpv4()),
		zap.String("ipv6", message.GetSelfIpv6()),
		zap.String("devices_cidr_v4", message.GetNetworkCidrV4()),
		zap.String("devices_cidr_v6", message.GetNetworkCidrV6()),
		zap.String("resources_cidr_v4", message.GetNetworkResourcesCidrV4()),
		zap.String("resources_cidr_v6", message.GetNetworkResourcesCidrV6()),
		zap.Any("peers", message.GetOnlinePeers()),
	)

	err := state.
		SetWireGuardPeers(message.GetOnlinePeers()).
		SetNetworkIPs(
			message.GetSelfIpv4(),
			message.GetSelfIpv6(),
			message.GetNetworkCidrV4(),
			message.GetNetworkCidrV6(),
			message.GetNetworkResourcesCidrV4(),
			message.GetNetworkResourcesCidrV6(),
		).
		Commit()
	if err != nil {
		logger.Error("failed to commit state after updating wireguard peers", zap.Error(err))
		// best effort commit, fallthrough
	}

	if err := wgmgr.RefreshIfRunning(); err != nil {
		return fmt.Errorf("failed to configure peers: %v", err)
	}
	return nil
}

func HandleServiceMessage(
	logger *zap.Logger,
	state state.State,
	wgmgr wgmgr.WireGuardManager,
	message *device.Service,
) error {
	logger.Info(
		"got service message",
		zap.String("network_id", message.GetNetworkId()),
		zap.String("service_name", message.GetName()),
		zap.String("service_type", message.GetType()),
		zap.String("service_ipv4", message.GetIpv4()),
		zap.String("service_ipv6", message.GetIpv6()),
		zap.Any("service_public_key", message.GetPeerPublicKey()),
		zap.Any("service_subnet_routes", message.GetSubnetRoutes()),
	)

	keyMap := make(map[string]bool)
	for _, publicKey := range message.GetPeerPublicKey() {
		keyMap[publicKey] = true
	}

	peers := state.GetWireGuardPeers()
	for _, peer := range peers {
		found := false
		needsRefresh := false
		for _, service := range peer.Services {
			if service.Name == message.GetName() {
				found = true
				if _, ok := keyMap[peer.PublicKey]; !ok {
					if err := state.RemoveService(peer, message).Commit(); err != nil {
						logger.Error("failed to remove service from peer", zap.Error(err))
					} else {
						needsRefresh = true
					}
				} else {
					if state, changed := state.UpdateService(peer, message); changed {
						if err := state.Commit(); err != nil {
							logger.Error("failed to update service from peer", zap.Error(err))
						} else {
							needsRefresh = true
						}
					}
				}
			}
		}

		if !found {
			if _, ok := keyMap[peer.PublicKey]; ok {
				if err := state.AddService(peer, message).Commit(); err != nil {
					logger.Error("failed to add service to peer", zap.Error(err))
				} else {
					needsRefresh = true
				}
			}
		}

		if needsRefresh {
			if err := wgmgr.RefreshPeerIfRunning(peer.PublicKey); err != nil {
				return fmt.Errorf("failed to configure peers: %v", err)
			}
		}
	}

	if message.GetName() == wgmgr.GetExitNode() {
		if err := wgmgr.UpdateExitNodeRoutes(); err != nil {
			return fmt.Errorf("failed to update exit node routes %v", err)
		}
	}

	return nil
}
