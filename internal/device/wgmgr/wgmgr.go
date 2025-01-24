package wgmgr

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"go.uber.org/atomic"
	"go.uber.org/zap"

	"github.com/borderzero/border0-cli/internal/device/network"
	"github.com/borderzero/border0-cli/internal/device/state"
	"github.com/borderzero/border0-cli/internal/device/utils/asyncio"
	"github.com/borderzero/border0-cli/internal/device/utils/gwtrack"
	"github.com/borderzero/border0-cli/internal/device/utils/nat"
	"github.com/borderzero/border0-cli/internal/device/utils/routes"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-cli/internal/device/wg/bind"
	"github.com/borderzero/border0-cli/internal/device/wg/endpoint"
	"github.com/borderzero/border0-cli/internal/device/wg/qos"
	"github.com/borderzero/border0-cli/internal/device/wg/tundev"
	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/lib/types/slice"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"github.com/borderzero/border0-go/types/service"
	"github.com/borderzero/turtle"
	"github.com/borderzero/wireguard-go/device"
	"github.com/borderzero/wireguard-go/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	defaultPingProbes   = 10
	defaultPingInterval = time.Millisecond * 250
	maxUtunValue        = 300

	defaultDnsResolutionTimeout = time.Second * 10

	oneByteBits = 8
	ipv4Bits    = 4 * oneByteBits
	ipv6Bits    = 16 * oneByteBits
)

type WireGuardManager interface {
	Start() error
	RefreshIfRunning() error
	RefreshPeerIfRunning(string) error
	RemovePeerIfRunning(string) error

	Stop() error
	Close() error
	GetPublicIPv4Address() *net.UDPAddr
	GetPublicIPv6Address() *net.UDPAddr
	IsRunning() bool
	SocketListener(address string) (net.Listener, error)
	GetPeerIP(pub string) (*netip.Addr, error)
	GetWireGuardConfig() (string, error)
	GetPeerStats() ([]stats.Peer, error)
	GetStats() *stats.Stats
	GetExitNode() string
	GetExitNodes() []string
	SetExitNode(string) error
	UpdateExitNodeRoutes() error
}

type wireGuardManager struct {
	setup *sync.Once

	logger    *zap.Logger
	state     state.State
	wgKey     *wgtypes.Key
	wgPort    int
	ifaceName string
	natMgr    nat.NATManager
	rm        routes.RouteManager
	gwtracker gwtrack.Tracker

	peerMap endpoint.Mapping
	wgBind  *bind.Bind

	udp4Addr            *atomic.Pointer[net.UDPAddr]
	udp6Addr            *atomic.Pointer[net.UDPAddr]
	onAddressChangeChan chan<- *DiscoverabilityAnnouncement

	mu           *sync.RWMutex
	isRunning    *atomic.Bool
	tunDevice    tun.Device
	realworldTUN tun.Device
	netstackTUN  tun.Device
	wgDevice     *device.Device

	qosDisallowedSourcesV4 []netip.Prefix
	qosDisallowedSourcesV6 []netip.Prefix

	netstackNet          *network.Net
	netstackStack        *stack.Stack
	localSocketAddrPorts *syncmap.Map[string, set.Set[uint16]]

	isConnector       bool
	bypassRoutes      set.Set[netip.Addr]
	needsBypassRoutes *atomic.Bool
	hostLock          sync.Mutex
	stats             stats.Tracker
}

type socketListener struct {
	*gonet.TCPListener
	netstackStack *stack.Stack
	cleanup       func()
}

// DiscoverabilityAnnouncement represents a message from the device to other
// peers through a side channel (e.g. the border0 api) incl. the self-discovered
// public addresses and whether it is willing to peer with others or not.
type DiscoverabilityAnnouncement struct {
	Discoverable bool
	UDP4Address  *net.UDPAddr
	UDP6Address  *net.UDPAddr
}

func New(
	logger *zap.Logger,
	state state.State,
	stats stats.Tracker,
	peerMap endpoint.Mapping,
	ifaceName string,
	relayURL string,
	// onAddressChange func(*DiscoverabilityAnnouncement),
	onAddressChangeChan chan<- *DiscoverabilityAnnouncement,
	isConnector bool,
	wgPort int,
) (WireGuardManager, error) {
	// TODO: clean-up state e.g. wipe interfaces, routes, etc...
	wgKey, err := wgtypes.ParseKey(base64.StdEncoding.EncodeToString(state.GetPrivateKey().Raw()[:]))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	naclKey, err := nacl.ParsePrivateKey(wgKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key as nacl key: %v", err)
	}

	tunInterface, err := findAvailableTunName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find available TUN interface name: %v", err)
	}
	if tunInterface != ifaceName {
		logger.Info("the current tun interface already exists, switching to use a different TUN interface name",
			zap.String("iface", tunInterface),
			zap.String("old_iface", ifaceName))
	}

	netstackTUN, netstackNet, netstackStack, err := network.CreateNetTUNWithStack(network.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create virtual (netstack) TUN device for sockets: %v", err)
	}

	realworldTUN, err := tun.CreateTUN(tunInterface, network.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface", tunInterface, fmt.Sprintf("mtu=%d", network.DefaultMTU))
		if output, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to set MTU on Windows: %v, output: %s", err, output)
		}

		cmd = exec.Command("netsh", "interface", "ipv6", "set", "subinterface", tunInterface, fmt.Sprintf("mtu=%d", network.DefaultMTU))
		if output, err := cmd.CombinedOutput(); err != nil {
			return nil, fmt.Errorf("failed to set IPv6 MTU on Windows: %v, output: %s", err, output)
		}
	}

	if err = state.AddManagedInterface(tunInterface).Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit state after adding managed interface %s: %v", tunInterface, err)
	}

	realworldReader, err := asyncio.NewReader(logger, realworldTUN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize availability reader for real world TUN device: %v", err)
	}

	netstackReader, err := asyncio.NewNetstackReader(logger, netstackTUN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize availability reader for virtual (netstack) TUN device for sockets: %v", err)
	}

	thisPeerCIDRv4, thisPeerCIDRv6, devicesNetworkCIDRv4, devicesNetworkCIDRv6, resourcesNetworkCIDRv4, resourcesNetworkCIDRv6 := state.GetNetworkIPs()
	selfv4, _, err := net.ParseCIDR(thisPeerCIDRv4)
	if err != nil {
		return nil, fmt.Errorf("failed to parse local Border0-network IPv4 address /32 %s: %v", thisPeerCIDRv4, err)
	}
	selfv6, _, err := net.ParseCIDR(thisPeerCIDRv6)
	if err != nil {
		return nil, fmt.Errorf("failed to parse local Border0-network IPv6 address /128 %s: %v", thisPeerCIDRv6, err)
	}
	devicesNetworkPrefixV4, err := netip.ParsePrefix(devicesNetworkCIDRv4)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Border0-network devices IPv4 CIDR %s: %v", devicesNetworkCIDRv4, err)
	}
	devicesNetworkPrefixV6, err := netip.ParsePrefix(devicesNetworkCIDRv6)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Border0-network devices IPv6 CIDR %s: %v", devicesNetworkCIDRv6, err)
	}
	resourcesNetworkPrefixV4, err := netip.ParsePrefix(resourcesNetworkCIDRv4)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Border0-network resources IPv4 CIDR %s: %v", resourcesNetworkCIDRv4, err)
	}
	resourcesNetworkPrefixV6, err := netip.ParsePrefix(resourcesNetworkCIDRv6)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Border0-network resources IPv6 CIDR %s: %v", resourcesNetworkCIDRv6, err)
	}

	localSocketAddrPorts := syncmap.New[string, set.Set[uint16]]()
	customTUN := tundev.New(
		logger,
		selfv4.String(),
		selfv6.String(),
		devicesNetworkPrefixV4,
		devicesNetworkPrefixV6,
		resourcesNetworkPrefixV4,
		resourcesNetworkPrefixV6,
		"",
		realworldTUN,
		netstackTUN,
		realworldReader.C(),
		netstackReader.C(),
		localSocketAddrPorts,
		stats,
	)
	rm := routes.NewManager(logger)

	wgm := &wireGuardManager{
		setup:     &sync.Once{},
		logger:    logger,
		state:     state,
		wgKey:     &wgKey,
		wgPort:    wgPort,
		ifaceName: tunInterface,
		rm:        rm,
		gwtracker: gwtrack.NewTracker(logger, rm),
		peerMap:   peerMap,

		udp4Addr:            atomic.NewPointer[net.UDPAddr](nil),
		udp6Addr:            atomic.NewPointer[net.UDPAddr](nil),
		onAddressChangeChan: onAddressChangeChan,

		mu:           &sync.RWMutex{},
		isRunning:    atomic.NewBool(false),
		tunDevice:    customTUN,
		realworldTUN: realworldTUN,
		netstackTUN:  netstackTUN,

		// disallow receiving QOS messages over the device/resource ranges so as to prevent
		// trying unoptimal paths e.g. roaming udp4 over relay, roaming udp4 over udp6, etc.
		qosDisallowedSourcesV4: []netip.Prefix{devicesNetworkPrefixV4, resourcesNetworkPrefixV4},
		qosDisallowedSourcesV6: []netip.Prefix{devicesNetworkPrefixV6, resourcesNetworkPrefixV6},

		netstackNet:          netstackNet,
		netstackStack:        netstackStack,
		localSocketAddrPorts: localSocketAddrPorts,

		isConnector:  isConnector,
		bypassRoutes: set.NewConcurrencySafe(determineBypassAddresses(logger, defaultDnsResolutionTimeout, relayURL)...),

		// NOTE: the needsBypassRoutes flag tells other portions of the code if there
		// is at least one subnet router service and so we must set up bypass routes.
		needsBypassRoutes: atomic.NewBool(false),

		stats: stats,
	}

	// set natmgr if applicable (e.g. if its a connector)
	if wgm.isConnector {
		natMgr, err := nat.NewManager(logger)
		if err != nil {
			return nil, fmt.Errorf("failed to create NAT manager: %v", err)
		}
		wgm.natMgr = natMgr
	}

	// set bind
	bindDisallowedSources := []netip.Prefix{
		devicesNetworkPrefixV4,
		resourcesNetworkPrefixV4,
		devicesNetworkPrefixV6,
		resourcesNetworkPrefixV6,
	}
	wgBind := bind.New(logger, naclKey, relayURL, peerMap, wgm.receiveSTUN, bindDisallowedSources, uint16(wgPort))
	wgm.wgBind = wgBind

	// set wireguard device
	wglogLevel := device.LogLevelError
	if strings.ToLower(os.Getenv("BORDER0_VERY_VERBOSE")) == "true" {
		wglogLevel = device.LogLevelVerbose
	}
	dlogger := device.NewLogger(wglogLevel, fmt.Sprintf("(%s) ", tunInterface))
	wgDevice := device.NewDevice(customTUN, wgBind, &device.Logger{Verbosef: dlogger.Verbosef, Errorf: dlogger.Errorf})
	wgm.wgDevice = wgDevice
	if err := wgm.init(); err != nil {
		// we cannot proceed if we cannot set config on the wireguard device object.
		return nil, fmt.Errorf("failed to set initial configuration on wireguard manager: %v", err)
	}

	// best effort route cleanup before starting
	wgm.cleanupManagedRoutes("")

	if wgm.isConnector {
		// cleanup NAT rules
		wgm.cleanupNatRules()
		// setup ingress iptables rules
		if err := wgm.natMgr.SetupIPv4WireGuardIngress(wgPort); err != nil {
			logger.Error("failed to setup udp-over-ipv4 ingress iptables rule", zap.Int("port", wgPort), zap.Error(err))
		} else {
			logger.Info("successfully setup udp-over-ipv4 ingress iptables rule", zap.Int("port", wgPort))
		}
		if err := wgm.natMgr.SetupIPv6WireGuardIngress(wgPort); err != nil {
			logger.Error("failed to setup udp-over-ipv6 ingress iptables rule", zap.Int("port", wgPort), zap.Error(err))
		} else {
			logger.Info("successfully setup udp-over-ipv6 ingress iptables rule", zap.Int("port", wgPort))
		}
	}

	// kick off monitoring for default gateway changes
	// and re-set bypass routes appropriately.
	if !wgm.isConnector {
		go func() {
			gatewayUpdates := wgm.gwtracker.Subscribe()
			logger.Info("subscribed to gateway tracker")

			for update := range gatewayUpdates.C() {
				logger.Debug(
					"subscriber got an update!",
					zap.Any("gateway_v4", update.GatewayV4),
					zap.Any("gateway_v6", update.GatewayV6),
				)

				if update.GatewayV4 != nil {
					if update.GatewayV4.Modified {
						if update.GatewayV4.Before != nil && update.GatewayV4.Before.OK {
							wgm.cleanupManagedRoutes(update.GatewayV4.Before.Address)
						}
					}
				}

				if update.GatewayV6 != nil {
					if update.GatewayV6.Modified {
						if update.GatewayV6.Before != nil && update.GatewayV6.Before.OK {
							wgm.cleanupManagedRoutes(update.GatewayV6.Before.Address)
						}
					}
				}

				if update.GatewayV4.Modified || update.GatewayV6.Modified {
					if wgm.IsRunning() {
						if wgm.needsBypassRoutes.Load() {
							if err := routes.EnsureBypassRoutes(wgm.rm, wgm.state, wgm.bypassRoutes.Slice()); err != nil {
								wgm.logger.Warn("failed to setup vpn bypass routes", zap.Error(err))
							}
						}
						wgm.wgBind.Rebind()
					}
				}
			}
		}()
	}

	return wgm, nil
}

func (wgm *wireGuardManager) Start() error {
	wgm.mu.Lock()
	defer wgm.mu.Unlock()

	alreadyRunning := wgm.isRunning.CompareAndSwap(false, true)
	if alreadyRunning {
		return nil
	}

	return wgm.startLocked()
}

func (wgm *wireGuardManager) RefreshIfRunning() error {
	wgm.mu.Lock()
	defer wgm.mu.Unlock()

	if !wgm.isRunning.Load() {
		return nil
	}
	return wgm.startLocked()
}

func (wgm *wireGuardManager) RefreshPeerIfRunning(pub string) error {
	wgm.mu.Lock()
	defer wgm.mu.Unlock()

	if !wgm.isRunning.Load() {
		return nil
	}

	peerConfig, ok := wgm.state.GetWireGuardPeer(pub)
	if !ok {
		return fmt.Errorf("got refresh request for a peer not in state (%s)", pub)
	}
	return wgm.updateOnePeerLocked(peerConfig)
}

func (wgm *wireGuardManager) RemovePeerIfRunning(pub string) error {
	wgm.mu.Lock()
	defer wgm.mu.Unlock()

	if !wgm.isRunning.Load() {
		return nil
	}

	if peerConfig, ok := wgm.state.GetWireGuardPeer(pub); ok {
		return wgm.removeOnePeerLocked(peerConfig)
	}
	return nil // already not present
}

func (wgm *wireGuardManager) cleanupNatRules() error {
	_, _, thisPeerCIDRv4, thisPeerCIDRv6, _, _ := wgm.state.GetNetworkIPs()
	if err := wgm.natMgr.CleanupIPv4NAT(thisPeerCIDRv4, wgm.ifaceName); err != nil {
		wgm.logger.Error("failed to cleanup IPv4 NAT rules", zap.Error(err))
	}
	if err := wgm.natMgr.CleanupIPv6NAT(thisPeerCIDRv6, wgm.ifaceName); err != nil {
		wgm.logger.Error("failed to cleanup IPv6 NAT rules", zap.Error(err))
	}
	if err := wgm.natMgr.CleanupIPv4WireGuardIngress(wgm.wgPort); err != nil {
		wgm.logger.Error("failed to cleanup IPv4 INPUT rules", zap.Error(err))
	}
	if err := wgm.natMgr.CleanupIPv6WireGuardIngress(wgm.wgPort); err != nil {
		wgm.logger.Error("failed to cleanup IPv6 INPUT rules", zap.Error(err))
	}
	return nil
}

func (wgm *wireGuardManager) hosts(skipHost *string) map[string]string {
	if !wgm.IsRunning() {
		return nil
	}

	hosts := make(map[string]string)
	for _, peer := range wgm.state.GetWireGuardPeers() {
		if skipHost != nil && peer.PublicKey == *skipHost {
			continue
		}
		if peer.Name != "" {
			if peer.IPv4Address != "" {
				hosts[peer.IPv4Address] = peer.Name
			}
			if peer.IPv6Address != "" {
				hosts[peer.IPv6Address] = peer.Name
			}
		}
		for _, svc := range peer.Services {
			if svc.Name != "" {
				if svc.IPv4Address != "" {
					hosts[svc.IPv4Address] = svc.Name
				}
				if svc.IPv6Address != "" {
					hosts[svc.IPv6Address] = svc.Name
				}
			}
		}
	}

	return hosts
}

func (wgm *wireGuardManager) Stop() error {
	wgm.mu.Lock()
	defer wgm.mu.Unlock()

	wasRunning := wgm.isRunning.Swap(false)
	if wasRunning {
		return wgm.stopLocked()
	}
	return nil
}

func (wgm *wireGuardManager) IsRunning() bool {
	// connectors are always running
	if wgm.isConnector {
		return true
	}
	return wgm.isRunning.Load()
}

func (wgm *wireGuardManager) Close() error {
	wgm.mu.Lock()
	defer wgm.mu.Unlock()

	wgm.logger.Info("WireGuard manager is closing...")

	// best effort routes cleanup
	defer wgm.cleanupManagedRoutes("")

	// bring down wireguard device (stop accepting traffic over WireGuard)
	if err := wgm.wgDevice.Down(); err != nil {
		return fmt.Errorf("failed to bring wireguard device down: %v", err)
	}

	// close netstack stack (stop serving sockets)
	wgm.netstackStack.Close()

	// close the custom device's underlying real world device (TUN from wireguard-go)
	if err := wgm.realworldTUN.Close(); err != nil {
		return fmt.Errorf("failed to close realworld TUN device: %v", err)
	}

	// close the custom device's underlying netstack device (TUN from netstack)
	if err := wgm.netstackTUN.Close(); err != nil {
		return fmt.Errorf("failed to close netstack TUN device: %v", err)
	}

	// close our custom device (stop processing accepted traffic)
	if err := wgm.tunDevice.Close(); err != nil {
		return fmt.Errorf("failed to close custom TUN device: %v", err)
	}

	// close the wireguard-go device (note: closes the bind under the hood)
	wgm.wgDevice.Close()

	// stop the gateway monitor
	wgm.gwtracker.Close()

	wgm.logger.Info("WireGuard manager closed successfully")
	return nil
}

// stopLocked stops the WireGuard mesh.
// It must be invoked while holding the wireGuardManager lock.
func (wgm *wireGuardManager) stopLocked() error {
	defer func() {
		wgm.cleanupManagedRoutes("")
		if err := wgm.updateHostfile(nil); err != nil {
			wgm.logger.Error("failed to update hostfile", zap.Error(err))
		}
		if wgm.isConnector {
			if err := wgm.cleanupNatRules(); err != nil {
				wgm.logger.Error("failed to cleanup NAT rules", zap.Error(err))
			}
		}
	}()

	if err := wgm.wgDevice.Down(); err != nil {
		return fmt.Errorf("failed to bring wireguard device down: %v", err)
	}
	for _, peer := range wgm.state.GetWireGuardPeers() {
		if present, ok := wgm.peerMap.GetByPub(peer.RuntimePublicKey.B64()); ok {
			endpoint.StopQOSChecks(present)
			wgm.peerMap.DeleteByPub(peer.RuntimePublicKey.B64())
		}
	}
	return nil
}

// startLocked starts the WireGuard mesh from data in the state.
// It must be invoked while holding the wireGuardManager lock.
func (wgm *wireGuardManager) startLocked() error {
	defer func() {
		// best effort commit for routes
		if err := wgm.state.Commit(); err != nil {
			wgm.logger.Warn("failed to commit state after starting WireGuard manager", zap.Error(err))
		}
	}()

	// associate the local device's IPs with the interface
	// and set routes for the private network CIDRs
	if err := wgm.ensurePrivateNetworkAddresses(); err != nil {
		return fmt.Errorf("failed to ensure integrity of private network addresses: %v", err)
	}

	peers := wgm.state.GetWireGuardPeers()
	var hasExitNode bool
	for _, peer := range peers {
		if wgm.state.GetExitNode() != "" {
			for _, svc := range peer.Services {
				if svc.Type == service.ServiceTypeExitNode && svc.Name == wgm.state.GetExitNode() {
					hasExitNode = true
				}
			}
		}
		wgm.resetPeerLocked(peer, false)
	}

	if wgm.state.GetExitNode() != "" && !hasExitNode {
		wgm.state.SetExitNode("")
	}

	if !wgm.isConnector && wgm.needsBypassRoutes.Load() {
		// set bypass routes (IPs we must unconditionally reach over the internet and never over WireGuard)
		err := routes.EnsureBypassRoutes(wgm.rm, wgm.state, wgm.bypassRoutes.Slice())
		if err != nil {
			wgm.logger.Warn("failed to setup vpn bypass routes", zap.Error(err))
		}
	}

	// write hosts file
	if err := wgm.updateHostfile(nil); err != nil {
		wgm.logger.Error("failed to update hostfile", zap.Error(err))
	}

	if err := wgm.reconfigure(peers); err != nil {
		return fmt.Errorf("failed to reconfigure wireguard manager with new peers: %v", err)
	}

	if err := wgm.wgDevice.Up(); err != nil {
		return fmt.Errorf("failed to bring wireguard device up: %v", err)
	}

	return nil
}

// ensurePrivateNetworkAddresses associate the local device's IPs in the private network
// with the network interface and sets coarse routes for device and resource ranges.
func (wgm *wireGuardManager) ensurePrivateNetworkAddresses() error {
	localDeviceIPv4, localDeviceIPv6, devicesCIDRv4, devicesCIDRv6, resourcesCIDRv4, resourcesCIDRv6 := wgm.state.GetNetworkIPs()

	// set v4 and v6 addresses on our TUN interface e.g. associate the
	// local device's (v4 and v6) addresses in the device ranges
	var err error
	wgm.setup.Do(func() { err = routes.AssignAddresses(wgm.rm, wgm.ifaceName, localDeviceIPv4, localDeviceIPv6) })
	if err != nil {
		return fmt.Errorf("failed to assign IP addresses to TUN interface: %v", err)
	}

	// set v4 route for devices range
	if err := wgm.rm.AddV4Route(wgm.ifaceName, devicesCIDRv4); err != nil {
		return fmt.Errorf("failed to add v4 route for devices network: %v", err)
	}
	wgm.state.AddNonServiceManagedRoute(devicesCIDRv4)

	// set v6 route for devices range
	if err := wgm.rm.AddV6Route(wgm.ifaceName, devicesCIDRv6); err != nil {
		return fmt.Errorf("failed to add v6 route for devices network: %v", err)
	}
	wgm.state.AddNonServiceManagedRoute(devicesCIDRv6)

	// set v4 route for resources range
	if err := wgm.rm.AddV4Route(wgm.ifaceName, resourcesCIDRv4); err != nil {
		return fmt.Errorf("failed to add v4 route for resources network: %v", err)
	}
	wgm.state.AddNonServiceManagedRoute(resourcesCIDRv4)

	// set v6 route for resources range
	if err := wgm.rm.AddV6Route(wgm.ifaceName, resourcesCIDRv6); err != nil {
		return fmt.Errorf("failed to add v6 route for resources network: %v", err)
	}
	wgm.state.AddNonServiceManagedRoute(resourcesCIDRv6)

	return nil
}

func (wgm *wireGuardManager) tryDeletePeerByPassRoutesLocked(peer *state.PeerConfig) {
	if peer.RuntimeEndpointUDP4.IsValid() {
		addrv4 := peer.RuntimeEndpointUDP4.Addr()
		cidrv4 := fmt.Sprintf("%s/32", addrv4.String())
		exists, err := wgm.rm.RouteExists(cidrv4, "")
		if err != nil {
			wgm.logger.Error("failed to check peer's IPv4 bypass route existence", zap.String("cidr", cidrv4), zap.Error(err))
		}
		if exists {
			if err := wgm.rm.DeleteRoute(cidrv4, ""); err != nil {
				wgm.logger.Warn("failed to cleanup managed route", zap.String("cidr", cidrv4), zap.Error(err))
			} else {
				wgm.bypassRoutes.Remove(addrv4)
			}
		}
		wgm.state.RemoveNonServiceManagedRoute(cidrv4)
	}
	if peer.RuntimeEndpointUDP6.IsValid() {
		addrv6 := peer.RuntimeEndpointUDP6.Addr()
		cidrv6 := fmt.Sprintf("%s/128", addrv6.String())
		exists, err := wgm.rm.RouteExists(cidrv6, "")
		if err != nil {
			wgm.logger.Error("failed to check peer's IPv6 bypass route existence", zap.String("cidr", cidrv6), zap.Error(err))
		}
		if exists {
			if err := wgm.rm.DeleteRoute(cidrv6, ""); err != nil {
				wgm.logger.Warn("failed to cleanup managed route", zap.String("cidr", cidrv6), zap.Error(err))
			} else {
				wgm.bypassRoutes.Remove(addrv6)
			}
		}
		wgm.state.RemoveNonServiceManagedRoute(cidrv6)
	}
}

func (wgm *wireGuardManager) tryEnsurePeerByPassRoutesLocked(peer *state.PeerConfig) {
	peerBypassRoutes := []netip.Addr{}
	if peer.RuntimeEndpointUDP4.IsValid() {
		peerBypassRoutes = append(peerBypassRoutes, peer.RuntimeEndpointUDP4.Addr())
	}
	if peer.RuntimeEndpointUDP6.IsValid() {
		peerBypassRoutes = append(peerBypassRoutes, peer.RuntimeEndpointUDP6.Addr())
	}
	wgm.bypassRoutes.Add(peerBypassRoutes...)
	if err := routes.EnsureBypassRoutes(wgm.rm, wgm.state, peerBypassRoutes); err != nil {
		wgm.logger.Error("failed to ensure peer's bypass routes", zap.String("peer_pub", peer.PublicKey), zap.Error(err))
	}
}

func (wgm *wireGuardManager) resetPeerLocked(peer *state.PeerConfig, remove bool) {
	// stop checks if already present
	if present, ok := wgm.peerMap.GetByPub(peer.RuntimePublicKey.B64()); ok {
		endpoint.StopQOSChecks(present)
		wgm.peerMap.DeleteByPub(peer.RuntimePublicKey.B64())
	}

	// set routes for services
	for _, svc := range peer.Services {
		// NOTE: the needsBypassRoutes flag tells other portions of the code if there
		// is at least one subnet router service and so we must set up bypass routes.
		if svc.Type == service.ServiceTypeSubnetRoutes || (svc.Type == service.ServiceTypeExitNode && wgm.state.GetExitNode() == svc.Name) {
			if !remove {
				if toggled := wgm.needsBypassRoutes.CompareAndSwap(false, true); toggled {
					wgm.logger.Info("got at least one subnet routes service, will set bypass routes", zap.String("service_name", svc.Name))
				}
			}

			for _, cidr := range svc.RuntimeSubnetRoutes {
				cidrStr := cidr.String()

				// handle special case for v4 default route
				if cidrStr == routes.IPv4DefaultRoute {
					// Only add default route for exit nodes that have a v4 endpoint
					if svc.Type == service.ServiceTypeExitNode {
						if peer.EndpointUDP4 == "" && peer.EndpointUDP6 != "" {
							continue
						}
					}
					// TODO(@adriano): delete existing route
					if !remove {
						if err := routes.SetDefaultV4Route(wgm.rm, wgm.state, wgm.ifaceName, peer.PublicKey, svc.Name); err != nil {
							wgm.logger.Error("failed to add v4 route for allowed ip for peer", zap.String("cidr", cidrStr), zap.String("peer", peer.PublicKey), zap.Error(err))
						}
					}
					continue
				}
				// handle special case for v6 default route
				if cidrStr == routes.IPv6DefaultRoute {
					// Only add default route for exit nodes that have a v4 endpoint
					if svc.Type == service.ServiceTypeExitNode {
						if peer.EndpointUDP6 == "" && peer.EndpointUDP4 != "" {
							continue
						}
					}
					// TODO(@adriano): delete existing route
					if !remove {
						if err := routes.SetDefaultV6Route(wgm.rm, wgm.state, wgm.ifaceName, peer.PublicKey, svc.Name); err != nil {
							wgm.logger.Error("failed to add v6 route for allowed ip for peer", zap.String("cidr", cidrStr), zap.String("peer", peer.PublicKey), zap.Error(err))
						}
					}
					continue
				}
				// everything else
				if cidr.Addr().Is6() {
					// TODO(@adriano): delete existing route
					if !remove {
						if err := wgm.rm.AddV6Route(wgm.ifaceName, cidrStr); err != nil {
							wgm.logger.Error("failed to add v6 route for allowed ip for peer", zap.String("cidr", cidrStr), zap.String("peer", peer.PublicKey), zap.Error(err))
							continue
						}
						wgm.state.AddServiceManagedRoute(cidrStr, peer.PublicKey, svc.Name)
					}
					continue
				}
				if cidr.Addr().Is4() {
					// TODO(@adriano): delete existing route
					if !remove {
						if err := wgm.rm.AddV4Route(wgm.ifaceName, cidrStr); err != nil {
							wgm.logger.Error("failed to add v4 route for allowed ip for peer", zap.String("cidr", cidrStr), zap.String("peer", peer.PublicKey), zap.Error(err))
							continue
						}
						wgm.state.AddServiceManagedRoute(cidrStr, peer.PublicKey, svc.Name)
					}
					continue
				}
			}
		}

		if peerManagedRoutes, ok := wgm.state.GetManagedRoutes().Peers[peer.PublicKey]; ok {
			if _, ok := peerManagedRoutes.Services[svc.Name]; ok {
				// cleanup routes for service if no longer present in svc
				for _, route := range peerManagedRoutes.Services[svc.Name].Slice() {
					found := false
					var routeToCheck string
					switch {
					case route == routes.IPv4InternetFirstHalf, route == routes.IPv4InternetSecondHalf:
						routeToCheck = routes.IPv4DefaultRoute
					case route == routes.IPv6InternetFirstHalf, route == routes.IPv6InternetSecondHalf:
						routeToCheck = routes.IPv6DefaultRoute
					default:
						routeToCheck = route
					}

					if svc.Type != service.ServiceTypeExitNode || wgm.state.GetExitNode() == svc.Name {
						for _, cidr := range svc.RuntimeSubnetRoutes {
							if routeToCheck == cidr.String() {
								found = true
								break
							}
						}
					}

					if !found {
						if err := wgm.rm.DeleteRoute(route, ""); err != nil {
							wgm.logger.Warn("failed to cleanup managed route", zap.String("route", route), zap.Error(err))
						}
						wgm.state.RemoveServiceManagedRoute(route, peer.PublicKey, svc.Name)
					}
				}
			}
		}
	}

	// cleanup deleted services
	if peerManagedRoutes, ok := wgm.state.GetManagedRoutes().Peers[peer.PublicKey]; ok {
		for svcName, svcRoutes := range peerManagedRoutes.Services {
			found := false
			for _, service := range peer.Services {
				if service.Name == svcName {
					found = true
					break
				}
			}

			if !found {
				for _, route := range svcRoutes.Slice() {
					if wgm.state.ManagedRouteCount(route) == 1 {
						if err := wgm.rm.DeleteRoute(route, ""); err != nil {
							wgm.logger.Warn("failed to cleanup managed route", zap.String("route", route), zap.Error(err))
						}
					}
					wgm.state.RemoveServiceManagedRoute(route, peer.PublicKey, svcName)
				}
			}
		}
	}

	if remove {
		if peerManagedRoutes, ok := wgm.state.GetManagedRoutes().Peers[peer.PublicKey]; ok {
			for svcName, svcRoutes := range peerManagedRoutes.Services {
				for _, route := range svcRoutes.Slice() {
					if wgm.state.ManagedRouteCount(route) == 1 {
						if err := wgm.rm.DeleteRoute(route, ""); err != nil {
							wgm.logger.Warn("failed to cleanup managed route", zap.String("route", route), zap.Error(err))
						}
					}
					wgm.state.RemoveServiceManagedRoute(route, peer.PublicKey, svcName)
				}
			}
		}
		wgm.tryDeletePeerByPassRoutesLocked(peer)
	} else {
		// NOTE: the needsBypassRoutes flag tells other portions of the code if there
		// is at least one subnet router service and so we must set up bypass routes.
		if wgm.needsBypassRoutes.Load() {
			wgm.tryEnsurePeerByPassRoutesLocked(peer)
		}
		wgm.peerMap.Set(
			endpoint.New(
				peer.RuntimePublicKey,
				qos.NewConn(
					wgm.logger,
					&qos.Settings{
						PrivateKey:    wgm.state.GetPrivateKey(),
						PeerPublicKey: peer.RuntimePublicKey,

						ProbesPeriod:       time.Second * 5, // how frequently to send QOS probes to peer
						ComputationPeriod:  time.Second * 3, // how frequently to calculate scores (also how fast we can switch conns)
						ComputationSamples: 5,               // how many probes to take into account in score calculations

						Udp4AddrPort: peer.RuntimeEndpointUDP4,
						Udp4Conn:     wgm.wgBind.GetUdp4Conn(),
						Udp6AddrPort: peer.RuntimeEndpointUDP6,
						Udp6Conn:     wgm.wgBind.GetUdp6Conn(),
						RelayAddr:    turtle.Address(peer.RuntimePublicKey),
						RelayConn:    wgm.wgBind.GetRelayConn(),

						DisallowedSourcesV4: wgm.qosDisallowedSourcesV4,
						DisallowedSourcesV6: wgm.qosDisallowedSourcesV6,
					},
				),
				peer.Name,
				peer.IPv4Address,
				peer.IPv6Address,
			),
		)

		// generate some traffic to force wireguard handshake with remote peer
		if peer.RuntimeIPv4Address.IsValid() {
			go ping(peer.RuntimeIPv4Address, defaultPingProbes, defaultPingInterval)
		}
		if peer.RuntimeIPv6Address.IsValid() {
			go ping(peer.RuntimeIPv6Address, defaultPingProbes, defaultPingInterval)
		}
	}
}

// init sets the private key and listener port for WireGuard in the inner WireGuard device.
func (wgm *wireGuardManager) init() error {
	buff := new(bytes.Buffer)
	err := writeConfig(buff, wgtypes.Config{
		PrivateKey: wgm.wgKey,
	})
	if err != nil {
		return fmt.Errorf("failed to build config object for wireguard device: %v", err)
	}
	if err := wgm.wgDevice.IpcSetOperation(buff); err != nil {
		return fmt.Errorf("failed to configure peers on wireguard device: %v", err)
	}
	return nil
}

func (wgm *wireGuardManager) reconfigure(peers []*state.PeerConfig) error {
	buff := new(bytes.Buffer)
	err := writeConfig(buff, wgtypes.Config{
		ReplacePeers: true, // always override peers
		Peers:        slice.Transform[*state.PeerConfig, wgtypes.PeerConfig](peers, transformPeer),
	})
	if err != nil {
		return fmt.Errorf("failed to build config object for wireguard device: %v", err)
	}
	if err := wgm.wgDevice.IpcSetOperation(buff); err != nil {
		return fmt.Errorf("failed to configure peers on wireguard device: %v", err)
	}
	return nil
}

func (wgm *wireGuardManager) updateOnePeerLocked(peer *state.PeerConfig) error {
	wgm.resetPeerLocked(peer, false)
	if err := wgm.state.Commit(); err != nil {
		wgm.logger.Warn("failed to commit state after updating managed routes for peer", zap.String("pub", peer.PublicKey), zap.Error(err))
	}
	if err := wgm.updateHostfile(nil); err != nil {
		wgm.logger.Error("failed to update hostfile", zap.Error(err))
	}

	buff := new(bytes.Buffer)
	err := writeConfig(buff, wgtypes.Config{
		ReplacePeers: false,
		Peers:        []wgtypes.PeerConfig{transformPeer(peer)},
	})
	if err != nil {
		return fmt.Errorf("failed to build config object for wireguard device while updating peer %s: %v", peer.PublicKey, err)
	}
	if err := wgm.wgDevice.IpcSetOperation(buff); err != nil {
		return fmt.Errorf("failed to configure updated peer on wireguard device: %v", err)
	}
	return nil
}

func (wgm *wireGuardManager) removeOnePeerLocked(peer *state.PeerConfig) error {
	wgm.resetPeerLocked(peer, true)
	if err := wgm.state.Commit(); err != nil {
		wgm.logger.Warn("failed to commit state after removing managed routes for peer", zap.String("pub", peer.PublicKey), zap.Error(err))
	}
	if err := wgm.updateHostfile(&peer.PublicKey); err != nil {
		wgm.logger.Error("failed to update hostfile", zap.Error(err))
	}

	buff := new(bytes.Buffer)
	err := writeConfig(buff, wgtypes.Config{
		ReplacePeers: false,
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:         *peer.RuntimePublicKey.Raw(),
				Remove:            true,
				ReplaceAllowedIPs: true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("failed to build config object for wireguard device while removing peer %s: %v", peer.PublicKey, err)
	}
	if err := wgm.wgDevice.IpcSetOperation(buff); err != nil {
		return fmt.Errorf("failed to configure removed peer on wireguard device: %v", err)
	}
	return nil
}

func (wgm *wireGuardManager) cleanupManagedRoutes(gatewayIP string) {
	for _, route := range wgm.state.GetManagedRoutes().Routes.Slice() {
		routeFields := strings.Fields(route)

		valid := false
		cidr := ""
		gwip := ""
		switch len(routeFields) {
		case 1:
			cidr, gwip, valid = routeFields[0], "", true
		case 2:
			cidr, gwip, valid = routeFields[0], routeFields[1], true
		default:
			wgm.logger.Error(
				"managed route in state has invalid number of parts",
				zap.String("route", route),
			)
			continue
		}

		if gatewayIP != "" {
			// if a route's gateway IP (gwip) does not match
			// the passed gatewayIP filter, we exclude it.
			if gatewayIP != gwip {
				continue
			}
		}

		if valid {
			// skip addresses that are already set
			exists, err := wgm.rm.RouteExists(cidr, gwip)
			if err != nil {
				wgm.logger.Error(
					"failed to check peer's route existence for route on gateway ip",
					zap.String("cidr", cidr),
					zap.String("gwip", gwip),
					zap.Error(err),
				)
				continue
			}
			if exists {
				if err := wgm.rm.DeleteRoute(cidr, gwip); err != nil {
					wgm.logger.Error(
						"failed to cleanup managed route",
						zap.String("route", route),
						zap.Error(err),
					)
					continue
				}
			}
		}
		wgm.state.RemoveNonServiceManagedRoute(route)
	}

	// only cleanup routes for services if gwip is not set
	if gatewayIP == "" {
		for peer, peerManagedRoutes := range wgm.state.GetManagedRoutes().Peers {
			for service, services := range peerManagedRoutes.Services {
				for _, route := range services.Slice() {
					routeFields := strings.Fields(route)

					valid := false
					cidr := ""
					gwip := ""
					switch len(routeFields) {
					case 1:
						cidr, gwip, valid = routeFields[0], "", true
					case 2:
						cidr, gwip, valid = routeFields[0], routeFields[1], true
					default:
						wgm.logger.Error(
							"managed route in state has invalid number of parts",
							zap.String("route", route),
						)
						continue
					}

					if gatewayIP != "" {
						// if a route's gateway IP (gwip) does not match
						// the passed gatewayIP filter, we exclude it.
						if gatewayIP != gwip {
							continue
						}
					}

					if valid {
						// skip addresses that are already set
						exists, err := wgm.rm.RouteExists(cidr, gwip)
						if err != nil {
							wgm.logger.Error(
								"failed to check peer service's route existence for route on gateway ip",
								zap.String("cidr", cidr),
								zap.String("gwip", gwip),
								zap.Error(err),
							)
							continue
						}
						if exists {
							if err := wgm.rm.DeleteRoute(cidr, gwip); err != nil {
								wgm.logger.Error(
									"failed to cleanup managed route",
									zap.String("route", route),
									zap.Error(err),
								)
								continue
							}
						}
					}
					wgm.state.RemoveServiceManagedRoute(route, peer, service)
				}
			}
		}
	}

	if err := wgm.state.Commit(); err != nil {
		wgm.logger.Warn(
			"failed to commit state after cleaning up routes",
			zap.Error(err),
		)
	}
}

func (wgm *wireGuardManager) receiveSTUN(addr *net.UDPAddr) {
	if addr == nil {
		wgm.logger.Error("received STUN response with invalid address (nil address)")
		return
	}
	// NOTE: order here matters e.g. To16() returns non nil for v4 addresses.
	switch {
	case addr.IP.To4() != nil:
		oldAddr, newAddr, changed := addrChanged(wgm.udp4Addr.Swap(addr), addr)
		if changed {
			wgm.onAddressChangeChan <- &DiscoverabilityAnnouncement{
				Discoverable: wgm.IsRunning(),
				UDP4Address:  wgm.GetPublicIPv4Address(),
				UDP6Address:  wgm.GetPublicIPv6Address(),
			}
		}
		wgm.logger.Info(
			"received STUN response for udp4",
			zap.String("old_address", oldAddr),
			zap.String("new_address", newAddr),
			zap.Bool("changed", changed),
		)
	case addr.IP.To16() != nil:
		oldAddr, newAddr, changed := addrChanged(wgm.udp6Addr.Swap(addr), addr)
		if changed {
			wgm.onAddressChangeChan <- &DiscoverabilityAnnouncement{
				Discoverable: wgm.IsRunning(),
				UDP4Address:  wgm.GetPublicIPv4Address(),
				UDP6Address:  wgm.GetPublicIPv6Address(),
			}
		}
		wgm.logger.Info(
			"received STUN response for udp6",
			zap.String("old_address", oldAddr),
			zap.String("new_address", newAddr),
			zap.Bool("changed", changed),
		)
	default:
		wgm.logger.Error("received STUN response with invalid address (IP is not v4 nor v6 address)", zap.String("addr", addr.String()))
	}
}

func (wgm *wireGuardManager) GetPublicIPv4Address() *net.UDPAddr { return wgm.udp4Addr.Load() }
func (wgm *wireGuardManager) GetPublicIPv6Address() *net.UDPAddr { return wgm.udp6Addr.Load() }

func (wgm *wireGuardManager) SocketListener(address string) (net.Listener, error) {
	addr, err := netip.ParseAddrPort(address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %v", err)
	}

	var protoNumber tcpip.NetworkProtocolNumber
	if addr.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else if addr.Addr().Is6() {
		protoNumber = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          protoNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.Addr().AsSlice()).WithPrefix(),
	}

	if err := wgm.netstackStack.AddProtocolAddress(1, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("failed to add protocol address to netstack: %v", err)
	}

	listener, err := wgm.netstackNet.ListenTCPAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen for TCP on netstack address: %v", err)
	}

	if portsInUseForSockets, present := wgm.localSocketAddrPorts.Load(addr.Addr().String()); present {
		portsInUseForSockets.Add(addr.Port())
	} else {
		wgm.localSocketAddrPorts.Store(addr.Addr().String(), set.NewConcurrencySafe(addr.Port()))
	}

	// callback function to remove socket from internal mapping
	cleanupFunc := func() {
		if portsInUseForSockets, present := wgm.localSocketAddrPorts.Load(addr.Addr().String()); present {
			portsInUseForSockets.Remove(addr.Port())
		}
	}

	return socketListener{
		TCPListener:   listener,
		netstackStack: wgm.netstackStack,
		cleanup:       cleanupFunc,
	}, nil
}

func (l socketListener) Close() error {
	defer l.cleanup()

	if err := l.TCPListener.Close(); err != nil {
		return fmt.Errorf("failed to close listener: %v", err)
	}

	addr := l.TCPListener.Addr().(*net.TCPAddr)
	var tcpipAddr tcpip.Address
	if ip4 := addr.IP.To4(); ip4 != nil {
		tcpipAddr = tcpip.AddrFromSlice(ip4)
	} else {
		tcpipAddr = tcpip.AddrFromSlice(addr.IP.To16())
	}

	var protoNumber tcpip.NetworkProtocolNumber
	if addr.IP.To4() != nil {
		protoNumber = ipv4.ProtocolNumber
	} else if addr.IP.To16() != nil {
		protoNumber = ipv6.ProtocolNumber
	}

	// remove protocol address from netstack
	if l.netstackStack.CheckLocalAddress(1, protoNumber, tcpipAddr) != 0 {
		if err := l.netstackStack.RemoveAddress(1, tcpipAddr); err != nil {
			return fmt.Errorf("failed to remove protocol address from netstack: %v", err)
		}
	}

	return nil
}

// return current best peer ip for endpoint
func (wgm *wireGuardManager) GetPeerIP(pub string) (*netip.Addr, error) {
	endpoint, ok := wgm.peerMap.GetByPub(pub)
	if !ok {
		return nil, fmt.Errorf("no endpoint found for public key %s", pub)
	}

	addr := endpoint.DstIP()
	return &addr, nil
}

// return current wireguard config
func (wgm *wireGuardManager) GetWireGuardConfig() (string, error) {
	return wgm.wgDevice.IpcGet()
}

// returns peer connection statuses
func (wgm *wireGuardManager) GetPeerStats() ([]stats.Peer, error) {
	return wgm.peerMap.GetStats()
}

// returns wireguard manager stats.
func (wgm *wireGuardManager) GetStats() *stats.Stats {
	return wgm.stats.Snapshot()
}

// returns wireguard manager exit node.
func (wgm *wireGuardManager) GetExitNode() string {
	return wgm.state.GetExitNode()
}

// returns wireguard manager exit nodes.
func (wgm *wireGuardManager) GetExitNodes() []string {
	var exitNodes []string
	for _, peer := range wgm.state.GetWireGuardPeers() {
		for _, svc := range peer.Services {
			if svc.Type == service.ServiceTypeExitNode {
				exitNodes = append(exitNodes, svc.Name)
			}
		}
	}
	return exitNodes
}

// update wireguard manager exit node.
func (wgm *wireGuardManager) UpdateExitNodeRoutes() error {
	peers := wgm.state.GetWireGuardPeers()
	for _, peer := range peers {
		for _, svc := range peer.Services {
			if svc.Type == service.ServiceTypeExitNode && svc.Name == wgm.state.GetExitNode() {
				wgm.resetPeerLocked(peer, false)
				if err := wgm.state.Commit(); err != nil {
					return fmt.Errorf("failed to commit state after setting exit node: %v", err)
				}
				if err := wgm.RefreshPeerIfRunning(peer.PublicKey); err != nil {
					return fmt.Errorf("failed to refresh peer %s after setting exit node: %v", peer.PublicKey, err)
				}
			}
		}
	}

	return nil
}

// set wireguard manager exit node.
func (wgm *wireGuardManager) SetExitNode(exitNode string) error {
	var found bool
	var oldExitNode string

	if exitNode == "" {
		oldExitNode = wgm.state.GetExitNode()
		wgm.state.SetExitNode("").Commit()
		found = true
	} else {
	peerLoop:
		for _, peer := range wgm.state.GetWireGuardPeers() {
			for _, svc := range peer.Services {
				if svc.Type == service.ServiceTypeExitNode && svc.Name == exitNode {
					oldExitNode = wgm.state.GetExitNode()
					wgm.state.SetExitNode(exitNode).Commit()
					found = true
					break peerLoop
				}
			}
		}
	}

	if oldExitNode == exitNode {
		return nil
	}

	if !found {
		return fmt.Errorf("exit node %s not found in state", exitNode)
	}

	peers := wgm.state.GetWireGuardPeers()
	for _, peer := range peers {
		for _, svc := range peer.Services {
			if svc.Type == service.ServiceTypeExitNode && svc.Name == oldExitNode {
				wgm.resetPeerLocked(peer, false)
				if err := wgm.state.Commit(); err != nil {
					return fmt.Errorf("failed to commit state after setting exit node: %v", err)
				}
				if err := wgm.RefreshPeerIfRunning(peer.PublicKey); err != nil {
					return fmt.Errorf("failed to refresh peer %s after setting exit node: %v", peer.PublicKey, err)
				}
			}
		}
	}

	for _, peer := range peers {
		for _, svc := range peer.Services {
			if svc.Type == service.ServiceTypeExitNode && svc.Name == exitNode {
				wgm.resetPeerLocked(peer, false)
				if err := wgm.state.Commit(); err != nil {
					return fmt.Errorf("failed to commit state after setting exit node: %v", err)
				}
				if err := wgm.RefreshPeerIfRunning(peer.PublicKey); err != nil {
					return fmt.Errorf("failed to refresh peer %s after setting exit node: %v", peer.PublicKey, err)
				}
			}
		}
	}

	if !wgm.isConnector && wgm.needsBypassRoutes.Load() {
		// set bypass routes (IPs we must unconditionally reach over the internet and never over WireGuard)
		err := routes.EnsureBypassRoutes(wgm.rm, wgm.state, wgm.bypassRoutes.Slice())
		if err != nil {
			wgm.logger.Warn("failed to setup vpn bypass routes", zap.Error(err))
		}
	}

	return nil
}
