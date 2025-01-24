package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/lib/types/slice"
	"github.com/borderzero/border0-proto/common"
	"github.com/borderzero/border0-proto/device"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

const (
	unassignedDeviceID = "UNASSIGNED"
)

var (
	doNotModifyHeader = []byte(`# DO NOT MODIFY - THIS FILE IS MANAGED BY THE BORDER0 CLI
`)
)

type State interface {
	NeedsAuth() bool
	GetPrivateKey() *nacl.PrivateKey
	GetPublicKey() *nacl.PublicKey
	GetManagedInterfaces() []string
	GetManagedRoutes() managedRoutes
	ManagedRouteCount(cidr string) int
	GetNetworkIPs() (ipv4, ipv6, cidrv4, cidrv6, rcidrv4, rcidrv6 string)
	GetPeerByIP(ip net.IP) *PeerConfig
	GetWireGuardPeers() []*PeerConfig
	GetWireGuardPeer(string) (*PeerConfig, bool)
	GetProfile() *Profile

	SetKeyExpiry(*time.Time) State
	SetDeviceID(string) State
	AddManagedInterface(string) State
	RemoveManagedInterface(string) State

	AddServiceManagedRoute(string, string, string) State
	RemoveServiceManagedRoute(string, string, string) State

	AddNonServiceManagedRoute(string) State
	RemoveNonServiceManagedRoute(string) State

	SetWireGuardPeers([]*common.WireGuardPeer) State
	SetWireGuardPeer(*common.WireGuardPeer) State
	RemoveWireGuardPeer(string) State

	SetNetworkIPs(ipv4, ipv6, cidrv4, cidrv6, rcidrv4, rcidrv6 string) State
	SetProfile(*Profile) State

	AddService(peer *PeerConfig, svc *device.Service) State
	UpdateService(peer *PeerConfig, svc *device.Service) (State, bool)
	RemoveService(peer *PeerConfig, svc *device.Service) State

	GetExitNode() string
	SetExitNode(string) State

	Commit() error

	MarshalJSON() ([]byte, error)
}

type state struct {
	logger *zap.Logger
	mu     *sync.RWMutex
	path   string
	data   data
}

type Profile struct {
	ImageURL     string `yaml:"image_url,omitempty" json:"image_url,omitempty"`
	Name         string `yaml:"name,omitempty" json:"name,omitempty"`
	Email        string `yaml:"email,omitempty" json:"email,omitempty"`
	OrgID        string `yaml:"org_id,omitempty" json:"org_id,omitempty"`
	OrgSubdomain string `yaml:"org_subdomain,omitempty" json:"org_subdomain,omitempty"`
}

type managedRoutes struct {
	Peers  map[string]peerManagedRoutes
	Routes set.Set[string]
}

type peerManagedRoutes struct {
	Services map[string]set.Set[string]
}

type data struct {
	DeviceID                 string        `yaml:"device_id" json:"device_id"`
	SelfIPv4                 string        `yaml:"self_ip_v4" json:"self_ip_v4"`
	SelfIPv6                 string        `yaml:"self_ip_v6" json:"self_ip_v6"`
	NetworkCIDRv4            string        `yaml:"network_cidr_v4" json:"network_cidr_v4"`
	NetworkCIDRv6            string        `yaml:"network_cidr_v6" json:"network_cidr_v6"`
	ResourcesCIDRv4          string        `yaml:"resources_cidr_v4" json:"resources_cidr_v4"`
	ResourcesCIDRv6          string        `yaml:"resources_cidr_v6" json:"resources_cidr_v6"`
	Key                      key           `yaml:"key" json:"key"`
	Peers                    []*PeerConfig `yaml:"peers,omitempty" json:"peers,omitempty"` // TODO(@adrianosela): consider not serializing peers...
	ManagedNetworkInterfaces []string      `yaml:"managed_network_interfaces,omitempty" json:"managed_network_interfaces,omitempty"`
	ManagedRoutes            []string      `yaml:"managed_routes,omitempty" json:"managed_routes,omitempty"`
	LastUpdatedAt            time.Time     `yaml:"last_updated_at" json:"last_updated_at"`
	Profile                  *Profile      `yaml:"profile,omitempty" json:"profile,omitempty"`
	ExitNode                 string        `yaml:"exit_node,omitempty" json:"exit_node,omitempty"`

	// below are runtime objects which should not be serialized
	RuntimeManagedRoutes managedRoutes `yaml:"-" json:"-"`
}

func (d *data) decodeAndValidate() error {
	// adjust profile if empty
	if d.Profile == nil {
		d.Profile = &Profile{
			ImageURL: "https://download.border0.com/static/idp_logos/unknown.png",
			Email:    "Unknown",
			Name:     "Unknown",
		}
	}

	// build key runtime object
	if err := d.Key.decodeAndValidate(); err != nil {
		return fmt.Errorf("failed to ensure device key integrity: %v", err)
	}

	// build peers onto runtime objects
	for _, peer := range d.Peers {
		if err := peer.decodeAndValidate(d.ExitNode); err != nil {
			return fmt.Errorf("failed to ensure peer data integrity: %v", err)
		}
	}

	// build managed routes runtime object
	if d.RuntimeManagedRoutes.Peers == nil {
		d.RuntimeManagedRoutes.Peers = make(map[string]peerManagedRoutes)
	}
	d.RuntimeManagedRoutes.Routes = set.New(d.ManagedRoutes...)
	return nil
}

// Load loads state from disk if available, otherwise initializes a new one.
func Load(logger *zap.Logger, path string) (State, error) {
	if path == "" {
		return nil, fmt.Errorf("path for state file cannot be empty")
	}

	if _, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to look for device state file: %v", err)
		}
		if err = newState(path); err != nil {
			return nil, fmt.Errorf("failed to initialize new state file: %v", err)
		}
		// don't return early on purpose, make sure the file is readable
	}

	stateBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %v", err)
	}

	s := &state{logger: logger, mu: &sync.RWMutex{}, path: path, data: data{ /* empty */ }}
	if err = yaml.Unmarshal(stateBytes, &s.data); err != nil {
		return nil, fmt.Errorf("failed to decode state file yaml data: %v", err)
	}
	if err := s.data.decodeAndValidate(); err != nil {
		return nil, fmt.Errorf("failed to ensure state file integrity: %v", err)
	}

	return s, nil
}

func newState(path string) error {
	privateKey, err := nacl.GenerateKey()
	if err != nil {
		return fmt.Errorf("failed to generate new device key: %v", err)
	}

	s := &state{
		mu:   &sync.RWMutex{},
		path: path,
		data: data{
			DeviceID: unassignedDeviceID,
			Key: key{
				PrivateKey: privateKey.B64(),
				PublicKey:  privateKey.Public().B64(),
			},
			LastUpdatedAt: time.Now(),
			RuntimeManagedRoutes: managedRoutes{
				Peers:  make(map[string]peerManagedRoutes),
				Routes: set.New[string](),
			},
		},
	}

	// ensure the directory
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to ensure %s directory: %v", dir, err)
	}

	if err := s.Commit(); err != nil {
		return fmt.Errorf("failed to commit new state to disk: %v", err)
	}

	return nil
}

func (s *state) NeedsAuth() bool {
	if s.data.DeviceID == unassignedDeviceID {
		return true
	}
	if s.data.Key.ExpiresAt != nil {
		if time.Now().After(*s.data.Key.ExpiresAt) {
			return true
		}
	}
	return false
}

func (s *state) GetPrivateKey() *nacl.PrivateKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data.Key.RuntimeKey
}

func (s *state) GetPublicKey() *nacl.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data.Key.RuntimeKey.Public()
}

func (s *state) GetManagedInterfaces() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data.ManagedNetworkInterfaces
}

func (s *state) GetManagedRoutes() managedRoutes {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data.RuntimeManagedRoutes
}

func (s *state) GetNetworkIPs() (string, string, string, string, string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data.SelfIPv4,
		s.data.SelfIPv6,
		s.data.NetworkCIDRv4,
		s.data.NetworkCIDRv6,
		s.data.ResourcesCIDRv4,
		s.data.ResourcesCIDRv6
}

func (s *state) GetWireGuardPeers() []*PeerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Peers
}

func (s *state) GetWireGuardPeer(pub string) (*PeerConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := 0; i < len(s.data.Peers); i++ {
		if s.data.Peers[i].PublicKey == pub {
			return s.data.Peers[i], true
		}
	}
	return nil, false
}

func (s *state) GetProfile() *Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.Profile
}

func (s *state) AddManagedInterface(iface string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.ManagedNetworkInterfaces = set.
		New(s.data.ManagedNetworkInterfaces...).
		Add(iface).
		Slice()
	s.data.LastUpdatedAt = time.Now()
	return s
}

func (s *state) RemoveManagedInterface(iface string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.ManagedNetworkInterfaces = set.
		New(s.data.ManagedNetworkInterfaces...).
		Remove(iface).
		Slice()
	s.data.LastUpdatedAt = time.Now()
	return s
}

// AddServiceManagedRoute adds a route to the state's routes
// list managed by the given peer public key and service.
func (s *state) AddServiceManagedRoute(cidr, peerPub, svcName string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	defer func() { s.data.LastUpdatedAt = time.Now() }()

	if _, ok := s.data.RuntimeManagedRoutes.Peers[peerPub]; !ok {
		s.data.RuntimeManagedRoutes.Peers[peerPub] = peerManagedRoutes{
			Services: make(map[string]set.Set[string]),
		}
	}

	if _, ok := s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName]; !ok {
		s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName] = set.New[string]()
	}

	if s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName].Has(cidr) {
		return s
	}

	s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName].Add(cidr)
	return s
}

// RemoveServiceManagedRoute removes a route from the state's routes
// list managed by the given peer public key and service.
func (s *state) RemoveServiceManagedRoute(cidr, peerPub, svcName string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	defer func() { s.data.LastUpdatedAt = time.Now() }()

	if _, ok := s.data.RuntimeManagedRoutes.Peers[peerPub]; !ok {
		return s
	}
	if _, ok := s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName]; !ok {
		return s
	}
	if s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName].Has(cidr) {
		s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName].Remove(cidr)
	}
	if s.data.RuntimeManagedRoutes.Peers[peerPub].Services[svcName].Size() == 0 {
		delete(s.data.RuntimeManagedRoutes.Peers[peerPub].Services, svcName)
	}
	if len(s.data.RuntimeManagedRoutes.Peers[peerPub].Services) == 0 {
		delete(s.data.RuntimeManagedRoutes.Peers, peerPub)
	}
	return s
}

// AddNonServiceManagedRoute adds a route to the state's list
// of routes that are NOT managed by any peer or service.
// NOTE: the route argument can have any of the following formats:
//   - "${CIDR}" e.g. the device and resource ranges in the private network
//   - "${CIDR} ${GATEWAY_IP}" e.g. bypass routes for peers public addresses,
//     the border0 api, the stun server address, the relay address.
func (s *state) AddNonServiceManagedRoute(route string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.RuntimeManagedRoutes.Routes.Add(route)
	s.data.LastUpdatedAt = time.Now()
	return s
}

// RemoveNonServiceManagedRoute removes any managed routes for the
// given CIDR regardless of the gateway IP they are associated with
// (if any). See the docs in AddNonServiceManagedRoute() for more info.
func (s *state) RemoveNonServiceManagedRoute(cidr string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, route := range s.data.RuntimeManagedRoutes.Routes.Slice() {
		if strings.HasPrefix(route, cidr) {
			s.data.RuntimeManagedRoutes.Routes.Remove(route)
		}
	}
	s.data.LastUpdatedAt = time.Now()
	return s
}

func (s *state) SetDeviceID(did string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.DeviceID = did
	s.data.LastUpdatedAt = time.Now()
	return s
}

func (s *state) SetKeyExpiry(exp *time.Time) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.Key.ExpiresAt = exp
	s.data.LastUpdatedAt = time.Now()
	return s
}

func (s *state) SetNetworkIPs(ipv4, ipv6, cidrv4, cidrv6, rcidrv4, rcidrv6 string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.SelfIPv4 = ipv4
	s.data.SelfIPv6 = ipv6
	s.data.NetworkCIDRv4 = cidrv4
	s.data.NetworkCIDRv6 = cidrv6
	s.data.ResourcesCIDRv4 = rcidrv4
	s.data.ResourcesCIDRv6 = rcidrv6
	s.data.LastUpdatedAt = time.Now()
	return s
}

func (s *state) SetWireGuardPeers(peers []*common.WireGuardPeer) State {
	formattedPeers := []*PeerConfig{}

	for i, peer := range peers {
		formattedPeer := &PeerConfig{
			Name:                        peer.GetName(),
			PublicKey:                   peer.GetPublicKey(),
			EndpointUDP4:                peer.GetPublicUdp4Endpoint(),
			EndpointUDP6:                peer.GetPublicUdp6Endpoint(),
			IPv4Address:                 peer.GetIpv4(),
			IPv6Address:                 peer.GetIpv6(),
			PersistentKeepaliveInterval: time.Second * time.Duration(peer.GetPersistentKeepaliveIntervalSeconds()),
			Services:                    []*ServiceConfig{},
		}
		for _, svc := range peer.GetServices() {
			formattedPeer.Services = append(formattedPeer.Services, &ServiceConfig{
				Name:         svc.GetName(),
				Type:         svc.GetType(),
				IPv4Address:  svc.GetIpv4(),
				IPv6Address:  svc.GetIpv6(),
				SubnetRoutes: svc.GetSubnetRoutes(),
				DNSName:      svc.GetDnsName(),
				UpstreamType: svc.GetUpstreamType(),
			})
		}

		if err := formattedPeer.decodeAndValidate(s.GetExitNode()); err != nil {
			s.logger.Error(
				"failed to decode and validate data for peer",
				zap.Int("index", i),
				zap.String("pub", peer.GetPublicKey()),
				zap.Error(err),
			)
			continue
		}
		formattedPeers = append(formattedPeers, formattedPeer)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.Peers = formattedPeers
	s.data.LastUpdatedAt = time.Now()
	return s
}

func (s *state) SetWireGuardPeer(peer *common.WireGuardPeer) State {
	formattedPeer := &PeerConfig{
		Name:                        peer.GetName(),
		PublicKey:                   peer.GetPublicKey(),
		EndpointUDP4:                peer.GetPublicUdp4Endpoint(),
		EndpointUDP6:                peer.GetPublicUdp6Endpoint(),
		IPv4Address:                 peer.GetIpv4(),
		IPv6Address:                 peer.GetIpv6(),
		PersistentKeepaliveInterval: time.Second * time.Duration(peer.GetPersistentKeepaliveIntervalSeconds()),
		Services:                    []*ServiceConfig{},
	}
	for _, svc := range peer.GetServices() {
		formattedPeer.Services = append(formattedPeer.Services, &ServiceConfig{
			Name:         svc.GetName(),
			Type:         svc.GetType(),
			IPv4Address:  svc.GetIpv4(),
			IPv6Address:  svc.GetIpv6(),
			SubnetRoutes: svc.GetSubnetRoutes(),
			DNSName:      svc.GetDnsName(),
			UpstreamType: svc.GetUpstreamType(),
		})
	}

	if err := formattedPeer.decodeAndValidate(s.GetExitNode()); err != nil {
		s.logger.Error(
			"failed to decode and validate data for peer",
			zap.String("pub", peer.GetPublicKey()),
			zap.Error(err),
		)
		return s
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < len(s.data.Peers); i++ {
		// replace existing peer if present
		if s.data.Peers[i].PublicKey == formattedPeer.PublicKey {
			s.data.Peers[i] = formattedPeer
			s.data.LastUpdatedAt = time.Now()
			return s
		}
	}

	s.data.Peers = append(s.data.Peers, formattedPeer)
	s.data.LastUpdatedAt = time.Now()
	return s
}

func (s *state) RemoveWireGuardPeer(pub string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < len(s.data.Peers); i++ {
		if s.data.Peers[i].PublicKey == pub {
			s.data.Peers = append(s.data.Peers[:i], s.data.Peers[i+1:]...)
			s.data.LastUpdatedAt = time.Now()
			return s
		}
	}

	return s
}

func (s *state) SetProfile(profile *Profile) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.Profile = profile
	return s
}

func (s *state) Commit() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// clone runtime object state to serialize-ready
	allRoutes := s.data.RuntimeManagedRoutes.Routes.Copy()
	for _, peer := range s.data.RuntimeManagedRoutes.Peers {
		for _, routes := range peer.Services {
			allRoutes.Join(routes)
		}
	}
	s.data.ManagedRoutes = allRoutes.Slice()

	// sort the managed routes by number of parts (spaces)
	// and for strings with the same number of parts, sort
	// them by IP bytes.
	sort.Slice(
		s.data.ManagedRoutes,
		func(i, j int) bool {
			// count spaces in both strings.
			iSpaceCount := strings.Count(s.data.ManagedRoutes[i], " ")
			jSpaceCount := strings.Count(s.data.ManagedRoutes[j], " ")
			// compare based on spaces.
			if iSpaceCount != jSpaceCount {
				return iSpaceCount < jSpaceCount
			}
			// extract IP addresses from the beginning of the strings.
			iIP := strings.Fields(s.data.ManagedRoutes[i])[0]
			jIP := strings.Fields(s.data.ManagedRoutes[j])[0]
			// parse IPs
			ip1, _, _ := net.ParseCIDR(iIP)
			ip2, _, _ := net.ParseCIDR(jIP)
			// if both IPs are valid, compare them.
			if ip1 != nil && ip2 != nil {
				return bytes.Compare(ip1, ip2) < 0
			}
			// if either IP is not valid, sort the original strings alphanumerically.
			return s.data.ManagedRoutes[i] < s.data.ManagedRoutes[j]
		},
	)

	dataBytes, err := yaml.Marshal(s.data)
	if err != nil {
		return fmt.Errorf("failed to encode state data to yaml: %v", err)
	}
	if err = os.WriteFile(s.path, append(doNotModifyHeader, dataBytes...), 0600); err != nil {
		return fmt.Errorf("failed to write state file: %v", err)
	}
	return nil
}

func (s *state) MarshalJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	byt, err := json.Marshal(s.data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal state data as JSON: %v", err)
	}
	return byt, nil
}

// GetPeerByIP returns the peer configuration that contains the given IP address.
func (s *state) GetPeerByIP(ip net.IP) *PeerConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ipStr := ip.String()
	for _, peer := range s.data.Peers {
		if ipStr == peer.IPv4Address || ipStr == peer.IPv6Address {
			return peer
		}
	}

	return nil
}

func (s *state) AddService(peer *PeerConfig, svc *device.Service) State {
	formattedPeer, ok := s.GetWireGuardPeer(peer.PublicKey)
	if !ok {
		return s
	}

	formattedPeer.Services = append(peer.Services, &ServiceConfig{
		Name:         svc.GetName(),
		Type:         svc.GetType(),
		IPv4Address:  svc.GetIpv4(),
		IPv6Address:  svc.GetIpv6(),
		SubnetRoutes: svc.GetSubnetRoutes(),
		DNSName:      svc.GetDnsName(),
		UpstreamType: svc.GetUpstreamType(),
	})

	if err := formattedPeer.decodeAndValidate(s.GetExitNode()); err != nil {
		s.logger.Error(
			"failed to decode and validate data for peer",
			zap.String("pub", peer.PublicKey),
			zap.Error(err),
		)
		return s
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < len(s.data.Peers); i++ {
		// replace existing peer if present
		if s.data.Peers[i].PublicKey == formattedPeer.PublicKey {
			s.data.Peers[i] = formattedPeer
			s.data.LastUpdatedAt = time.Now()
			return s
		}
	}

	s.data.Peers = append(s.data.Peers, formattedPeer)
	s.data.LastUpdatedAt = time.Now()

	return s
}

func (s *state) UpdateService(peer *PeerConfig, svc *device.Service) (State, bool) {
	formattedPeer, ok := s.GetWireGuardPeer(peer.PublicKey)
	if !ok {
		return s, false
	}

	changed := false
	for _, service := range formattedPeer.Services {
		if service.Name == svc.GetName() {
			if service.Type != svc.GetType() {
				service.Type = svc.GetType()
				changed = true
			}
			if service.IPv4Address != svc.GetIpv4() {
				service.IPv4Address = svc.GetIpv4()
				changed = true
			}
			if service.IPv6Address != svc.GetIpv6() {
				service.IPv6Address = svc.GetIpv6()
				changed = true
			}
			if n, r := slice.Diff(service.SubnetRoutes, svc.GetSubnetRoutes()); len(n) > 0 || len(r) > 0 {
				service.SubnetRoutes = svc.GetSubnetRoutes()
				changed = true
			}
		}
	}

	if !changed {
		return s, false
	}

	if err := formattedPeer.decodeAndValidate(s.GetExitNode()); err != nil {
		s.logger.Error(
			"failed to decode and validate data for peer",
			zap.String("pub", peer.PublicKey),
			zap.Error(err),
		)
		return s, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < len(s.data.Peers); i++ {
		// replace existing peer if present
		if s.data.Peers[i].PublicKey == formattedPeer.PublicKey {
			s.data.Peers[i] = formattedPeer
			s.data.LastUpdatedAt = time.Now()
			return s, true
		}
	}

	s.data.Peers = append(s.data.Peers, formattedPeer)
	s.data.LastUpdatedAt = time.Now()

	return s, true
}
func (s *state) RemoveService(peer *PeerConfig, svc *device.Service) State {
	formattedPeer, ok := s.GetWireGuardPeer(peer.PublicKey)
	if !ok {
		return s
	}

	for i, service := range formattedPeer.Services {
		if service.Name == svc.GetName() {
			formattedPeer.Services = append(formattedPeer.Services[:i], formattedPeer.Services[i+1:]...)
			break
		}
	}

	if err := formattedPeer.decodeAndValidate(s.GetExitNode()); err != nil {
		s.logger.Error(
			"failed to decode and validate data for peer",
			zap.String("pub", peer.PublicKey),
			zap.Error(err),
		)
		return s
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 0; i < len(s.data.Peers); i++ {
		// replace existing peer if present
		if s.data.Peers[i].PublicKey == formattedPeer.PublicKey {
			s.data.Peers[i] = formattedPeer
			s.data.LastUpdatedAt = time.Now()
			return s
		}
	}

	s.data.Peers = append(s.data.Peers, formattedPeer)
	s.data.LastUpdatedAt = time.Now()

	return s
}

func (s *state) ManagedRouteCount(cidr string) (count int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, route := range s.data.RuntimeManagedRoutes.Routes.Slice() {
		if route == cidr {
			count++
		}
	}

	for _, peer := range s.data.RuntimeManagedRoutes.Peers {
		for _, routes := range peer.Services {
			for _, route := range routes.Slice() {
				if route == cidr {
					count++
				}
			}
		}
	}

	return
}

func (s *state) GetExitNode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.data.ExitNode
}

func (s *state) SetExitNode(node string) State {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.ExitNode = node
	s.data.LastUpdatedAt = time.Now()

	for _, peer := range s.data.Peers {
		if err := peer.decodeAndValidate(node); err != nil {
			s.logger.Error(
				"failed to decode and validate data for peer",
				zap.String("pub", peer.PublicKey),
				zap.Error(err),
			)
		}
	}

	return s
}
