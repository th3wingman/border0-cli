package endpoint

import (
	"net"
	"sync"

	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/wireguard-go/conn"
)

// Mapping represents a way to keep track of peers.
type Mapping interface {
	Set(ep conn.Endpoint)
	GetByPub(pub string) (conn.Endpoint, bool)
	GetByAddr(addr net.Addr) (conn.Endpoint, bool)
	DeleteByPub(pub string)
	GetStats() ([]stats.Peer, error)
}

// mapping implements Mapping with in-memory maps and a mutex.
type mapping struct {
	mu sync.RWMutex

	byPub  map[string]*endpoint
	byAddr map[string]*endpoint
}

// NewMapping returns the default implementation of the Mapping interface.
func NewMapping() Mapping {
	return &mapping{
		mu:     sync.RWMutex{},
		byPub:  make(map[string]*endpoint),
		byAddr: make(map[string]*endpoint),
	}
}

// Set sets a conn.Endpoint in the mapping.
func (m *mapping) Set(ep conn.Endpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()

	upToDateEndpoint := ep.(*endpoint)
	upToDatePub := upToDateEndpoint.pub.B64()

	upToDateUdp4s := upToDateEndpoint.qosconn.Udp4Addrs()
	upToDateUdp6s := upToDateEndpoint.qosconn.Udp6Addrs()

	upToDateUdp4Set := set.New[string]()
	upToDateUdp6Set := set.New[string]()

	// map the latest addresses to the up-to-date endpoint
	for _, upToDateUdp4 := range upToDateUdp4s {
		if upToDateUdp4.IsValid() {
			upToDateUdp4Str := upToDateUdp4.String()
			upToDateUdp4Set.Add(upToDateUdp4Str)
			m.byAddr[upToDateUdp4Str] = upToDateEndpoint
		}
	}
	for _, upToDateUdp6 := range upToDateUdp6s {
		if upToDateUdp6.IsValid() {
			upToDateUdp6Str := upToDateUdp6.String()
			upToDateUdp6Set.Add(upToDateUdp6Str)
			m.byAddr[upToDateUdp6Str] = upToDateEndpoint
		}
	}

	// if there was already an entry for this pub
	// we may have to clean up outdated addresses.
	if endpointInMap, alreadyInMap := m.byPub[upToDatePub]; alreadyInMap {
		inMapUdp4s := endpointInMap.qosconn.Udp4Addrs()
		inMapUdp6s := endpointInMap.qosconn.Udp6Addrs()

		// if the existing endpoint had a udp4 address and the updated one does not OR
		// if the existing endpoint had a different udp4 address than the updated one, delete the existing address.
		for _, inMapUdp4 := range inMapUdp4s {
			if inMapUdp4.IsValid() {
				if !upToDateUdp4Set.Has(inMapUdp4.String()) {
					delete(m.byAddr, inMapUdp4.String())
				}
			}
		}
		// if the existing endpoint had a udp6 address and the updated one does not OR
		// if the existing endpoint had a different udp6 address than the updated one, delete the existing address.
		for _, inMapUdp6 := range inMapUdp6s {
			if inMapUdp6.IsValid() {
				if !upToDateUdp6Set.Has(inMapUdp6.String()) {
					delete(m.byAddr, inMapUdp6.String())
				}
			}
		}
	}

	// map the public key to the up-to-date endpoint
	m.byPub[upToDatePub] = upToDateEndpoint
}

// GetByPub returns the endpoint corresponding to a public key.
func (m *mapping) GetByPub(pub string) (conn.Endpoint, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ep, ok := m.byPub[pub]
	return ep, ok
}

// GetByAddr returns the endpoint corresponding to an endpoint (public) address.
func (m *mapping) GetByAddr(addr net.Addr) (conn.Endpoint, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ep, ok := m.byAddr[addr.String()]
	return ep, ok
}

// DeleteByPub removes an endpoint from the Mappign by (public) address.
func (m *mapping) DeleteByPub(pub string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if endpointInMap, ok := m.byPub[pub]; ok {
		for _, inMapUdp4 := range endpointInMap.qosconn.Udp4Addrs() {
			if inMapUdp4.IsValid() {
				delete(m.byAddr, inMapUdp4.String())
			}
		}
		for _, inMapUdp6 := range endpointInMap.qosconn.Udp6Addrs() {
			if inMapUdp6.IsValid() {
				delete(m.byAddr, inMapUdp6.String())
			}
		}
	}
	delete(m.byPub, pub)
}

// GetStats returns stats
func (m *mapping) GetStats() ([]stats.Peer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := []stats.Peer{}
	for key, ep := range m.byPub {
		peers = append(peers, stats.Peer{
			PublicKey:   key,
			Alias:       ep.alias,
			PrivateIPv4: ep.privateIPv4,
			PrivateIPv6: ep.privateIPv6,
			Connections: ep.qosconn.Stats(),
		})
	}
	return peers, nil
}
