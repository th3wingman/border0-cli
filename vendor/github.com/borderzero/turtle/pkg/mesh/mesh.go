package mesh

import (
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/border0-go/lib/types/set"
)

type Peer struct {
	Addr string
	Pub  *nacl.PublicKey
}

type Mesh interface {
	HasPeer(relayPub *nacl.PublicKey) bool
	GetPeerDetails() map[string]*nacl.PublicKey
	AddPeer(*Peer) error
	RemoveRelayPeers(relayPub *nacl.PublicKey) bool
	GetRelayForClient(clientPub *nacl.PublicKey) (*nacl.PublicKey, bool)
	AddClientsToRelay(relayPub *nacl.PublicKey, clientPubs ...*nacl.PublicKey) error
	RemoveClientFromRelay(relayPub, clientPub *nacl.PublicKey) error
	GetTlsConfig() *tls.Config
}

type mesh struct {
	relays        *sync.Map
	clientToRelay *sync.Map
	tlsConfig     *tls.Config
}

type peer struct {
	addr    string
	pub     *nacl.PublicKey
	clients set.Set[string]
}

type Option func(*mesh)

func WithTlsConfig(config *tls.Config) Option {
	return func(m *mesh) { m.tlsConfig = config }
}

func New(opts ...Option) Mesh {
	m := &mesh{
		relays:        &sync.Map{},
		clientToRelay: &sync.Map{},
		tlsConfig:     &tls.Config{},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *mesh) HasPeer(relayPub *nacl.PublicKey) bool {
	_, ok := m.relays.Load(relayPub.B64())
	return ok
}

func (m *mesh) GetPeerDetails() map[string]*nacl.PublicKey {
	peers := make(map[string]*nacl.PublicKey)
	m.relays.Range(func(key, value any) bool {
		peers[value.(*peer).addr] = value.(*peer).pub
		return true
	})
	return peers
}

func (m *mesh) AddPeer(relay *Peer) error {
	_, ok := m.relays.LoadOrStore(relay.Pub.B64(), &peer{
		addr:    relay.Addr,
		pub:     relay.Pub,
		clients: set.NewConcurrencySafe[string](),
	})
	if ok {
		return fmt.Errorf("relay %s already existed in mesh", relay.Pub.B64())
	}
	return nil
}

func (m *mesh) RemoveRelayPeers(relayPub *nacl.PublicKey) bool {
	// load the relay
	p, ok := m.relays.Load(relayPub.B64())
	if !ok {
		return true
	}
	// remove the relay's clients
	for _, clientPub := range p.(*peer).clients.Slice() {
		m.clientToRelay.Delete(clientPub)
	}
	return true
}

func (m *mesh) GetRelayForClient(clientPub *nacl.PublicKey) (*nacl.PublicKey, bool) {
	if relayPubB64, ok := m.clientToRelay.Load(clientPub.B64()); ok {
		relayPub, err := nacl.ParsePublicKeyB64(relayPubB64.(string))
		if err != nil {
			panic(fmt.Errorf("a peer's b64 public key could not be parsed %s: %v", relayPubB64.(string), err))
		}
		return relayPub, true
	}
	return nil, false
}

func (m *mesh) AddClientsToRelay(relayPub *nacl.PublicKey, clientPubs ...*nacl.PublicKey) error {
	// retrieve relay
	relay, ok := m.relays.Load(relayPub.B64())
	if !ok {
		return fmt.Errorf("relay %s does not exist in mesh", relayPub.B64())
	}
	for _, clientPub := range clientPubs {
		// remove from an existing relay if it was already present
		if existingRelay, present := m.clientToRelay.Load(clientPub.B64()); present {
			existingRelay.(*peer).clients.Remove(clientPub.B64())
		}
		// add to the new relay
		relay.(*peer).clients.Add(clientPub.B64())
		m.clientToRelay.Store(clientPub.B64(), relayPub.B64())
	}
	return nil

}

func (m *mesh) RemoveClientFromRelay(relayPub, clientPub *nacl.PublicKey) error {
	if loaded, ok := m.relays.Load(relayPub.B64()); ok {
		loaded.(*peer).clients.Remove(clientPub.B64())
		m.clientToRelay.Delete(clientPub.B64())
		return nil
	}
	return fmt.Errorf("relay %s does not exist in mesh", relayPub.B64())
}

func (m *mesh) GetTlsConfig() *tls.Config {
	return m.tlsConfig
}
