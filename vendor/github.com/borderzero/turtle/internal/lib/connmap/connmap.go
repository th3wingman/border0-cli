package connmap

import (
	"net"
	"sync"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/turtle/internal/lib/keyconn"
)

// ConnMap is a map of address to connection.
type ConnMap interface {
	Set(net.Addr, *keyconn.KeyConn)
	Get(net.Addr) (*keyconn.KeyConn, bool)
	ConditionallyDelete(net.Addr, func(*keyconn.KeyConn) bool)
	Keys() []*nacl.PublicKey
}

// connmap is the default implementation of the ConnMap interface.
type connmap struct {
	mu    sync.RWMutex
	conns map[string]*keyconn.KeyConn
}

// New returns a newly initialized ConnMap.
func New() ConnMap {
	return &connmap{
		mu:    sync.RWMutex{},
		conns: make(map[string]*keyconn.KeyConn),
	}
}

// Set sets a new connection in the connmap.
func (cm *connmap) Set(addr net.Addr, conn *keyconn.KeyConn) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	cm.conns[addr.String()] = conn
}

// Get gets a connection in the connmap.
func (cm *connmap) Get(addr net.Addr) (*keyconn.KeyConn, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	conn, ok := cm.conns[addr.String()]
	return conn, ok
}

// ConditionallyDelete deletes a connection from the connmap if a given condition is satisfied.
func (cm *connmap) ConditionallyDelete(addr net.Addr, cond func(*keyconn.KeyConn) bool) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	wlc, ok := cm.conns[addr.String()]
	if ok {
		if shouldDelete := cond(wlc); shouldDelete {
			delete(cm.conns, addr.String())
		}
	}
}

// Keys gets all keys for connections in the map.
func (cm *connmap) Keys() []*nacl.PublicKey {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	keys := make([]*nacl.PublicKey, 0, len(cm.conns))
	for _, conn := range cm.conns {
		keys = append(keys, conn.Key())
	}
	return keys
}
