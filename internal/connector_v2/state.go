package connectorv2

import (
	"sync"

	b0 "github.com/borderzero/border0-cli/internal/border0"
	"github.com/borderzero/border0-cli/internal/connector_v2/plugin"
)

type state interface {
	connectorPluginsState
	connectorSocketsState
}

type connectorPluginsState interface {
	GetPlugin(id string) (plugin.Plugin, bool)
	GetPluginIDs() []string
	SetPlugin(id string, pl plugin.Plugin)
	DeletePlugin(id string)
}

type connectorSocketsState interface {
	GetSocket(id string) (*b0.Socket, bool)
	GetSocketIDs() []string
	SetSocket(id string, sck *b0.Socket)
	DeleteSocket(id string)
}

type inMemoryState struct {
	lk sync.RWMutex

	plugins map[string]plugin.Plugin
	sockets map[string]*b0.Socket
}

func newState() state {
	return &inMemoryState{
		plugins: make(map[string]plugin.Plugin),
		sockets: make(map[string]*b0.Socket),
	}
}

func (s *inMemoryState) GetPlugin(id string) (plugin.Plugin, bool) { return mget(&s.lk, s.plugins, id) }
func (s *inMemoryState) GetPluginIDs() []string                    { return mkeys(&s.lk, s.plugins) }
func (s *inMemoryState) SetPlugin(id string, pl plugin.Plugin)     { mset(&s.lk, s.plugins, id, pl) }
func (s *inMemoryState) DeletePlugin(id string)                    { mdel(&s.lk, s.plugins, id) }
func (s *inMemoryState) GetSocket(id string) (*b0.Socket, bool)    { return mget(&s.lk, s.sockets, id) }
func (s *inMemoryState) GetSocketIDs() []string                    { return mkeys(&s.lk, s.sockets) }
func (s *inMemoryState) SetSocket(id string, sck *b0.Socket)       { mset(&s.lk, s.sockets, id, sck) }
func (s *inMemoryState) DeleteSocket(id string)                    { mdel(&s.lk, s.sockets, id) }

func mget[T any](lock *sync.RWMutex, m map[string]T, key string) (T, bool) {
	lock.RLock()
	defer lock.RUnlock()

	value, ok := m[key]
	return value, ok
}

func mkeys[T any](lock *sync.RWMutex, m map[string]T) []string {
	lock.RLock()
	defer lock.RUnlock()

	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	return ids
}

func mset[T any](lock *sync.RWMutex, m map[string]T, key string, value T) {
	lock.Lock()
	defer lock.Unlock()

	m[key] = value
}

func mdel[T any](lock *sync.RWMutex, m map[string]T, key string) {
	lock.Lock()
	defer lock.Unlock()

	delete(m, key)
}
