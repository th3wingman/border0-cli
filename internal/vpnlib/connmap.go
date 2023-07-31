package vpnlib

import (
	"net"
	"sync"
)

// ConnectionMap is a concurrent-safe map for managing connections.
// The key is the client IP address, and the value is the net.Conn for that connection
type ConnectionMap struct {
	sync.RWMutex

	Connections map[string]net.Conn
}

// NewConnectionMap creates a new ConnectionMap with an empty map.
// This map will be used to keep track of connections to clients.
func NewConnectionMap() *ConnectionMap {
	return &ConnectionMap{
		Connections: make(map[string]net.Conn),
	}
}

// Get retrieves a connection (Net.Conn) by IP from the map.
func (cm *ConnectionMap) Get(ip string) (net.Conn, bool) {
	cm.RLock()
	defer cm.RUnlock()

	conn, exists := cm.Connections[ip]
	return conn, exists
}

// Set adds a connection to the map.
func (cm *ConnectionMap) Set(ip string, conn net.Conn) {
	cm.Lock()
	defer cm.Unlock()

	cm.Connections[ip] = conn
}

// Delete removes a connection from the connection map
func (cm *ConnectionMap) Delete(ip string) {
	cm.Lock()
	defer cm.Unlock()

	delete(cm.Connections, ip)
}
