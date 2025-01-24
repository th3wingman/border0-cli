package proto

import (
	"net"

	"github.com/borderzero/border0-go/lib/nacl"
)

// address is a net.Addr implementation which
// uses noise public keys for unique addressing.
type address struct {
	key *nacl.PublicKey
	b64 string
}

// AddrFromKey returns a new address implementation of net.Addr.
func AddrFromKey(key *nacl.PublicKey) net.Addr { return addrFromKey(key) }

// addrFromKey returns a new address
func addrFromKey(key *nacl.PublicKey) *address { return &address{key: key, b64: key.B64()} }

// Network returns the name of the network.
func (a *address) Network() string { return "turtle" }

// String returns the string form of the address.
func (a *address) String() string { return a.b64 }
