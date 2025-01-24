package turtle

import (
	"net"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/turtle/internal/proto"
)

// RxPacketBufferSize is the recommended size of the buffer passed to ReadFrom().
const RxPacketBufferSize = proto.MaxUdpPacketSize

// Address returns the net.Addr for a given public key.
func Address(key *nacl.PublicKey) net.Addr { return proto.AddrFromKey(key) }
