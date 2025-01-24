package endpoint

import (
	"net"
	"net/netip"
	"reflect"

	"github.com/borderzero/border0-cli/internal/device/wg/rebind"
	"github.com/borderzero/wireguard-go/conn"
)

// maybeRestrictedNAT represents a logical connection to a single wireguard peer.
// This implementation of conn.Endpoint is only used to receive packets.
// It is used because sometimes the source address's port is different than
// the port that the peer self-reported (from STUN). This happens when the
// peer is behind an endpoint-dependent NAT gateway. Without this, we would
// drop packets and have to rely only on the relay.
type maybeRestrictedNAT struct {
	// Wireguard peer's uniquely-identifying UDPv4 address. this is a deliberately
	// fake class E IPv4 address (and port) that is only used for wireguard to
	// identify the peer. Class E addresses are used because they are and will
	// likely always remain reserved and unused in the wild.
	//
	// We do not use the real endpoint address for the peer here because that
	// address is subject to change, whereas our fake one will not.
	uaddr []byte

	pconn rebind.PacketConn
	addr  net.Addr
}

// Ensures that maybeRestrictedNAT implements conn.Endpoint at compile-time.
var _ conn.Endpoint = (*maybeRestrictedNAT)(nil)

// NewMaybeRestrictedNAT is the maybeRestrictedNAT constructor.
func NewMaybeRestrictedNAT(pconn rebind.PacketConn, addrport net.Addr) *maybeRestrictedNAT {
	return &maybeRestrictedNAT{
		uaddr: fakeUdp4AddrPortClassE(uint64(reflect.ValueOf(&addrport).Pointer())),
		pconn: pconn,
		addr:  addrport,
	}
}

// ClearSrc does nothing (required to implement the interface).
func (r *maybeRestrictedNAT) ClearSrc() {}

// SrcToString panics (required to implement the conn.Endpoint interface, but not used by wireguard-go).
func (r *maybeRestrictedNAT) SrcToString() string { panic("not used by wireguard-go") }

// SrcIP panics (required to implement the conn.Endpoint interface, but not used by wireguard-go).
func (r *maybeRestrictedNAT) SrcIP() netip.Addr { panic("not used by wireguard-go") }

// DstToString returns the internal representation of the
// endpoint (which is the ip and port from which data was received).
func (r *maybeRestrictedNAT) DstToString() string { return r.addr.String() }

// DstToBytes returns the uniquely-identifying address of the endpoint.
func (r *maybeRestrictedNAT) DstToBytes() []byte { return r.uaddr }

// DstIP returns the endpoint's address.
func (r *maybeRestrictedNAT) DstIP() netip.Addr {
	return netip.MustParseAddrPort(r.addr.String()).Addr()
}
