package endpoint

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"

	"github.com/borderzero/border0-cli/internal/device/wg/qos"
	"github.com/borderzero/border0-cli/internal/device/wg/rebind"
	"github.com/borderzero/border0-go/lib/nacl"

	"github.com/borderzero/wireguard-go/conn"
)

// endpoint represents a logical connection to a single wireguard peer.
// Under the hood the logical connection maintains multiple active connections
// each representing a way to communicate with the remote peer. At all times,
// the most favourable connection is used to send packets to the remote peer.
// The "most favourable" is a determined by a heuristic which may depend on
// wire MTU, round-trip-time (RTT), and other factors.
type endpoint struct {
	// Wireguard peer's uniquely-identifying UDPv4 address. this is a deliberately
	// fake class E IPv4 address (and port) that is only used for wireguard to
	// identify the peer. Class E addresses are used because they are and will
	// likely always remain reserved and unused in the wild.
	//
	// We do not use the real endpoint address for the peer here because that
	// address is subject to change, whereas our fake one will not.
	uaddr []byte

	// (remote) WireGuard peer's public key
	pub *nacl.PublicKey

	qosconn *qos.Conn

	// used only for stats/debug only
	alias       string
	privateIPv4 string
	privateIPv6 string
}

// Ensures that endpoint implements conn.Endpoint at compile-time.
var _ conn.Endpoint = (*endpoint)(nil)

// New is the endpoint constructor.
func New(pub *nacl.PublicKey, qosconn *qos.Conn, alias, privateIPv4, privateIPv6 string) *endpoint {
	return &endpoint{
		pub:         pub,
		uaddr:       fakeUdp4AddrPortClassE(uint64(reflect.ValueOf(&pub).Pointer())),
		qosconn:     qosconn,
		alias:       alias,
		privateIPv4: privateIPv4,
		privateIPv6: privateIPv6,
	}
}

// ClearSrc does nothing (required to implement the interface).
func (e *endpoint) ClearSrc() {}

// SrcToString panics (required to implement the conn.Endpoint interface, but not used by wireguard-go).
func (e *endpoint) SrcToString() string { panic("not used by wireguard-go") }

// SrcIP panics (required to implement the conn.Endpoint interface, but not used by wireguard-go).
func (e *endpoint) SrcIP() netip.Addr { panic("not used by wireguard-go") }

// DstToString returns the internal representation of the
// endpoint (which is the peer's base64-encoded public key).
func (e *endpoint) DstToString() string { return e.pub.B64() }

// DstToBytes returns the uniquely-identifying address of the endpoint.
func (e *endpoint) DstToBytes() []byte { return e.uaddr }

// DstIP returns the endpoint's address.
func (e *endpoint) DstIP() netip.Addr {
	return e.qosconn.CurrentAddress()
}

func HandleQOSRequest(emap Mapping, ep conn.Endpoint, req *qos.Message, pconn rebind.PacketConn, from net.Addr) error {
	if endpoint, ok := ep.(*endpoint); ok {
		if !endpoint.qosconn.AllowQosTrafficFrom(pconn, from) {
			return nil
		}
		if _, err := pconn.WriteTo(req.Encode(), from); err != nil {
			return fmt.Errorf("failed to echo QOS message back to requester: %v", err)
		}
		if _, _, isNew := endpoint.qosconn.EnsureCandidate(pconn, from); isNew {
			// if the connection candidate is new, we must update the
			// peer's addresses in the internal endpoint mappings.
			emap.Set(ep)
		}
		return nil
	}
	return fmt.Errorf("expected the concrete type of the given conn.Endpoint to be endpoint but got %T", ep)
}

func HandleQOSResponse(emap Mapping, ep conn.Endpoint, qosmsg *qos.Message, pconn rebind.PacketConn, from net.Addr) error {
	if endpoint, ok := ep.(*endpoint); ok {
		if isNew := endpoint.qosconn.ProbeResponseFrom(qosmsg, pconn, from); isNew {
			// if the connection candidate is new, we must update the
			// peer's addresses in the internal endpoint mappings.
			emap.Set(ep)
		}
		return nil
	}
	return fmt.Errorf("expected the concrete type of the given conn.Endpoint to be endpoint but got %T", ep)
}

func StopQOSChecks(ep conn.Endpoint) {
	if endpoint, ok := ep.(*endpoint); ok {
		endpoint.qosconn.Close()
	}
}

// Send sends data to the given endpoint over the preferred connection.
func Send(ep conn.Endpoint, eMap Mapping, buffs [][]byte) error {
	switch concrete := ep.(type) {
	case *endpoint:
		return concrete.qosconn.Send(buffs)
	case *maybeRestrictedNAT:
		for i := 0; i < len(buffs); i++ {
			if _, err := concrete.pconn.WriteTo(buffs[i], concrete.addr); err != nil {
				return fmt.Errorf("failed to write buffer at index %d to nat-restricted connection: %v", i, err)
			}
		}
		return nil
	case *conn.KeyedEndpoint:
		inner := concrete.GetInner()
		switch inner := inner.(type) {
		case *endpoint:
			return inner.qosconn.Send(buffs)
		case *maybeRestrictedNAT:
			// for i := 0; i < len(buffs); i++ {
			// 	if _, err := inner.pconn.WriteTo(buffs[i], inner.addr); err != nil {
			// 		return fmt.Errorf("failed to write buffer at index %d to nat-restricted inner connection: %v", i, err)
			// 	}
			// }
			// return nil

			// NOTE: in order for us to support the MacOS app built by the
			// contractors we **HAVE** to support maybeRestrictedNAT endpoints.
			// Additionally to requiring support for this here, if you want the
			// contractors to be able to talk to a connector, the connector must
			// have the relay disabled using BORDER0_ALLOWED_METHODS i.e. set env
			// BORDER0_ALLOWED_METHODS=udp4 to only allow UDP-over IP
			pub := concrete.GetPublicKey().B64()
			staticEndpoint, ok := eMap.GetByPub(pub)
			if !ok {
				return fmt.Errorf("no static endpoint found for key %s", pub)
			}
			staticEndpoint.(*endpoint).qosconn.EnsureCandidate(inner.pconn, inner.addr)
			return staticEndpoint.(*endpoint).qosconn.Send(buffs)
		default:
			return fmt.Errorf("unexpected concrete type %T for the given inner conn.Endpoint", inner)
		}
	default:
		return fmt.Errorf("unexpected concrete type %T for the given conn.Endpoint", concrete)
	}
}
