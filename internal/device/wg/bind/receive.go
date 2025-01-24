package bind

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/borderzero/border0-cli/internal/device/utils/stun"
	"github.com/borderzero/border0-cli/internal/device/wg/endpoint"
	"github.com/borderzero/border0-cli/internal/device/wg/qos"
	"github.com/borderzero/border0-cli/internal/device/wg/rebind"
	"github.com/borderzero/wireguard-go/conn"
	"go.uber.org/zap"
)

// A ReceiveFunc receives at least one packet from the network and writes them into buffers.
// On a successful read it returns the number of elements of sizes, packets, and endpoints that should be evaluated.
// Some elements of sizes may be zero, and callers should ignore them.
// Callers must pass a sizes and eps slice with a length greater than or equal to the length of packets.
// These lengths must not exceed the length of the associated Bind.BatchSize().
func (b *Bind) getReceiveFunc(pconn rebind.PacketConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if !b.isOpen.Load() {
			return 0, net.ErrClosed
		}
		for i := range packets {
			ep, size, err := b.rxOne(pconn, packets[i])
			if err != nil {
				if b.logRxFailures {
					switch err.(type) {
					case *suppressedError:
						continue // error suppressed, do not log
					default:
						b.logger.Error(
							"failed to receive packet from packet conn",
							zap.String("pck_conn_addr", pconn.LocalAddr().String()),
							zap.Error(err),
						)
					}
				}
				continue
			}
			eps[i] = ep
			sizes[i] = size
		}

		return len(packets), nil
	}
}

// A getReceiveFuncForRelay receives at least one packet from the relay and writes them into buffers.
// On a successful read it returns the number of elements of sizes, packets, and endpoints that should be evaluated.
// Some elements of sizes may be zero, and callers should ignore them.
// Callers must pass a sizes and eps slice with a length greater than or equal to the length of packets.
// These lengths must not exceed the length of the associated Bind.BatchSize().
func (b *Bind) getReceiveFuncForRelay(pconn rebind.PacketConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if !b.isOpen.Load() {
			return 0, net.ErrClosed
		}
		for i := range packets {
			ep, size, err := b.rxOneForRelay(pconn, packets[i])
			if err != nil {
				if b.logRxFailures {
					switch err.(type) {
					case *suppressedError:
						continue // error suppressed, do not log
					default:
						b.logger.Error(
							"failed to receive packet from packet conn",
							zap.String("pck_conn_addr", pconn.LocalAddr().String()),
							zap.Error(err),
						)
					}
				}
				continue
			}
			eps[i] = ep
			sizes[i] = size
		}
		return len(packets), nil
	}
}

// rxOne reads a single packet from the given rebind.PacketConn.
func (b *Bind) rxOne(pconn rebind.PacketConn, pck []byte) (conn.Endpoint, int, error) {
	n, addr, err := pconn.ReadFrom(pck)
	if err != nil {
		if pconn.ShouldRebindOnError(err) {
			if b.isOpen.Load() && !b.isBinding.Load() {
				if err := pconn.Rebind(); err != nil {
					b.logger.Error("failed to rebind udp socket when encountering unexpected (but rebindable) error", zap.Error(err))
				}
			}
			return nil, 0, &suppressedError{err}
		}
		return nil, 0, fmt.Errorf("failed to read packet from packet conn: %v", err)
	}
	// STUN
	if b.handleStunMessage(pck[:n], addr) {
		return nil, 0, nil
	}
	// QOS
	if b.handleQOSCMessage(pconn, addr, pck[:n]) {
		return nil, 0, nil
	}
	// destination is a registered wireguard peer
	if ep, ok := b.epMap.GetByAddr(addr); ok {
		return ep, n, nil
	}
	// unrecognized udp traffic
	return b.endpointForUnrecognizedUdpTraffic(pconn, addr), n, nil
}

// rxOneForRelay reads a single packet from the given net.PacketConn.
func (b *Bind) rxOneForRelay(pconn rebind.PacketConn, pck []byte) (conn.Endpoint, int, error) {
	n, addr, err := pconn.ReadFrom(pck)
	if err != nil {
		if pconn.ShouldRebindOnError(err) {
			if b.isOpen.Load() && !b.isBinding.Load() {
				if err := pconn.Rebind(); err != nil {
					b.logger.Error("failed to rebind relay connection when encountering unexpected (but rebindable) error", zap.Error(err))
				}
			}
			return nil, 0, &suppressedError{err}
		}
		return nil, 0, fmt.Errorf("failed to read packet from packet conn: %v", err)
	}
	// QOS
	if b.handleQOSCMessage(pconn, addr, pck[:n]) {
		return nil, 0, nil
	}
	// destination is a registered wireguard peer
	if ep, ok := b.epMap.GetByPub(addr.String()); ok {
		return ep, n, nil
	}
	return nil, 0, fmt.Errorf("no way to handle packet from %s", addr.String())
}

// endpointForUnrecognizedUdpTraffic returns an endpoint (or nil) for
// traffic that has not yet been attributable to STUN, QOS, or a WireGuard
// peer from a known address (i.e. truly unrecognized traffic).
func (b *Bind) endpointForUnrecognizedUdpTraffic(pconn rebind.PacketConn, addr net.Addr) conn.Endpoint {
	// We only accept unexpected traffic over UDP connections (not relay)
	// so make sure that the given rebind.PacketConn is for a udp method.
	//
	// endpointForUnrecognizedUdpTraffic is only used in rxOne, which only
	// handles UDP traffic, so it is not possible for this branch to be
	// taken... we check this for defensive programming.
	method := pconn.Method()
	if method != rebind.MethodUdp4 && method != rebind.MethodUdp6 {
		b.logger.Error(
			"conn.Bind implementation's rxOne() got a packet with a non-udp address",
			zap.String("addr", addr.String()),
		)
		return nil
	}

	// The Bind implementation is only meant to receive WireGuard traffic and
	// a other types of traffic (STUN and QOS) which are already handled at this
	// point.
	//
	// The only things this can be are WireGuard traffic from a "roaming"
	// peer that does not support QOS (such as the WIP contractor's MacOS app)
	// or truly unknown traffic.
	//
	// We have to drop traffic coming from the VPN's private ranges in case this
	// is valid WireGuard traffic. If we don't do this, WireGuard might update
	// its internal configuration to have the peer's "endpoint" set to this
	// private address. We have seen this happen in the wild and it makes the
	// local peer get into an unrecoverable state.
	if len(b.disallowedSources) > 0 {
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			// This branch is not possible, checking for defensive programming.
			b.logger.Error(
				"conn.Bind implementation's rxOne() got a packet with a non-udp address",
				zap.String("addr", addr.String()),
			)
			return nil
		}
		netipAddr, ok := netip.AddrFromSlice(udpAddr.IP)
		if !ok {
			// This branch is not possible, checking for defensive programming.
			b.logger.Error(
				"conn.Bind implementation's rxOne() got a packet with an invalid UDP address",
				zap.String("addr", addr.String()),
			)
			return nil
		}
		for _, disallowedSource := range b.disallowedSources {
			// We have a match, return no endpoint (dropping the traffic and
			// preventing WireGuard from doing a handshake for traffic from
			// this address).
			if disallowedSource.Contains(netipAddr) {
				return nil
			}
		}
	}

	// Traffic at this point is either valid WireGuard traffic or truly unknown
	// traffic. WireGuard itself handle both cases gracefully, so we return a valid
	// conn.Endpoint implementation here.
	return endpoint.NewMaybeRestrictedNAT(pconn, addr)
}

// handleStunMessage tries to treat a byte slice as if it contains
// a UDP packet corresponding to a STUN response.
//
// Returns true if the packet was a STUN message and should not be
// processed any further by the caller. Errors are handled internally.
func (b *Bind) handleStunMessage(pck []byte, addr net.Addr) bool {
	stunMessage, ok := stun.ParseStunMessage(pck)
	if !ok {
		return false
	}
	b.stunner.Receive(stunMessage, addr)
	return true
}

// handleQOSCMessage tries to treat a byte slice as if it contains
// a UDP packet corresponding to a QOSC response.
//
// Returns true if the packet was a QOSC message and should not be
// processed any further by the caller. Errors are handled internally.
func (b *Bind) handleQOSCMessage(
	pconn rebind.PacketConn,
	addr net.Addr,
	pck []byte,
) bool {
	msg, ok, err := qos.ParseQOSMessage(b.naclKey, pck)
	if !ok {
		return false
	}
	if err != nil {
		b.logger.Error("failed to parse QOS message", zap.Error(err))
		return true
	}

	// ensure we want to do something with this probe
	ep, ok := b.epMap.GetByPub(msg.From().B64())
	if !ok {
		b.logger.Error("got a valid QOS message from an unknown peer", zap.String("pub", msg.From().B64()))
		return true
	}

	// if its a request, we simply echo it back.
	if msg.MessageType() == qos.MessageTypeRequest {
		if b.logQosProbes {
			b.logger.Debug("received QOS request", zap.Uint32("probe_id", msg.ProbeID()), zap.String("from", addr.String()))
		}
		if err := endpoint.HandleQOSRequest(b.epMap, ep, qos.NewResponse(b.naclKey, msg), pconn, addr); err != nil {
			b.logger.Error("failed to receive QOS response", zap.String("addr", addr.String()), zap.Error(err))
			return true
		}
		return true
	}

	// if its a response, we write it to the endpoint
	if b.logQosProbes {
		b.logger.Debug("received QOS response", zap.Uint32("probe_id", msg.ProbeID()), zap.String("from", addr.String()))
	}
	if err := endpoint.HandleQOSResponse(b.epMap, ep, msg, pconn, addr); err != nil {
		b.logger.Error("failed to receive QOS response", zap.String("addr", addr.String()), zap.Error(err))
		return true
	}
	return true
}
