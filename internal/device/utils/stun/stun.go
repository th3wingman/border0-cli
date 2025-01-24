package stun

import (
	"fmt"
	"net"
	"time"

	"github.com/borderzero/border0-go/lib/types/syncmap"
	"github.com/pion/stun/v3"
	"go.uber.org/zap"
)

// Network represents the network to send and
// receive STUN messages over (udp4 or udp6).
type Network string

const (
	// NetworkUDP4 represents the UDP-over-IPv4 network.
	NetworkUDP4 = "udp4"

	// NetworkUDP6 represents the UDP-over-IPv6 network.
	NetworkUDP6 = "udp6"
)

var (
	// TODO(@adriano): run our own STUN server and only use
	// public servers as a fallback, e.g. ~5 consecutive STUN
	// requests with no response after ~5 seconds.
	stunServers = map[string]string{
		"stun.cloudflare.com": "3478",
		"stun.l.google.com":   "19302",
	}
)

// OnRxFunc represents what to do when receiving a STUN response.
type OnRxFunc func(*net.UDPAddr)

// Stunner is an entity capable of sending and tracking STUN requests.
type Stunner interface {
	Send(network Network, pconn net.PacketConn) error
	Receive(resp *stun.Message, from net.Addr)
	Reset()
}

// stunner is an entity capable of sending and tracking STUN requests.
type stunner struct {
	logger          *zap.Logger
	onRx            OnRxFunc
	attemptsPerReq  int           // how many times we will try per STUN request
	waitBeforeRetry time.Duration // how long to wait between retries

	inFlight *syncmap.Map[[stun.TransactionIDSize]byte, *transaction]
}

// NewStunner returns a newly initialized default implementation of the Stunner interface.
func NewStunner(logger *zap.Logger, onRx OnRxFunc, attemptsPerReq int, waitBeforeRetry time.Duration) Stunner {
	return &stunner{
		logger:          logger,
		onRx:            onRx,
		attemptsPerReq:  attemptsPerReq,
		waitBeforeRetry: waitBeforeRetry,
		inFlight:        syncmap.New[[stun.TransactionIDSize]byte, *transaction](),
	}
}

// Send sends a stun request for the given network over a given net.PacketConn.
// Network must be one of "udp4" or "udp6".
func (s *stunner) Send(network Network, pconn net.PacketConn) error {
	request, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return fmt.Errorf("failed to build STUN message: %v", err)
	}
	go s.send(network, pconn, request)
	return nil
}

// send will initialize state for a new stun request, and then wait until either
// all attempts at sending and waiting have been exceeded, or a response is received.
func (s *stunner) send(network Network, pconn net.PacketConn, req *stun.Message) {
	tx := newTransaction()
	defer tx.expire()

	s.inFlight.Store(req.TransactionID, tx)
	defer s.inFlight.Delete(req.TransactionID)

	attempts := 0
	s.sendOne(network, pconn, req, &attempts)

	for attempt := 1; attempt < s.attemptsPerReq; attempt++ {
		select {
		case response, ok := <-tx.ch:
			if !ok {
				return // channel was closed, return
			}
			addr, err := extractAddress(response)
			if err != nil {
				s.logger.Error("failed to extract address from stun message", zap.Error(err))
				continue
			}
			go s.onRx(addr)
			return
		case <-time.After(s.waitBeforeRetry):
			s.sendOne(network, pconn, req, &attempts)
		}
	}
}

// sendOne iterates over all stun servers, resolving their address and sending them the same STUN request.
func (s *stunner) sendOne(network Network, pconn net.PacketConn, req *stun.Message, attempt *int) {
	networkStr := string(network)

	for stunServerHost, stunServerPort := range stunServers {
		go func() {
			stunServerAddress, err := net.ResolveUDPAddr(networkStr, net.JoinHostPort(stunServerHost, stunServerPort))
			if err != nil {
				s.logger.Warn(
					"STUN module failed to resolve address",
					zap.Int("stun_attempt", *attempt),
					zap.String("network", networkStr),
					zap.String("stun_server_host", stunServerHost),
					zap.Error(err),
				)
				return
			}
			nWritten, err := pconn.WriteTo(req.Raw, stunServerAddress)
			if err != nil {
				s.logger.Warn(
					"STUN module failed to write STUN message to server",
					zap.Int("stun_attempt", *attempt),
					zap.String("network", networkStr),
					zap.String("stun_server_host", stunServerHost),
					zap.Error(err),
				)
				return
			}
			if nWritten != len(req.Raw) {
				s.logger.Warn(
					"STUN message bytes written did not match message size",
					zap.Int("stun_attempt", *attempt),
					zap.String("network", networkStr),
					zap.String("stun_server_host", stunServerHost),
					zap.Int("written", nWritten),
					zap.Int("size", len(req.Raw)),
				)
				return
			}
		}()
	}

	(*attempt)++
}

// Reset cancels all in-flight requests in the stunner such that
// No responses for existing requests in-flight result in any actions.
func (s *stunner) Reset() {
	// NOTE: the channel will be closed by still-ongoing function.
	// Here we simply make sure that no signals can be delivered
	// to the channel for any active STUN requests any more.
	s.inFlight.Range(func(key [12]byte, tx *transaction) bool {
		s.inFlight.Delete(key)
		tx.expire()
		return true
	})
}

// ExtractAddress extracts the address from a STUN response message.
func (s *stunner) Receive(resp *stun.Message, _ net.Addr) {
	if tx, loaded := s.inFlight.Load(resp.TransactionID); loaded {
		tx.receive(resp)
	}
}

// ParseStunMessage parses a STUN message from a UDP packet.
// Returns true if the packet indeed contained a STUN message.
func ParseStunMessage(pck []byte) (*stun.Message, bool) {
	stunResponse := &stun.Message{Raw: pck}
	if err := stunResponse.Decode(); err != nil {
		return nil, false
	}
	return stunResponse, true
}

// extractAddress extracts the address from a STUN response message.
func extractAddress(resp *stun.Message) (*net.UDPAddr, error) {
	var self stun.XORMappedAddress
	if err := self.GetFrom(resp); err != nil {
		return nil, fmt.Errorf("failed to get XOR mapped address from STUN response: %v", err)
	}
	return &net.UDPAddr{IP: self.IP, Port: self.Port}, nil
}
