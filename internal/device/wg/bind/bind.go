package bind

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/device/utils/stun"
	"github.com/borderzero/border0-cli/internal/device/wg/endpoint"
	"github.com/borderzero/border0-cli/internal/device/wg/rebind"
	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/wireguard-go/conn"
	"go.uber.org/atomic"
	"go.uber.org/zap"
)

var (
	// ErrBindOpen is returned when attempting to open an already open bind.
	ErrBindOpen = errors.New("bind is open")
)

const (
	stunAttemptsPerRequest = 30 // stun is essential for p2p so we retry a lot
	stunWaitBeforeRetry    = time.Second * 2
)

// Bind listens on a port for both IPv6 and IPv4 UDP traffic.
type Bind struct {
	logger   *zap.Logger
	naclKey  *nacl.PrivateKey
	relayURL string
	epMap    endpoint.Mapping
	stunner  stun.Stunner

	setup     *sync.Once
	rxFuncs   []conn.ReceiveFunc
	isOpen    *atomic.Bool
	isBinding *atomic.Bool
	udp4      rebind.PacketConn
	udp6      rebind.PacketConn
	relay     rebind.PacketConn
	port      uint16

	disallowedSources []netip.Prefix

	logRxFailures bool
	logQosProbes  bool
}

// Ensures that Bind implements conn.Bind at compile-time.
var _ conn.Bind = (*Bind)(nil)

// New is the bind constructor.
func New(
	logger *zap.Logger,
	naclKey *nacl.PrivateKey,
	relayURL string,
	mapping endpoint.Mapping,
	onSTUN stun.OnRxFunc,
	disallowedSources []netip.Prefix,
	port uint16,
) *Bind {
	return &Bind{
		logger:    logger,
		naclKey:   naclKey,
		relayURL:  relayURL,
		epMap:     mapping,
		stunner:   stun.NewStunner(logger, onSTUN, stunAttemptsPerRequest, stunWaitBeforeRetry),
		setup:     &sync.Once{},
		rxFuncs:   []conn.ReceiveFunc{},
		isOpen:    atomic.NewBool(false),
		isBinding: atomic.NewBool(false),
		udp4:      nil,
		udp6:      nil,
		relay:     nil,
		port:      port,

		disallowedSources: disallowedSources,

		logRxFailures: (strings.ToLower(os.Getenv("BORDER0_VERY_VERBOSE")) == "true"),
		logQosProbes:  (strings.ToLower(os.Getenv("BORDER0_VERY_VERBOSE")) == "true"),
	}
}

// Open puts the Bind into a listening state on a randomly selected port. The returned
// slice of ReceiveFunc is the set of functions that will be called to receive packets.
func (b *Bind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	if !b.isOpen.CompareAndSwap(false, true) {
		return nil, 0, ErrBindOpen // already open
	}

	isFirstTimeSetup := false
	b.setup.Do(func() {
		isFirstTimeSetup = true

		b.logger.Info("bind opening requested, opening udp4, upd6, and relay packet streams")
		b.stunner.Reset() // cancel in-flight STUN requests
		udp4, err := rebind.ListenPacketUdp4(b.logger, b.port)
		if err != nil {
			b.logger.Warn("failed to set up rebinding listener for udp4 network", zap.Error(err))
		} else {
			if err := b.stunner.Send(stun.NetworkUDP4, udp4); err != nil {
				b.logger.Warn("failed to send STUN request with udp4 packet conn", zap.Error(err))
			}
		}
		udp6, err := rebind.ListenPacketUdp6(b.logger, b.port)
		if err != nil {
			b.logger.Warn("failed to set up rebinding listener for udp6 network", zap.Error(err))
		} else {
			if err := b.stunner.Send(stun.NetworkUDP6, udp6); err != nil {
				b.logger.Warn("failed to send STUN request with udp6 packet conn", zap.Error(err))
			}
		}
		relay, err := rebind.ListenPacketUdpR(b.logger, b.relayURL, b.naclKey)
		if err != nil {
			b.logger.Warn("failed to set up rebinding listener for udprelay network", zap.Error(err))
		}

		b.udp4 = udp4
		b.udp6 = udp6
		b.relay = relay
		b.rxFuncs = []conn.ReceiveFunc{
			b.getReceiveFunc(b.udp4),
			b.getReceiveFunc(b.udp6),
			b.getReceiveFuncForRelay(b.relay),
		}
	})

	if !isFirstTimeSetup {
		b.Rebind()
	}

	return b.rxFuncs, b.udp4.Port(), nil
}

// Rebind rebinds the Bind for all connections.
func (b *Bind) Rebind() {
	b.isBinding.Store(true)
	defer b.isBinding.Store(false)
	b.logger.Info("bind rebind requested, rebinding udp4, upd6, and relay packet streams")
	b.stunner.Reset() // cancel in-flight STUN requests
	if err := b.udp4.Rebind(); err != nil {
		b.logger.Warn("failed to re-bind rebinding listener for udp4 network: %v", zap.Error(err))
	} else {
		if err := b.stunner.Send(stun.NetworkUDP4, b.udp4); err != nil {
			b.logger.Warn("failed to send STUN request with udp4 packet conn", zap.Error(err))
		}
	}
	if err := b.udp6.Rebind(); err != nil {
		b.logger.Warn("failed to re-bind rebinding listener for udp6 network: %v", zap.Error(err))
	} else {
		if err := b.stunner.Send(stun.NetworkUDP6, b.udp6); err != nil {
			b.logger.Warn("failed to send STUN request with udp6 packet conn", zap.Error(err))
		}
	}
	if err := b.relay.Rebind(); err != nil {
		b.logger.Warn("failed to re-bind rebinding listener for udprelay network: %v", zap.Error(err))
	}
}

// Close closes the Bind listener. All fns returned by Open must return net.ErrClosed
// after a call to Close.
func (b *Bind) Close() error {
	if !b.isOpen.CompareAndSwap(true, false) {
		return nil // already closed
	}
	b.logger.Info("bind closure requested, closing udp4, upd6, and relay packet streams")
	b.stunner.Reset() // cancel in-flight STUN requests
	if err := b.udp4.Close(); err != nil {
		b.logger.Debug("failed to close udp4 packet conn", zap.Error(err))
	}
	if err := b.udp6.Close(); err != nil {
		b.logger.Debug("failed to close udp6 packet conn", zap.Error(err))
	}
	if err := b.relay.Close(); err != nil {
		b.logger.Debug("failed to close relay packet conn", zap.Error(err))
	}
	return nil
}

// SetMark sets the mark for each packet sent through this Bind. This mark is passed
// to the kernel as the socket option SO_MARK.
func (b *Bind) SetMark(mark uint32) error {
	return nil
}

// BatchSize is the number of buffers expected to be passed to the ReceiveFuncs,
// and the maximum expected to be passed to SendBatch.
func (b *Bind) BatchSize() int {
	return 1 // optimize this later, first make it work with batch of 1
}

// ParseEndpoint creates a new endpoint from a string.
func (b *Bind) ParseEndpoint(endpoint string) (conn.Endpoint, error) {
	e, ok := b.epMap.GetByPub(endpoint)
	if !ok {
		b.logger.Error("got a ParseEndpoint request for a peer with no endpoint", zap.String("endpoint", endpoint))
		return nil, fmt.Errorf("unknown endpoint for peer with endpoint %s", endpoint)
	}
	return e, nil
}

// Send sends data to the given endpoint.
func (b *Bind) Send(buffs [][]byte, e conn.Endpoint) error {
	if !b.isOpen.Load() {
		return net.ErrClosed
	}
	return endpoint.Send(e, b.epMap, buffs)
}

// GetUdp4Conn returns the udp4 connection.
func (b *Bind) GetUdp4Conn() rebind.PacketConn { return b.udp4 }

// GetUdp4Conn returns the udp6 connection.
func (b *Bind) GetUdp6Conn() rebind.PacketConn { return b.udp6 }

// GetRelayConn returns the relay connection.
func (b *Bind) GetRelayConn() rebind.PacketConn { return b.relay }
