package turtle

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/turtle/internal/lib/deadline"
	"github.com/borderzero/turtle/internal/lib/gpool"
	"github.com/borderzero/turtle/internal/lib/keyconn"
	"github.com/borderzero/turtle/internal/lib/wsdialopts"
	"github.com/borderzero/turtle/internal/proto"
	"github.com/cenkalti/backoff/v4"
	"github.com/coder/websocket"
	"github.com/pion/dtls/v3"
	"go.uber.org/zap"
)

const (
	defaultRxPacketsChannelSize = 100
	defaultDialTimeout          = time.Second * 5
)

type txResult struct {
	n   int
	err error
}

// Turtle is an implementation of net.PacketConn
// that leverages a remote relay for sending packets.
type Turtle struct {
	logger *zap.Logger

	url *url.URL
	key *nacl.PrivateKey

	connptr *atomic.Pointer[keyconn.KeyConn]
	addr    net.Addr

	// deadlines
	txDeadline deadline.Deadline
	rxDeadline deadline.Deadline

	// inbound data packet management
	rxPackets          chan *proto.InboundPacket
	rxPacketBufferPool *gpool.Pool[[]byte]

	// client lifecycle management
	ctx  context.Context
	ctxc context.CancelFunc

	// reconnection management
	getConn func() (net.Conn, error)
	backoff *backoff.ExponentialBackOff
}

// Connect connects to a TURTLE server.
func Connect(address string, key *nacl.PrivateKey, opts ...Option) (net.PacketConn, error) {
	t, err := newTurtleClient(address, key, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize ")
	}
	if err := t.connectOnce(); err != nil {
		t.logger.Error("initial turtle connection attempt did not succeed, will retry...", zap.Error(err))
	}
	go proto.DeliverPackets(t.ctx, t.logger, t.connptr, t.rxPackets, t.rxPacketBufferPool, t.reconnect)
	return t, nil
}

// Close closes the TURTLE client.
func (t *Turtle) Close() error {
	defer t.logger.Sync() // flush buffered data if any
	t.ctxc()
	conn := t.connptr.Load()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

// LocalAddr returns the local TURTLE address.
func (t *Turtle) LocalAddr() net.Addr { return t.addr }

// ReadFrom reads a single packet onto the given buffer. Note that the
// given buffers must be at least RxPacketBufferSize in size. There is
// no validation for this and data may be lost if you do not respect
// this requirement. We skip validation for performance purposes.
func (t *Turtle) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	// connection closed
	case <-t.ctx.Done():
		return 0, nil, net.ErrClosed
	// deadline exceeded
	case <-t.rxDeadline.Done():
		return 0, nil, os.ErrDeadlineExceeded
	// inbound packet available
	case pck, ok := <-t.rxPackets:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if len(p) < pck.N {
			// the given buffer is too small to read in the packet data
			return 0, nil, io.ErrShortBuffer
		}
		defer t.rxPacketBufferPool.Put(pck.Buffer) // return buffer to pool
		return copy(p, pck.Buffer[:pck.N]), pck.From, nil
	}
}

// WriteTo writes a single packet for the given address.
func (t *Turtle) WriteTo(p []byte, addr net.Addr) (int, error) {
	// drop empty writes early
	if len(p) == 0 {
		return 0, nil
	}

	// Note:
	//
	// Spinning-up a go-routine per write could be quite expensive...
	// We do this in order to ensure that we respect the write-deadline
	// e.g. not rely on the underlying t.conn net.Conn implementation
	// respecting the write-deadline.
	//
	// If we identify this to be a bottleneck, it is OK to remove
	// this and instead simply call proto.SendPacket() in a default
	// clause in the select statement below... after all, we don't really
	// care about deadlines; they've been added just for compliance with
	// the net.PacketConn interface.
	txResultChan := make(chan txResult)
	go func() {
		defer close(txResultChan)

		conn := t.connptr.Load()
		if conn == nil {
			txResultChan <- txResult{0, net.ErrClosed}
			return
		}

		err := proto.SendPacket(conn, p, addr)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "write: broken pipe") {
				txResultChan <- txResult{0, net.ErrClosed}
				return
			}
		}

		txResultChan <- txResult{len(p), err}
	}()

	select {
	// connection closed
	case <-t.ctx.Done():
		return 0, net.ErrClosed
	// deadline exceeded
	case <-t.txDeadline.Done():
		return 0, os.ErrDeadlineExceeded
	// write completed
	case result := <-txResultChan:
		return result.n, result.err
	}
}

// SetDeadline sets both read and write deadlines.
func (t *Turtle) SetDeadline(d time.Time) error {
	if err := t.SetReadDeadline(d); err != nil {
		return fmt.Errorf("failed to set read deadline: %v", err)
	}
	if err := t.SetWriteDeadline(d); err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}
	return nil
}

// SetReadDeadline sets the deadline to for read operations.
func (t *Turtle) SetReadDeadline(d time.Time) error {
	select {
	case <-t.ctx.Done():
		return net.ErrClosed
	default:
		t.rxDeadline.Set(d)
		return t.connptr.Load().SetReadDeadline(d)
	}
}

// SetWriteDeadline sets the deadline to for write operations.
func (t *Turtle) SetWriteDeadline(d time.Time) error {
	select {
	case <-t.ctx.Done():
		return net.ErrClosed
	default:
		t.txDeadline.Set(d)
		return t.connptr.Load().SetWriteDeadline(d)
	}
}

// internal constructor used by both the tcp and ws variants.
func newTurtleClient(
	address string,
	key *nacl.PrivateKey,
	opts ...Option,
) (*Turtle, error) {
	parsedURL, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server URL: %v", err)
	}

	config := &Config{
		context:   context.Background(),
		logger:    zap.L(),
		tlsConfig: &tls.Config{},
	}
	for _, opt := range opts {
		opt(config)
	}

	var connptr atomic.Pointer[keyconn.KeyConn]
	ctx, ctxc := context.WithCancel(config.context)

	var getConn func() (net.Conn, error)

	switch parsedURL.Scheme {
	case "ws", "wss":
		dialOpts := wsdialopts.GetDialOpts(defaultDialTimeout)
		getConn = func() (net.Conn, error) {
			websocketConn, _, err := websocket.Dial(ctx, parsedURL.String(), dialOpts)
			if err != nil {
				return nil, err
			}
			conn := websocket.NetConn(ctx, websocketConn, websocket.MessageBinary)
			return conn, nil
		}
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6", "ip", "ip4", "ip6":
		dialer := &net.Dialer{
			Timeout: defaultDialTimeout,
			Cancel:  ctx.Done(),
		}
		getConn = func() (net.Conn, error) {
			return dialer.Dial(parsedURL.Scheme, parsedURL.Host)
		}
	case "tls":
		dialer := &net.Dialer{
			Timeout: defaultDialTimeout,
			Cancel:  ctx.Done(),
		}
		getConn = func() (net.Conn, error) {
			return tls.DialWithDialer(
				dialer,
				parsedURL.Scheme,
				parsedURL.Host,
				config.tlsConfig,
			)
		}
	case "dtls":
		// try resolving host outside of getConn for validation
		if _, err := net.ResolveUDPAddr("udp", parsedURL.Host); err != nil {
			return nil, fmt.Errorf("failed to resolve udp address: %v", err)
		}

		getConn = func() (net.Conn, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", parsedURL.Host)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve udp address: %v", err)
			}
			return dtls.Dial(
				"udp",
				udpAddr,
				&dtls.Config{
					RootCAs:      config.tlsConfig.RootCAs,
					Certificates: config.tlsConfig.Certificates,
				},
			)
		}
	default:
		return nil, fmt.Errorf("invalid scheme \"%s\" in server url", parsedURL.Scheme)
	}

	return &Turtle{
		logger: config.logger,

		url: parsedURL,
		key: key,

		connptr: &connptr,
		addr:    proto.AddrFromKey(key.Public()),

		txDeadline: deadline.New(),
		rxDeadline: deadline.New(),

		rxPackets:          make(chan *proto.InboundPacket, defaultRxPacketsChannelSize),
		rxPacketBufferPool: gpool.New[[]byte](func() []byte { return make([]byte, proto.MaxPacketSize) }),

		ctx:  ctx,
		ctxc: ctxc,

		getConn: getConn,
		backoff: backoff.NewExponentialBackOff(
			backoff.WithInitialInterval(2*time.Second), // wait for 2 seconds after first attempt
			backoff.WithMaxInterval(30*time.Second),    // wait for no more than 30 seconds between attempts
			backoff.WithMultiplier(2.0),                // double the interval after each failed attempt
			backoff.WithRandomizationFactor(0.5),       // jitter of 50% of the current interval
		),
	}, nil
}

// connectOnce will try connecting once
func (t *Turtle) connectOnce() error {
	conn, err := t.getConn()
	if err != nil {
		return err
	}
	keyConn, err := proto.Authenticate(conn, t.key)
	if err != nil {
		return err
	}
	old := t.connptr.Swap(keyConn)
	if old != nil {
		old.Close()
	}
	return nil
}

// reconnect
func (t *Turtle) reconnect() {
	attempts := 0

	operation := func() error {
		attempts++

		select {
		case <-t.ctx.Done():
			return backoff.Permanent(t.ctx.Err())
		default:
			t.logger.Info("reconnecting to relay...")
			return t.connectOnce()
		}
	}

	notify := func(err error, duration time.Duration) {
		t.logger.Debug(
			"failed to reconnect to relay",
			zap.Int("attempts", attempts),
			zap.Duration("next_retry_in", duration),
			zap.Duration("total_elapsed_time", t.backoff.GetElapsedTime()),
			zap.Error(err),
		)
	}

	t.backoff.Reset()
	err := backoff.RetryNotify(operation, t.backoff, notify)
	if err != nil {
		t.logger.Error("permanent failure during reconnection attempt, will not retry", zap.Error(err))
		return
	}
	t.logger.Info("reconnected to relay!")
}
