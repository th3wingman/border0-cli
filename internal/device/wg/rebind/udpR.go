package rebind

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/turtle"
	"go.uber.org/zap"
)

// MethodUdpR is the method for UDP over relay.
const MethodUdpR = "udpR"

// udp4PacketConn is a udp-over-relay PacketConn.
type udpRPacketConn struct {
	logger  *zap.Logger
	inner   *atomic.Pointer[net.PacketConn]
	open    *atomic.Bool
	binding *atomic.Bool

	relayURL string
	naclKey  *nacl.PrivateKey
}

// ListenPacketUdpR wraps a connection to a TURTLE relay in a rebinding PacketConn.
// Rebinding for this PacketConn simply means re-connecting to the TURTLE server.
func ListenPacketUdpR(logger *zap.Logger, relayURL string, naclKey *nacl.PrivateKey) (PacketConn, error) {
	pc := &udpRPacketConn{
		logger:   logger,
		inner:    &atomic.Pointer[net.PacketConn]{},
		relayURL: relayURL,
		naclKey:  naclKey,
		open:     &atomic.Bool{},
		binding:  &atomic.Bool{},
	}
	if err := pc.Rebind(); err != nil {
		return nil, err
	}
	return pc, nil
}

// Rebind binds to a local network address.
func (c *udpRPacketConn) Rebind() error {
	swapped := c.binding.CompareAndSwap(false, true)
	if !swapped {
		time.Sleep(alreadyRebindingWait)
		return nil
	}
	defer c.binding.Store(false)

	c.open.Store(false)

	current := c.inner.Load()
	if current != nil {
		(*current).Close()
	}

	// NOTE(@adrianosela): only errors when URL is not valid.
	turtleClientPconn, err := turtle.Connect(c.relayURL, c.naclKey, turtle.WithLogger(c.logger))
	if err != nil {
		return fmt.Errorf("failed to set-up relay connection: %v", err)
	}

	c.inner.Store(&turtleClientPconn)
	c.open.Store(true)
	return nil
}

// Method returns the method of this connection (udp over relay).
func (c *udpRPacketConn) Method() string { return MethodUdpR }

// IsOpen returns true if the PacketConn is announcing on the local network.
func (c *udpRPacketConn) IsOpen() bool { return c.open.Load() }

// IsBinding returns true if the PacketConn is currently trying to bind.
func (c *udpRPacketConn) IsBinding() bool { return c.binding.Load() }

// ShouldRebindOnError returns true when a Read() error should prompt a rebinding.
func (c *udpRPacketConn) ShouldRebindOnError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed)
}

// Close closes the connection.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (c *udpRPacketConn) Close() error {
	c.open.Store(false)
	return (*c.inner.Load()).Close()
}

// LocalAddr returns the local network address, if known.
func (c *udpRPacketConn) LocalAddr() net.Addr {
	return (*c.inner.Load()).LocalAddr()
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return an Error after a
// fixed time limit; see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c *udpRPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return (*c.inner.Load()).WriteTo(p, addr)
}

// ReadFrom reads a packet from the connection,
// copying the payload into p. It returns the number of
// bytes copied into p and the return address that
// was on the packet.
// It returns the number of bytes read (0 <= n <= len(p))
// and any error encountered. Callers should always process
// the n > 0 bytes returned before considering the error err.
// ReadFrom can be made to time out and return an error after a
// fixed time limit; see SetDeadline and SetReadDeadline.
func (c *udpRPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return (*c.inner.Load()).ReadFrom(b)
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail instead of blocking. The deadline applies to all future
// and pending I/O, not just the immediately following call to
// Read or Write. After a deadline has been exceeded, the
// connection can be refreshed by setting a deadline in the future.
//
// If the deadline is exceeded a call to Read or Write or to other
// I/O methods will return an error that wraps os.ErrDeadlineExceeded.
// This can be tested using errors.Is(err, os.ErrDeadlineExceeded).
// The error's Timeout method will return true, but note that there
// are other possible errors for which the Timeout method will
// return true even if the deadline has not been exceeded.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful ReadFrom or WriteTo calls.
//
// A zero value for t means I/O operations will not time out.
func (c *udpRPacketConn) SetDeadline(t time.Time) error {
	return (*c.inner.Load()).SetDeadline(t)
}

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (c *udpRPacketConn) SetReadDeadline(t time.Time) error {
	return (*c.inner.Load()).SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (c *udpRPacketConn) SetWriteDeadline(t time.Time) error {
	return (*c.inner.Load()).SetWriteDeadline(t)

}

// Port returns the uint16 representation of the
// port in the address returned by LocalAddr().
func (c *udpRPacketConn) Port() uint16 {
	return 0
}
