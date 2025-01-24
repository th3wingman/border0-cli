package rebind

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

// MethodUdp4 is the method for UDP over IPv4.
const MethodUdp4 = "udp4"

// udp4PacketConn is a udp-over-ipv4 PacketConn.
type udp4PacketConn struct {
	logger  *zap.Logger
	inner   *atomic.Pointer[net.PacketConn]
	open    *atomic.Bool
	binding *atomic.Bool
	port    *atomic.Uint32
}

// ListenPacketUdp4 announces on the local IPv4 network address.
// The given port is treated as a preference and not a requirement,
// if the port is taken, a different available port will be used
// and no error will be returned.
func ListenPacketUdp4(logger *zap.Logger, port uint16) (PacketConn, error) {
	pc := &udp4PacketConn{
		logger:  logger,
		inner:   &atomic.Pointer[net.PacketConn]{},
		open:    &atomic.Bool{},
		binding: &atomic.Bool{},
		port:    &atomic.Uint32{},
	}
	pc.port.Store(uint32(port))
	if err := pc.Rebind(); err != nil {
		return nil, err
	}
	return pc, nil
}

// Rebind binds to a local network address.
func (c *udp4PacketConn) Rebind() error {
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

	addr := net.UDPAddr{IP: net.IPv4zero}

	port := int(c.port.Load())
	portsToTry := []int{port}
	if port != 0 {
		portsToTry = append(portsToTry, 0)
	}

	errors := []string{}
	for _, portToTry := range portsToTry {
		addr.Port = portToTry
		address := addr.String()
		inner, err := net.ListenPacket("udp4", address)
		if err != nil {
			c.logger.Warn("failed to start udp4 listener", zap.Int("port", portToTry), zap.Error(err))
			errors = append(errors, fmt.Errorf("failed to set up udp4 listener on %s: %v", address, err).Error())
			continue
		}
		c.logger.Info("successfully started udp4 listener", zap.Int("port", portToTry), zap.Error(err))
		c.inner.Store(&inner)
		c.open.Store(true)
		c.port.Store(uint32(inner.LocalAddr().(*net.UDPAddr).Port))
		return nil
	}

	return fmt.Errorf("failed to set up packet listener: %s", strings.Join(errors, "and also "))
}

// Method returns the method of this connection (udp over IPv4).
func (c *udp4PacketConn) Method() string { return MethodUdp4 }

// IsOpen returns true if the PacketConn is announcing on the local network.
func (c *udp4PacketConn) IsOpen() bool { return c.open.Load() }

// IsBinding returns true if the PacketConn is currently trying to bind.
func (c *udp4PacketConn) IsBinding() bool { return c.binding.Load() }

// ShouldRebindOnError returns true when a Read() error should prompt a rebinding.
func (c *udp4PacketConn) ShouldRebindOnError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.EPIPE)
}

// Close closes the connection.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (c *udp4PacketConn) Close() error {
	c.open.Store(false)
	return (*c.inner.Load()).Close()
}

// LocalAddr returns the local network address, if known.
func (c *udp4PacketConn) LocalAddr() net.Addr {
	return (*c.inner.Load()).LocalAddr()
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return an Error after a
// fixed time limit; see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (c *udp4PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
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
func (c *udp4PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
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
func (c *udp4PacketConn) SetDeadline(t time.Time) error {
	return (*c.inner.Load()).SetDeadline(t)
}

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (c *udp4PacketConn) SetReadDeadline(t time.Time) error {
	return (*c.inner.Load()).SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (c *udp4PacketConn) SetWriteDeadline(t time.Time) error {
	return (*c.inner.Load()).SetWriteDeadline(t)

}

// Port returns the uint16 representation of the
// port in the address returned by LocalAddr().
func (c *udp4PacketConn) Port() uint16 {
	return uint16(c.port.Load())
}
