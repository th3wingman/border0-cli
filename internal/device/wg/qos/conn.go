package qos

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/borderzero/border0-cli/internal/device/network"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-cli/internal/device/wg/rebind"
	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/border0-go/lib/types/set"
	"go.uber.org/atomic"
	"go.uber.org/zap"
)

var (
	methodUdp4Roaming = fmt.Sprintf("%s (roaming)", rebind.MethodUdp4)
	methodUdp6Roaming = fmt.Sprintf("%s (roaming)", rebind.MethodUdp6)

	udp4AddrUnavailable = netip.MustParseAddr("0.0.0.0")
	udp6AddrUnavailable = netip.MustParseAddr("::1")
)

type Conn struct {
	logger *zap.Logger

	settings *Settings

	mu   sync.RWMutex // lock for options
	opts map[string]*qconn
	best *atomic.Pointer[qconn]

	ctx  context.Context
	ctxc context.CancelFunc
}

type Settings struct {
	PrivateKey    *nacl.PrivateKey
	PeerPublicKey *nacl.PublicKey

	Udp4AddrPort netip.AddrPort
	Udp4Conn     rebind.PacketConn

	Udp6AddrPort netip.AddrPort
	Udp6Conn     rebind.PacketConn

	RelayAddr net.Addr
	RelayConn rebind.PacketConn

	DisallowedSourcesV4 []netip.Prefix
	DisallowedSourcesV6 []netip.Prefix

	ProbesPeriod       time.Duration
	ComputationPeriod  time.Duration
	ComputationSamples int
}

func NewConn(logger *zap.Logger, settings *Settings) *Conn {
	allowedMethods := rebind.ValidAllowedMethods
	if allowedMethodsOverride := os.Getenv("BORDER0_ALLOWED_METHODS"); allowedMethodsOverride != "" {
		allowedMethods = set.New[string]()
		for _, method := range strings.Split(allowedMethodsOverride, ",") {
			trimmed := strings.TrimSpace(method)
			if rebind.ValidAllowedMethods.Has(trimmed) {
				allowedMethods.Add(trimmed)
			}
		}
	}

	best := atomic.NewPointer[qconn](nil)
	opts := make(map[string]*qconn)

	if allowedMethods.Has(rebind.MethodUdpR) {
		addr := settings.RelayAddr
		qconn := newConn(logger, settings.RelayConn, addr, rebind.MethodUdpR, settings.ComputationSamples, network.DefaultMTU, settings.PrivateKey, settings.PeerPublicKey)
		qconn.start(settings.ProbesPeriod)
		opts[settings.RelayAddr.String()] = qconn

		// unconditionally set as best
		best.Store(qconn)
	}

	if allowedMethods.Has(rebind.MethodUdp4) && settings.Udp4AddrPort.IsValid() {
		addr := net.UDPAddrFromAddrPort(settings.Udp4AddrPort)
		qconn := newConn(logger, settings.Udp4Conn, addr, rebind.MethodUdp4, settings.ComputationSamples, network.DefaultMTU, settings.PrivateKey, settings.PeerPublicKey)
		qconn.start(settings.ProbesPeriod)
		opts[settings.Udp4AddrPort.String()] = qconn

		// set as best if udpR is not allowed
		if !allowedMethods.Has(rebind.MethodUdpR) {
			best.Store(qconn)
		}
	}

	if allowedMethods.Has(rebind.MethodUdp6) && settings.Udp6AddrPort.IsValid() {
		addr := net.UDPAddrFromAddrPort(settings.Udp6AddrPort)
		qconn := newConn(logger, settings.Udp6Conn, addr, rebind.MethodUdp6, settings.ComputationSamples, network.DefaultMTU, settings.PrivateKey, settings.PeerPublicKey)
		qconn.start(settings.ProbesPeriod)
		opts[settings.Udp6AddrPort.String()] = qconn

		// set as best if udpR and udp4 are not allowed
		if !allowedMethods.Has(rebind.MethodUdpR) && !allowedMethods.Has(rebind.MethodUdp4) {
			best.Store(qconn)
		}
	}

	ctx, ctxc := context.WithCancel(context.Background())
	conn := &Conn{
		logger:   logger,
		settings: settings,
		mu:       sync.RWMutex{},
		opts:     opts,
		best:     best,
		ctx:      ctx,
		ctxc:     ctxc,
	}

	conn.start(settings.ComputationPeriod)
	return conn
}

func (c *Conn) start(period time.Duration) {
	go func() {
		for {
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(period):
				bestBefore := c.best.Load()
				if bestBefore == nil {
					// can only be nil if Close() set it to nil,
					// so we can safely end this goroutine...
					return
				}

				bestQualityBefore := bestBefore.currentQuality()

				best := bestBefore
				bestQuality := bestQualityBefore

				c.mu.RLock()
				for _, opt := range c.opts {
					if opt == bestBefore {
						continue
					}

					thisQuality := opt.currentQuality()
					if thisQuality > bestQuality {
						best = opt
						bestQuality = thisQuality
					}
				}
				c.mu.RUnlock()

				if best != bestBefore {
					c.best.Store(best)
				}
			}
		}
	}()
}

func (c *Conn) ensureCandidateLocked(pconn rebind.PacketConn, addr net.Addr) (chan<- uint32, bool, bool) {
	if qconn, ok := c.opts[addr.String()]; ok {
		return qconn.probesReturned, true, false
	}

	c.logger.Info("adding new candiate to QOS conn", zap.String("addr", addr.String()))

	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		// The only way this can happen is if relay messages are disabled.
		// The program still connects to the relay and tries fo receive messages
		// but we have manually chosen (via env BORDER0_ALLOWED_METHODS) that we
		// do not want to talk to other peers over relay, so we will reject this.
		return nil, false, false
	}

	method := rebind.MethodUdp4
	switch {
	case ap.Addr().Is4(), ap.Addr().Is4In6():
		method = methodUdp4Roaming
	case ap.Addr().Is6():
		method = methodUdp6Roaming
	}

	qconn := newConn(c.logger, pconn, addr, method, c.settings.ComputationSamples, network.DefaultMTU, c.settings.PrivateKey, c.settings.PeerPublicKey)
	qconn.start(c.settings.ProbesPeriod)
	c.opts[addr.String()] = qconn

	return qconn.probesReturned, true, true
}

func (c *Conn) EnsureCandidate(pconn rebind.PacketConn, addr net.Addr) (chan<- uint32, bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ensureCandidateLocked(pconn, addr)
}

// AllowQosTrafficFrom returns true if QOS traffic from a given conn and address should be
// accepted. We disallow receiving QOS messages over the device/resource ranges so as to
// prevent trying unoptimal paths e.g. roaming udp4 over relay, roaming udp4 over udp6, etc.
func (c *Conn) AllowQosTrafficFrom(pconn rebind.PacketConn, addr net.Addr) bool {
	switch pconn.Method() {
	case rebind.MethodUdp4:
		netipAddrport, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			c.logger.Error("failed to parse net.Addr for udp4 packet conn as netip.Addr", zap.String("addr", addr.String()), zap.Error(err))
			return false
		}
		netipAddr := netipAddrport.Addr()
		for _, dropSource := range c.settings.DisallowedSourcesV4 {
			if dropSource.Contains(netipAddr) {
				return false
			}
		}
	case rebind.MethodUdp6:
		netipAddrport, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			c.logger.Error("failed to parse net.Addr for udp6 packet conn as netip.Addr", zap.String("addr", addr.String()), zap.Error(err))
			return false
		}
		netipAddr := netipAddrport.Addr()
		for _, dropSource := range c.settings.DisallowedSourcesV6 {
			if dropSource.Contains(netipAddr) {
				return false
			}
		}
	case rebind.MethodUdpR:
		// no filtering
	}
	return true
}

func (c *Conn) ProbeResponseFrom(msg *Message, pconn rebind.PacketConn, addr net.Addr) bool {
	if !c.AllowQosTrafficFrom(pconn, addr) {
		return false
	}
	ch, ok, added := c.EnsureCandidate(pconn, addr)
	if ok {
		ch <- msg.probeId
	}
	return added
}

func (c *Conn) Send(bufs [][]byte) error {
	qconn := c.best.Load()
	if qconn == nil || qconn.pconn == nil {
		return fmt.Errorf("connection has no way to send packets to destination %s (best conn is nil)", c.settings.RelayAddr.String())
	}

	for i, buf := range bufs {
		if _, err := qconn.pconn.WriteTo(buf, qconn.addr); err != nil {
			return fmt.Errorf(
				"failed to write packet at batch index %d to peer %s over %s://%s connection: %v",
				i,
				c.settings.PeerPublicKey.B64(),
				qconn.pconn.Method(),
				qconn.addr.String(),
				err,
			)
		}
	}

	return nil
}

func (c *Conn) Udp4Addrs() []netip.AddrPort {
	c.mu.RLock()
	defer c.mu.RUnlock()

	addrs := []netip.AddrPort{}
	for _, opt := range c.opts {
		if opt.method == rebind.MethodUdp4 || opt.method == methodUdp4Roaming {
			addrs = append(addrs, netip.MustParseAddrPort(opt.addr.String()))
		}
	}
	return addrs
}

func (c *Conn) Udp6Addrs() []netip.AddrPort {
	addrs := []netip.AddrPort{}
	for _, opt := range c.opts {
		if opt.method == rebind.MethodUdp6 || opt.method == methodUdp6Roaming {
			addrs = append(addrs, netip.MustParseAddrPort(opt.addr.String()))
		}
	}
	return addrs
}

func (c *Conn) RelayAddr() net.Addr { return c.settings.RelayAddr }

func (c *Conn) Close() {
	c.ctxc()
	for _, opt := range c.opts {
		opt.stop()
	}
	c.best.Store(nil)
}

func (c *Conn) CurrentAddress() netip.Addr {
	qconn := c.best.Load()
	if qconn != nil {
		if udpAddr, ok := qconn.addr.(*net.UDPAddr); ok {
			return netip.MustParseAddr(udpAddr.IP.String())
		}
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	udp4Addr := udp4AddrUnavailable
	udp6Addr := udp6AddrUnavailable

	for _, opt := range c.opts {
		if opt.method == rebind.MethodUdpR {
			continue
		}
		if opt.method == rebind.MethodUdp4 || opt.method == methodUdp4Roaming {
			if udpAddr, ok := opt.addr.(*net.UDPAddr); ok {
				udp4Addr = netip.MustParseAddr(udpAddr.IP.String())
				if time.Since(opt.lastProbeRx.Load()) < time.Minute {
					return udp4Addr
				}
			}
		}
		if opt.method == rebind.MethodUdp6 || opt.method == methodUdp6Roaming {
			if udpAddr, ok := opt.addr.(*net.UDPAddr); ok {
				udp6Addr = netip.MustParseAddr(udpAddr.IP.String())
				if time.Since(opt.lastProbeRx.Load()) < time.Minute {
					return udp6Addr
				}
			}
		}
	}

	// TODO: this means traffic is coming over the relay. With the relay
	// we don't have a source IP. So we assume that the client is talking
	// to the relay from the udp4 address published to the border0 api.
	if udp4Addr != udp4AddrUnavailable {
		return udp4Addr
	}
	if udp6Addr != udp6AddrUnavailable {
		return udp6Addr
	}
	return udp4AddrUnavailable
}

// Stats returns connection statistics for each
// of the connections encompassed by this Conn.
func (c *Conn) Stats() []stats.Connection {
	best := c.best.Load()

	c.mu.RLock()
	defer c.mu.RUnlock()

	conns := []stats.Connection{}
	for _, conn := range c.opts {
		rtt := "-"
		loss := "100.00%"
		mtu := fmt.Sprintf("%d", conn.mtu)
		score := "0.0000"
		if conn.traffic.Load() {
			rtt = fmt.Sprintf("%d ms", time.Duration(conn.rttRing.Average()).Milliseconds())
			if rtt == fmt.Sprintf("%d ms", rttWorst.Milliseconds()) {
				rtt = "-"
			}
			loss = fmt.Sprintf("%.2f%%", conn.lossRing.Average()*100)
			score = fmt.Sprintf("%.4f", conn.currentQuality())
		}

		conns = append(conns, stats.Connection{
			Method:    conn.method,
			Address:   conn.addr.String(),
			RTT:       rtt,
			Loss:      loss,
			MTU:       mtu,
			Score:     score,
			Active:    best == conn,
			LastProbe: conn.lastProbeRx.Load(),
		})
	}
	return conns
}
