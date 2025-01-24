package network

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/borderzero/wireguard-go/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	/*
		Recommended MTU for WireGuard is typically 1420. This accounts for the following overheads:
		- IPv4 header: 20 bytes (or 40 bytes for IPv6)
		- UDP header: 8 bytes
		- Type: 4 bytes
		- Key index: 4 bytes
		- Nonce: 8 bytes
		- Authentication tag: 16 bytes

		Total overhead:
		- IPv4: 20 + 8 + 4 + 4 + 8 + 16 = 60 bytes
		- IPv6: 40 + 8 + 4 + 4 + 8 + 16 = 80 bytes
		hence 1500 - 80 =  1420 bytes

		While 1420 is the common MTU, additional overhead may come from protocols like:
		- PPPoE (8 bytes) (DSL connections)
		- GRE (24 bytes)
		- IPv4-in-IPv6 encapsulation (40 bytes, as per RFC 6333 Section 5.3: https://www.rfc-editor.org/rfc/rfc6333#section-5.3)

		To accommodate these scenarios, we reduce the MTU by 40 bytes, resulting in a default MTU of 1380.

		Maybe at some point we can have this be part of the STUN dicovery process or something. For now, this may be a safe choice

	*/
	DefaultMTU = 1380
)

type netTun struct {
	ep             *channel.Endpoint
	stack          *stack.Stack
	events         chan tun.Event
	incomingPacket chan *buffer.View
	mtu            int
}

type Net netTun

func CreateNetTUNWithStack(mtu int) (tun.Device, *Net, *stack.Stack, error) {
	opts := stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol6, icmp.NewProtocol4},
		HandleLocal:        true,
	}
	dev := &netTun{
		ep:             channel.New(1024, uint32(mtu), ""),
		stack:          stack.New(opts),
		events:         make(chan tun.Event, 10),
		incomingPacket: make(chan *buffer.View),
		mtu:            mtu,
	}

	sackEnabledOpt := tcpip.TCPSACKEnabled(true) // TCP SACK is disabled by default
	tcpipErr := dev.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt)
	if tcpipErr != nil {
		return nil, nil, nil, fmt.Errorf("could not enable TCP SACK: %v", tcpipErr)
	}
	dev.ep.AddNotify(dev)
	tcpipErr = dev.stack.CreateNIC(1, dev.ep)
	if tcpipErr != nil {
		return nil, nil, nil, fmt.Errorf("CreateNIC: %v", tcpipErr)
	}

	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	dev.stack.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	dev.events <- tun.EventUp

	return dev, (*Net)(dev), dev.stack, nil
}

func (tun *netTun) WriteNotify() {
	pkt := tun.ep.Read()
	if pkt.IsNil() {
		return
	}

	view := pkt.ToView()
	pkt.DecRef()

	tun.incomingPacket <- view
}

func (tun *netTun) Name() (string, error) {
	return "border0", nil
}

func (tun *netTun) File() *os.File {
	return nil
}

func (tun *netTun) Events() <-chan tun.Event {
	return tun.events
}

func (tun *netTun) Read(buf [][]byte, sizes []int, offset int) (int, error) {
	view, ok := <-tun.incomingPacket
	if !ok {
		return 0, os.ErrClosed
	}

	n, err := view.Read(buf[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (tun *netTun) Write(buf [][]byte, offset int) (int, error) {
	for _, buf := range buf {
		packet := buf[offset:]
		if len(packet) == 0 {
			continue
		}

		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		switch packet[0] >> 4 {
		case 4:
			tun.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			tun.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			return 0, syscall.EAFNOSUPPORT
		}
	}
	return len(buf), nil
}

func (tun *netTun) Close() error {
	tun.stack.RemoveNIC(1)

	if tun.events != nil {
		close(tun.events)
	}

	tun.ep.Close()

	if tun.incomingPacket != nil {
		close(tun.incomingPacket)
	}

	return nil
}

func (tun *netTun) MTU() (int, error) {
	return tun.mtu, nil
}

func (tun *netTun) BatchSize() int {
	return 1
}

func (net *Net) ListenTCPAddrPort(addr netip.AddrPort) (*gonet.TCPListener, error) {
	fa, pn := convertToFullAddr(addr)
	return ListenTCP(net.stack, fa, pn)
}

func convertToFullAddr(endpoint netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if endpoint.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  1,
		Addr: tcpip.AddrFromSlice(endpoint.Addr().AsSlice()),
		Port: endpoint.Port(),
	}, protoNumber
}

// maxListenBacklog is set to be reasonably high for most uses of gonet. Go net
// package uses the value in /proc/sys/net/core/somaxconn file in Linux as the
// default listen backlog. The value below matches the default in common linux
// distros.
//
// See: https://cs.opensource.google/go/go/+/refs/tags/go1.18.1:src/net/sock_linux.go;drc=refs%2Ftags%2Fgo1.18.1;l=66
const maxListenBacklog = 4096

// ListenTCP creates a new TCPListener.
func ListenTCP(s *stack.Stack, addr tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*gonet.TCPListener, error) {
	// Create a TCP endpoint, bind it, then start listening.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	ep.SocketOptions().SetReuseAddress(true)

	if err := ep.Bind(addr); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "bind",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  errors.New(err.String()),
		}
	}

	if err := ep.Listen(maxListenBacklog); err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "listen",
			Net:  "tcp",
			Addr: fullToTCPAddr(addr),
			Err:  errors.New(err.String()),
		}
	}

	return gonet.NewTCPListener(s, &wq, ep), nil
}

func fullToTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(addr.Addr.AsSlice()), Port: int(addr.Port)}
}
