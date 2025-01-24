package tundev

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"runtime"

	"github.com/borderzero/border0-cli/internal/device/utils/asyncio"
	"github.com/borderzero/border0-cli/internal/device/utils/pckparse"
	"github.com/borderzero/border0-cli/internal/device/utils/stats"
	"github.com/borderzero/border0-go/lib/types/set"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"github.com/borderzero/wireguard-go/tun"
	"go.uber.org/zap"
)

// Device is a custom implementation of tun.Device which
// adds additional processing for read and written packets
// to an existing tun.Device.
type Device struct {
	logger               *zap.Logger
	localDeviceIPv4      string
	localDeviceIPv6      string
	devicesNetworkCIDRv4 netip.Prefix
	devicesNetworkCIDRv6 netip.Prefix
	socketsNetworkCIDRv4 netip.Prefix
	socketsNetworkCIDRv6 netip.Prefix
	dnsIPv4              string
	forwardPacketsToSelf bool
	realworld            tun.Device
	netstack             tun.Device
	fromRealWorld        <-chan *asyncio.Packet
	fromNetstack         <-chan *asyncio.Packet
	fromLocalGeneration  chan []byte
	socketAddrs          *syncmap.Map[string, set.Set[uint16]]

	readContext      context.Context
	stopPendingReads context.CancelFunc

	statsTracker stats.Tracker
}

// New returns a new custom device based on the given device.
func New(
	logger *zap.Logger,
	localDeviceIPv4 string,
	localDeviceIPv6 string,
	devicesNetworkCIDRv4 netip.Prefix,
	devicesNetworkCIDRv6 netip.Prefix,
	socketsNetworkCIDRv4 netip.Prefix,
	socketsNetworkCIDRv6 netip.Prefix,
	dnsIPv4 string,
	realworld tun.Device,
	netstack tun.Device,
	fromRealWorld <-chan *asyncio.Packet,
	fromNetstack <-chan *asyncio.Packet,
	socketAddrs *syncmap.Map[string, set.Set[uint16]],
	statsTracker stats.Tracker,
) tun.Device {
	readContext, stopPendingReads := context.WithCancel(context.Background())
	return &Device{
		logger:               logger,
		localDeviceIPv4:      localDeviceIPv4,
		localDeviceIPv6:      localDeviceIPv6,
		devicesNetworkCIDRv4: devicesNetworkCIDRv4,
		devicesNetworkCIDRv6: devicesNetworkCIDRv6,
		socketsNetworkCIDRv4: socketsNetworkCIDRv4,
		socketsNetworkCIDRv6: socketsNetworkCIDRv6,
		dnsIPv4:              dnsIPv4,
		forwardPacketsToSelf: mustWritePacketsForSelf(),
		realworld:            realworld,
		netstack:             netstack,
		fromRealWorld:        fromRealWorld,
		fromNetstack:         fromNetstack,
		fromLocalGeneration:  make(chan []byte, 100),
		socketAddrs:          socketAddrs,
		readContext:          readContext,
		stopPendingReads:     stopPendingReads,
		statsTracker:         statsTracker,
	}
}

// File returns the file descriptor of the device.
func (d *Device) File() *os.File { return d.realworld.File() }

// Read one or more packets from the Device (without any additional headers).
// On a successful read it returns the number of packets read, and sets
// packet lengths within the sizes slice. len(sizes) must be >= len(bufs).
// A nonzero offset can be used to instruct the Device on where to begin
// reading into each element of the bufs slice.
//
// This is where traffic flows from sources (e.g. kernel utun device or
// netstack) to our custom software.
//
// NOTE(@adriano): The offset here is the byte index within the buffer where the
// caller of Read() wants us to start reading packets onto. This exists because
// wireguard preprends certain metadata to packets read for internal processing.
// As far as I can tell, this value will always be MessageTransportOffsetContent
// (constant in the golang.zx2c4.com/wireguard/device package). Specifically,
// the wireguard library uses the bytes before the offset as a packet counter.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	stats := initStats(d.statsTracker)
	defer stats.commit()

	// block until we have at least one packet
	n := d.readAtLeastOne(bufs, sizes, offset)
	if n == 0 {
		return 0, net.ErrClosed
	}
	stats.packetsRead += uint64(n)

	// process all the packtes read, one-by-one
	for i := 0; i < n; i++ {
		_, packet := bufs[i][:offset], bufs[i][offset:offset+sizes[i]]
		stats.bytesRead += uint64(len(packet))

		srcIP, dstIP, err := pckparse.ExtractIPs(packet)
		if err != nil {
			d.logger.Error(
				"(tundev.Device).Read() failed to extract src/dst IP addresses from IP packet (bad packet)",
				zap.Int("batch_index", i),
				zap.String("packet", hex.Dump(packet)),
				zap.Error(err),
			)
			doNotReadCurrentPacket(bufs, sizes, &i, &n)
			continue
		}

		if dstIP.String() == d.dnsIPv4 {
			if _, err := d.netstack.Write([][]byte{packet}, 0); err != nil {
				d.logger.Error(
					"(tundev.Device).Read() failed to write packet for dns override address",
					zap.Int("batch_index", i),
					zap.Error(err),
				)
			}
			doNotReadCurrentPacket(bufs, sizes, &i, &n)
			continue
		}

		// TODO(@adriano): consider doing software NAT?

		protocol, err := pckparse.ExtractProtocol(packet)
		if err != nil {
			d.logger.Error(
				"(tundev.Device).Read() failed to extract protocol from IP packet (bad packet)",
				zap.Int("batch_index", i),
				zap.String("packet", hex.Dump(packet)),
				zap.Error(err),
			)
			doNotReadCurrentPacket(bufs, sizes, &i, &n)
			continue
		}

		if protocol == pckparse.ProtocolTCP {
			// packet is destined for a local socket
			if portsInUseForSockets, ok := d.socketAddrs.Load(dstIP.String()); ok && portsInUseForSockets.Size() > 0 {
				// packet will be processed here, no need to read it in.
				doNotReadCurrentPacket(bufs, sizes, &i, &n)

				// drop packets with a source IP not in the devices range.
				if !d.devicesNetworkCIDRv4.Contains(srcIP) && !d.devicesNetworkCIDRv6.Contains(srcIP) {
					continue
				}

				// write the packet to the netstack device where it is
				// internally processed and delivered to the correct listener.
				if _, err := d.netstack.Write([][]byte{packet}, 0); err != nil {
					d.logger.Error(
						"(tundev.Device).Read() failed to write packet for local socket",
						zap.Int("batch_index", i+1 /* i was decremented above */),
						zap.Error(err),
					)
				}
				continue
			}
		}

		if dstIP.String() == d.localDeviceIPv4 || dstIP.String() == d.localDeviceIPv6 {
			if d.forwardPacketsToSelf {
				if _, err := d.realworld.Write(bufs[i:i+1], offset); err != nil {
					d.logger.Error(
						"(tundev.Device).Read() failed to write packet meant for localhost back to TUN device",
						zap.Int("batch_index", i),
						zap.Error(err),
					)
				} else {
					stats.bytesWritten += uint64(len(bufs[i : i+1]))
				}
				doNotReadCurrentPacket(bufs, sizes, &i, &n)
				continue
			}
		}
	}
	return n, nil
}

// NOTE(@adriano): We've discovered that blocking when reading these channels
// (instead of spinning until there is data available) results in a pretty
// worth-while performance improvement.
// See https://github.com/borderzero/border0-cli/pull/470.
func (d *Device) readAtLeastOne(bufs [][]byte, sizes []int, offset int) int {
	select {
	case <-d.readContext.Done():
		return 0
	case pck := <-d.fromLocalGeneration:
		sizes[0] = copy(bufs[0][offset:], pck)
	case pck := <-d.fromNetstack:
		sizes[0] = pck.ReadAndFreeBuffer(bufs[0][offset:])
	case pck := <-d.fromRealWorld:
		sizes[0] = pck.ReadAndFreeBuffer(bufs[0][offset:])
	}
	return 1
}

// Write one or more packets to the device (without any additional headers).
// On a successful write it returns the number of packets written. A nonzero
// offset can be used to instruct the Device on where to begin writing from
// each packet contained within the bufs slice.
//
// This is where traffic flows from our custom software to sinks (e.g. kernel
// utun device or netstack).
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	stats := initStats(d.statsTracker)
	defer stats.commit()

	bytesWritten := uint64(0)
	generated := 0

	// process packets one by one
	n := len(bufs)
	for i := 0; i < n; i++ {
		_, packet := bufs[i][:offset], bufs[i][offset:]

		protocol, err := pckparse.ExtractProtocol(packet)
		if err != nil {
			d.logger.Error(
				"(tundev.Device).Write() failed to extract protocol from IP packet (bad packet)",
				zap.Int("batch_index", i),
				zap.String("packet", hex.Dump(packet)),
				zap.Error(err),
			)
			doNotWriteCurrentPacket(bufs, &i, &n)
			continue
		}

		srcIP, dstIP, err := pckparse.ExtractIPs(packet)
		if err != nil {
			d.logger.Error(
				"(tundev.Device).Write() failed to extract src/dst IP addresses from IP packet (bad packet)",
				zap.Int("batch_index", i),
				zap.String("packet", hex.Dump(packet)),
				zap.Error(err),
			)
			doNotWriteCurrentPacket(bufs, &i, &n)
			continue
		}

		// If this peer receives (over WireGuard) an ICMP Echo Request destined
		// for sockets, that means that the socket is being served by *this* peer
		// (and thus this peer's allowed IPs include the socket's IP).
		//
		// When this happens, we manually generate an ICMP Echo Reply.
		isICMPForSocket := (protocol == pckparse.ProtocolICMP && d.socketsNetworkCIDRv4.Contains(dstIP))
		isICMPv6ForSocket := (protocol == pckparse.ProtocolICMPv6 && d.socketsNetworkCIDRv6.Contains(dstIP))
		if isICMPForSocket || isICMPv6ForSocket {
			if pckparse.IsICMPEchoRequest(packet) {
				if err := pckparse.CraftICMPEchoReplyInPlace(packet); err != nil {
					// we fail silently here and let the kernel deal with the
					// original, likely malformed, ICMP Echo Request packet.
				} else {
					// create a copy since we don't know how long it will take to read this
					// packet (e.g. the caller of Write() might re-use the buffer before we
					// consume it).
					cloned := make([]byte, len(packet))
					copy(cloned, packet)

					select {
					case d.fromLocalGeneration <- cloned:
						generated++
						doNotWriteCurrentPacket(bufs, &i, &n)
					default:
						// NOTE: this default clause executes only if the fromLocalGeneration
						// channel was full... i.e. we don't want to block on writing to the
						// channel, so we just move on and try to handle the ICMP Echo Request
						// by relying on the kernel.
						//
						// Since we didn't remove the packet from the buffer in this case, the
						// now-modified packet (now an ICMP Echo Reply) will be written to the
						// kernel. The kernel will then forward the packet to the utun interface
						// (because the destination IP is in the devices range) and will end up
						// in the Read() above. From there is is read into our custom software.
						// Our software delivers the packet to the correct peer based on the
						// destination IP address on the ICMP Echo Reply.
					}
				}
				continue
			}
		}

		if protocol == pckparse.ProtocolTCP {
			// packet is destined for a local socket
			if portsInUseForSockets, ok := d.socketAddrs.Load(dstIP.String()); ok && portsInUseForSockets.Size() > 0 {
				// packet will be processed here, no need to write it out.
				doNotWriteCurrentPacket(bufs, &i, &n)

				// drop packets with a source IP not in the devices range.
				if !d.devicesNetworkCIDRv4.Contains(srcIP) && !d.devicesNetworkCIDRv6.Contains(srcIP) {
					continue
				}

				// write the packet to the netstack device where it is
				// internally processed and delivered to the correct listener.
				if _, err := d.netstack.Write([][]byte{packet}, 0); err != nil {
					d.logger.Error(
						"(tundev.Device).Write() failed to write packet for local socket",
						zap.Int("batch_index", i+1 /* i was decremented above */),
						zap.Error(err),
					)
				}
				continue
			}

			// TODO(@adriano): consider doing software NAT?
		}

		bytesWritten += uint64(len(packet))
	}

	// we return early if there are no packets to write to the kernel
	if n == 0 {
		return generated, nil
	}

	// write unprocessed packets back to the device
	written, err := d.realworld.Write(bufs, offset)
	if err == nil {
		stats.bytesWritten += bytesWritten
		stats.packetsWritten += uint64(written)
	}
	return generated + written, err
}

// doNotReadCurrentPacket drops the packet (and size) at position i in the bufs slice, adjusts i and n accordingly.
// This is useful when a packet read from the inner device is processed internally and we do not need to propagate it.
func doNotReadCurrentPacket(bufs [][]byte, sizes []int, iptr, nptr *int) {
	i := *iptr
	copy(bufs[i:], bufs[i+1:])   // shift packets one position to the left to omit it
	copy(sizes[i:], sizes[i+1:]) // shift packet sizes one position to the left to omit it
	*iptr--                      // in order to process the next packet on the next iteration of the loop
	*nptr--                      // we have one packet less (we removed it)
}

// doNotWriteCurrentPacket drops the packet at position i in the bufs slice, adjusts i and n accordingly.
// This is useful when a packet being written to the inner device is processed internally and we do not need to propagate it.
func doNotWriteCurrentPacket(bufs [][]byte, iptr, nptr *int) {
	i := *iptr
	if i < *nptr-1 {
		copy(bufs[i:], bufs[i+1:]) // shift packets one position to the left to omit it
	}
	*iptr-- // in order to process the next packet on the next iteration of the loop
	*nptr-- // we have one packet less (we removed it)
}

// MTU returns the MTU of the Device.
func (d *Device) MTU() (int, error) { return d.realworld.MTU() }

// Name returns the current name of the Device.
func (d *Device) Name() (string, error) { return d.realworld.Name() }

// Events returns a channel of type Event, which is fed Device events.
func (d *Device) Events() <-chan tun.Event { return d.realworld.Events() }

// Close stops the Device and closes the Event channel.
func (d *Device) Close() error {
	d.stopPendingReads()
	return nil
}

// BatchSize returns the preferred/max number of packets that can be read or
// written in a single read/write call. BatchSize must not change over the
// lifetime of a Device.
func (d *Device) BatchSize() int { return d.realworld.BatchSize() }

// On BSD based hosts (e.g. darwin included) we must write packets meant for the
// local Border0-network IP to the Border0-network TUN device manually... Otherwise
// they will be forced to go over a peer (if there is one available, or else the
// traffic is dropped). In the happy case the remote peer sends it back to this
// machine, where it finally accepted by the kernel.
//
// That is obviously undesirable because it means packets for the local Border0-network
// IP must do a round-trip somewhere before they are delivered to the destination,
// incurring the latency for the round-trip in the best case, or being dropped in the
// worst case (when there are no peers to forward the traffic back).
func mustWritePacketsForSelf() bool {
	return set.New(
		"darwin",
		"dragonfly",
		"freebsd",
		"netbsd",
		"openbsd",
	).Has(runtime.GOOS)
}
