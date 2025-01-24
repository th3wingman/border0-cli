package asyncio

import (
	"errors"
	"fmt"
	"os"

	"github.com/borderzero/border0-cli/internal/util/typesafepool"
	"github.com/borderzero/wireguard-go/device"
	"github.com/borderzero/wireguard-go/tun"
	"go.uber.org/zap"
)

const (
	defaultChannelBufferSize = 100
)

// Reader represents a non-blocking reader which reads packets
// from wireguard tun.Device implementations onto pre-allocated
// buffers.
//
// The whole point of this package is making the Read() operation of
// a tun.Device non-blocking i.e. enable asynchronous Read()ing from
// multiple different tun.Device implementations.
type Reader interface {
	C() <-chan *Packet
}

// packet is used to communicate the contents
// of a network packet along with its size.
type Packet struct {
	pool         typesafepool.Pool[[]byte]
	readerOffset int

	buf  []byte
	size int
}

// ReadAndFreeBuffer reads a packet's data onto a given destination
// buffer and returns the number of bytes read. After copying the
// data, it frees the buffer used to hold the packet's data.
func (p *Packet) ReadAndFreeBuffer(dst []byte) int {
	defer p.pool.Put(p.buf)
	return copy(dst, p.buf[p.readerOffset:p.readerOffset+p.size])
}

// reader is the default implementation of the Reader interface.
type reader struct {
	logger          *zap.Logger
	source          tun.Device
	pbufpool        typesafepool.Pool[[]byte]
	available       chan *Packet
	readerBatchSize int
	readerOffset    int
}

// NewReader returns a newly initialized Reader.
func NewReader(logger *zap.Logger, source tun.Device) (Reader, error) {
	return newReader(logger, source, device.MessageTransportOffsetReceiver)
}

// NewNetstackReader returns a newly initialized Reader
// for a netstack tun.Device implementation.
func NewNetstackReader(logger *zap.Logger, source tun.Device) (Reader, error) {
	return newReader(logger, source, 0 /* no offset for netstack devices */)
}

func newReader(
	logger *zap.Logger,
	source tun.Device,
	readerOffset int,
) (Reader, error) {
	sourceDeviceMTU, err := source.MTU()
	if err != nil {
		return nil, fmt.Errorf("failed to determine MTU from source device: %v", err)
	}
	r := &reader{
		logger:          logger,
		source:          source,
		pbufpool:        typesafepool.New(func() []byte { return make([]byte, readerOffset+sourceDeviceMTU) }),
		available:       make(chan *Packet, defaultChannelBufferSize),
		readerBatchSize: source.BatchSize(),
		readerOffset:    readerOffset,
	}
	go r.receive()
	return r, nil
}

func (r *reader) C() <-chan *Packet { return r.available }

// receive continuously reads packets from the source device
// and writes them to the reader's available channel.
func (r *reader) receive() {
	bufs := make([][]byte, r.readerBatchSize)
	sizes := make([]int, r.readerBatchSize)

	for {
		for i := 0; i < r.readerBatchSize; i++ {
			bufs[i] = r.pbufpool.Get() // get a new packet buffer from pool
		}

		n, err := r.source.Read(bufs, sizes, r.readerOffset)

		// enqueue read packets
		for i := 0; i < n; i++ {
			r.available <- &Packet{
				pool:         r.pbufpool,
				readerOffset: r.readerOffset,
				buf:          bufs[i],
				size:         sizes[i],
			}
		}

		// discard unused buffers
		for i := n; i < r.readerBatchSize; i++ {
			r.pbufpool.Put(bufs[i])
		}

		// handle any encountered errors
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				r.logger.Warn("asyncio.Reader's underlying device was closed, reader routine exiting")
				return
			}
			if errors.Is(err, tun.ErrTooManySegments) {
				r.logger.Warn("not enough buffers, read packets may have been dropped", zap.Error(err))
				continue
			}
			r.logger.Error("an error occurred while reading packets from device", zap.Error(err))
		}
	}
}
