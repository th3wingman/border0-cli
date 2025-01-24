package qos

import (
	"context"
	"math"
	"net"
	"os"
	"strings"
	"time"

	"github.com/borderzero/border0-cli/internal/device/wg/rebind"
	"github.com/borderzero/border0-go/lib/nacl"
	"github.com/borderzero/border0-go/lib/types/ring"
	"github.com/borderzero/border0-go/lib/types/syncmap"
	"go.uber.org/atomic"
	"go.uber.org/zap"
)

const (
	mtuWeight  = float64(0.00) // portion of quality score attributed to wire MTU.
	lossWeight = float64(0.80) // portion of quality score attributed to packet loss.
	rttWeight  = float64(0.20) // portion of quality score attributed to round-trip-time.

	mtuBest   = (1 << 16) - 1 // best normalization value for wire MTU (65535 bytes).
	mtuWorst  = 0             // worst normalization value for wire MTU (0 bytes).
	lossBest  = 0.00          // best normalization value for packet loss (0%).
	lossWorst = 1.00          // worst normalization value for packet loss (100%).
	rttBest   = float64(0.0)  // best normalization value for round-trip-time (infinitely fast).
	rttWorst  = time.Second   // best normalization value for round-trip-time (1 second delay).
)

type qconn struct {
	logger *zap.Logger

	pconn  rebind.PacketConn
	addr   net.Addr
	method string

	traffic  *atomic.Bool
	mtu      uint16
	rttRing  ring.Ring[int64]
	lossRing ring.Ring[int64]

	priv *nacl.PrivateKey
	pub  *nacl.PublicKey

	probesTX    *atomic.Uint64
	probesRX    *atomic.Uint64
	lastProbeRx *atomic.Time

	probesInFlight *syncmap.Map[uint32, *Message]
	probesReturned chan uint32
	ctx            context.Context
	ctxc           context.CancelFunc

	logProbeFailures  bool
	logProbeSuccesses bool
}

func newConn(
	logger *zap.Logger,
	pconn rebind.PacketConn,
	addr net.Addr,
	method string,
	samples int,
	mtu uint16,
	priv *nacl.PrivateKey,
	pub *nacl.PublicKey,
) *qconn {
	ctx, ctxc := context.WithCancel(context.Background())
	return &qconn{
		logger: logger,

		pconn:  pconn,
		addr:   addr,
		method: method,

		traffic:  atomic.NewBool(false),
		mtu:      mtu,
		rttRing:  ring.New[int64](samples),
		lossRing: ring.New[int64](samples),

		probesTX:    atomic.NewUint64(0),
		probesRX:    atomic.NewUint64(0),
		lastProbeRx: atomic.NewTime(time.Time{}),

		probesInFlight: syncmap.New[uint32, *Message](),
		probesReturned: make(chan uint32, 100),
		ctx:            ctx,
		ctxc:           ctxc,

		logProbeFailures:  (strings.ToLower(os.Getenv("BORDER0_VERY_VERBOSE")) == "true"),
		logProbeSuccesses: (strings.ToLower(os.Getenv("BORDER0_VERY_VERBOSE")) == "true"),

		priv: priv,
		pub:  pub,
	}
}

func (q *qconn) start(probePeriod time.Duration) {
	go func() {
		ticker := time.NewTicker(probePeriod)
		go q.sendOne()
		for {
			select {
			case <-q.ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				go q.sendOne()
			}
		}
	}()

	go func() {
		for {
			select {
			case <-q.ctx.Done():
				return
			case probeId := <-q.probesReturned:
				q.traffic.Store(true) // we have a round trip, connection is viable - yay!
				if msg, ok := q.probesInFlight.LoadAndDelete(probeId); ok {
					q.probesRX.Add(1)
					q.lastProbeRx.Store(time.Now())
					q.rttRing.Put(int64(time.Since(msg.sentAt)))
					q.lossRing.Put(int64(0))
				}
			}
		}
	}()
}

func (q *qconn) sendOne() {
	q.probesTX.Add(1)

	// if the underlying conn is unhealthy, simply count the probe
	// packet as lost without writing anything out to the network.
	if q.pconn == nil || !q.pconn.IsOpen() {
		if q.logProbeFailures {
			q.logger.Info("QOS conn's underlying connection is nil or not open", zap.String("method", q.method), zap.String("addr", q.addr.String()))
		}
		q.rttRing.Put(int64(rttWorst))
		q.lossRing.Put(int64(1))
		return
	}

	req := NewRequest(q.priv, q.pub)
	if q.logProbeSuccesses {
		q.logger.Info("sending QOS request", zap.Uint32("probe_id", req.probeId), zap.String("to", q.addr.String()))
	}
	if _, err := q.pconn.WriteTo(req.Encode(), q.addr); err != nil {
		if q.logProbeFailures {
			q.logger.Error("failed to send connection quality probe", zap.String("address", q.addr.String()), zap.Error(err))
		}
		return
	}
	if q.logProbeSuccesses {
		q.logger.Info("sent QOS request", zap.Uint32("probe_id", req.probeId), zap.String("to", q.addr.String()))
	}

	q.probesInFlight.Store(req.probeId, req)

	go func() {
		time.Sleep(rttWorst)
		if _, stillPresent := q.probesInFlight.LoadAndDelete(req.probeId); stillPresent {
			q.rttRing.Put(int64(rttWorst))
			q.lossRing.Put(int64(1))
		}
	}()
}

func (q *qconn) stop() {
	q.ctxc()
	q.traffic.Store(false)
}

func (q *qconn) currentQuality() float64 {
	if !q.traffic.Load() {
		return 0.0
	}

	// NOTE: we take the component_score^4 for each component so that small
	// differences in the component score cause a severe difference in score.
	rttNorm := math.Pow((float64(rttWorst)-q.rttRing.Average())/(float64(rttWorst)-rttBest), 4)
	lossNorm := math.Pow((lossWorst-q.lossRing.Average())/(lossWorst-lossBest), 4)

	mtuNorm := float64((q.mtu - mtuWorst) / (mtuBest - mtuWorst))
	return (mtuNorm * mtuWeight) + (rttNorm * rttWeight) + (lossNorm * lossWeight)
}
