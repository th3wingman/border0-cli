package stats

import (
	"context"
	"time"

	"go.uber.org/atomic"
	"go.uber.org/zap"
)

// Stats represents a public statistics object.
type Stats struct {
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
}

// Delta represents delta in statistics values.
type Delta Stats

// PushFunc represents a function capable of publishing
// count statistics from a map of counter name to counter value.
type PushFunc func(*Delta) error

// Tracker represents an entity capable of
// adding values to counters by counter name.
type Tracker interface {
	IncBytesIn(uint64)
	IncBytesOut(uint64)
	IncPacketsIn(uint64)
	IncPacketsOut(uint64)
	Snapshot() *Stats
}

// Manager represents an entity capable of tracking
// counters and also publishing their values to some
// generic upstream metrics store.
type Manager interface {
	Tracker
	Push(ctx context.Context, interval time.Duration, fn PushFunc)
}

// manager is the default Manager implementation.
type manager struct {
	logger *zap.Logger
	stats  *stats
}

// stats represents an internal statistics object.
type stats struct {
	BytesIn    *atomic.Uint64
	BytesOut   *atomic.Uint64
	PacketsIn  *atomic.Uint64
	PacketsOut *atomic.Uint64

	BytesInCumulative    *atomic.Uint64
	BytesOutCumulative   *atomic.Uint64
	PacketsInCumulative  *atomic.Uint64
	PacketsOutCumulative *atomic.Uint64
}

// cumulativeSnapshot returns a read-only copy of the cumulative counters.
func (s *stats) cumulativeSnapshot() *Stats {
	return &Stats{
		BytesIn:    s.BytesInCumulative.Load(),
		BytesOut:   s.BytesOutCumulative.Load(),
		PacketsIn:  s.PacketsInCumulative.Load(),
		PacketsOut: s.PacketsOutCumulative.Load(),
	}
}

// deltaAndClear returns a read-only copy of the delta counters since
// the last call to deltaAndClear and resets all counters to zero.
func (s *stats) deltaAndClear() *Delta {
	return &Delta{
		BytesIn:    s.BytesIn.Swap(0),
		BytesOut:   s.BytesOut.Swap(0),
		PacketsIn:  s.PacketsIn.Swap(0),
		PacketsOut: s.PacketsOut.Swap(0),
	}
}

// NewManager returns a newly initialized default Manager.
func NewManager(logger *zap.Logger) Manager {
	return &manager{
		logger: logger,
		stats: &stats{
			BytesIn:              atomic.NewUint64(0),
			BytesOut:             atomic.NewUint64(0),
			PacketsIn:            atomic.NewUint64(0),
			PacketsOut:           atomic.NewUint64(0),
			BytesInCumulative:    atomic.NewUint64(0),
			BytesOutCumulative:   atomic.NewUint64(0),
			PacketsInCumulative:  atomic.NewUint64(0),
			PacketsOutCumulative: atomic.NewUint64(0),
		},
	}
}

// IncBytesIn increments the bytes-in counter.
func (m *manager) IncBytesIn(n uint64) {
	m.stats.BytesIn.Add(n)
	m.stats.BytesInCumulative.Add(n)
}

// IncBytesOut increments the bytes-out counter.
func (m *manager) IncBytesOut(n uint64) {
	m.stats.BytesOut.Add(n)
	m.stats.BytesOutCumulative.Add(n)
}

// IncPacketsIn increments the packets-in counter.
func (m *manager) IncPacketsIn(n uint64) {
	m.stats.PacketsIn.Add(n)
	m.stats.PacketsInCumulative.Add(n)
}

// IncPacketsOut increments the packets-out counter.
func (m *manager) IncPacketsOut(n uint64) {
	m.stats.PacketsOut.Add(n)
	m.stats.PacketsOutCumulative.Add(n)
}

// Snapshot returns a read-only snapshot of the current
func (m *manager) Snapshot() *Stats { return m.stats.cumulativeSnapshot() }

// Push periodically publishes the values of the
// Manager's counters by invoking the given PushFunc.
func (m *manager) Push(ctx context.Context, interval time.Duration, fn PushFunc) {
	for {
		select {
		case <-ctx.Done():
			// try pushing a final time.
			if err := fn(m.stats.deltaAndClear()); err != nil {
				m.logger.Warn("stats tracker failed to push current counter values", zap.Error(err))
			}
			m.logger.Info("context cancelled, shutting down stats tracker")
			return
		case <-time.After(interval):
			if err := fn(m.stats.deltaAndClear()); err != nil {
				m.logger.Warn("stats tracker failed to push current counter values", zap.Error(err))
			}
		}
	}
}
