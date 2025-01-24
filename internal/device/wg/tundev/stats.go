package tundev

import "github.com/borderzero/border0-cli/internal/device/utils/stats"

// uncommittedStats represents statistics used
// to measure packets and bytes read in the
// tun.Device implementation's Read() and Write().
type uncommittedStats struct {
	tracker stats.Tracker

	bytesRead      uint64
	bytesWritten   uint64
	packetsRead    uint64
	packetsWritten uint64
}

// init stats returns fresh uncommittedStats with all counters set to zero.
func initStats(tracker stats.Tracker) *uncommittedStats {
	return &uncommittedStats{
		tracker: tracker,

		bytesRead:      0,
		bytesWritten:   0,
		packetsRead:    0,
		packetsWritten: 0,
	}
}

// commit adds the uncommited stats to the global stats tracker.
func (s *uncommittedStats) commit() {
	s.tracker.IncBytesIn(s.bytesRead)
	s.tracker.IncBytesOut(s.bytesWritten)
	s.tracker.IncPacketsIn(s.packetsRead)
	s.tracker.IncPacketsOut(s.packetsWritten)
}
