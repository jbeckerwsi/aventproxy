package imm

import (
	"slices"
	"time"
)

// The SCD860 treats live-video start and stop as global switches on its one
// encoder, with no count of viewers: when any session stops live video (an
// explicit stop, a disconnect, or its timeout) the encoder falls to its idle
// rate of about 10.8 fps, even while other sessions still watch. A stop
// followed by a play on a remaining session restarts it at 30 fps, for every
// viewer, the official app included, at the cost of a gap until the next IDR.
//
// The camera can also be slow for reasons a restart does not fix, so the guard
// only acts on a fall from full rate that it has seen itself: it arms once the
// session has run at full rate, fires once when the rate then drops to idle,
// and re-arms only after full rate is back. A camera that is slow from the
// start, or stays slow after a restart, is left alone.

const (
	fpsWindow       = 12
	fpsSlowInterval = 60 * time.Millisecond // below ~16 fps
	fpsFullInterval = 45 * time.Millisecond // above ~22 fps
)

type fpsGuard struct {
	intervals []time.Duration
	armed     bool
}

func newFPSGuard() *fpsGuard {
	return &fpsGuard{}
}

// observe takes the interval to the previous frame, from the camera's RTP
// timestamps, and reports whether live video should be restarted now.
func (g *fpsGuard) observe(interval time.Duration) bool {
	if interval <= 0 || interval > time.Second {
		return false
	}
	g.intervals = append(g.intervals, interval)
	if len(g.intervals) > fpsWindow {
		g.intervals = g.intervals[len(g.intervals)-fpsWindow:]
	}
	if len(g.intervals) < fpsWindow {
		return false
	}
	sorted := slices.Clone(g.intervals)
	slices.Sort(sorted)
	median := sorted[fpsWindow/2]

	switch {
	case median < fpsFullInterval:
		g.armed = true
	case median >= fpsSlowInterval && g.armed:
		g.armed = false
		g.intervals = g.intervals[:0]
		return true
	}
	return false
}
