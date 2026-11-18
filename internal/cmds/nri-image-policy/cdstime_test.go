package nriimagepolicy

import (
	"testing"
	"time"
)

// localClock is a CDS clock no test drives: it follows the local clock, as it
// does on a node before the first poll reply.
func localClock() *cdsClock {
	return newCDSClock(time.Now)
}

// The node judges a component set's deadline by the CDS's time, not the
// host's: every poll reply dates it, and it only ever moves forward.
func TestCDSClockFollowsTheDateOfAReply(t *testing.T) {
	start := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	local := start
	clock := newCDSClock(func() time.Time { return local })

	if got := clock.now(); !got.Equal(start) {
		t.Fatalf("before the first reply the clock reads %s, want the local %s", got, start)
	}

	dated := start.Add(2 * time.Hour)
	clock.observe(dated)
	if got := clock.now(); !got.Equal(dated) {
		t.Fatalf("CDS time = %s, want the reply's date %s", got, dated)
	}

	local = local.Add(time.Minute)
	if got := clock.now(); !got.Equal(dated.Add(time.Minute)) {
		t.Fatalf("CDS time = %s, want it carried a minute past %s", got, dated)
	}

	clock.observe(dated.Add(-time.Hour))
	clock.observe(time.Time{})
	if got := clock.now(); !got.Equal(dated.Add(time.Minute)) {
		t.Fatalf("CDS time = %s after an earlier and an undated reply, want it unchanged", got)
	}

	ahead := dated.Add(time.Hour)
	clock.observe(ahead)
	if got := clock.now(); !got.Equal(ahead) {
		t.Fatalf("CDS time = %s, want the later date %s", got, ahead)
	}
}
