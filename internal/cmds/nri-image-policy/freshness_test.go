package nriimagepolicy

import (
	"sync/atomic"
	"testing"
	"time"
)

// movingClock is a local clock a test moves while the pull loop reads it.
type movingClock struct {
	at atomic.Pointer[time.Time]
}

func newMovingClock(at time.Time) *movingClock {
	c := &movingClock{}
	c.at.Store(&at)
	return c
}

func (c *movingClock) now() time.Time {
	return *c.at.Load()
}

func (c *movingClock) advance(d time.Duration) {
	at := c.now().Add(d)
	c.at.Store(&at)
}

// The limit a node takes from a reply is the certificate lifetime it reports,
// never above the cap, and the cap when the reply reports none.
func TestFreshnessLimitFollowsTheReportedCertificateLifetime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reported time.Duration
		want     time.Duration
	}{
		{name: "an hour", reported: time.Hour, want: time.Hour},
		{name: "longer than the cap", reported: 48 * time.Hour, want: freshnessLimitCap},
		{name: "none reported", want: freshnessLimitCap},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := newFreshness(newMovingClock(time.Now()).now)
			fresh.replied(tc.reported, true)
			if _, got := fresh.report(); got != tc.want {
				t.Fatalf("limit = %s, want %s", got, tc.want)
			}
		})
	}
}

// A node is behind until its first fresh poll, falls back once the limit has
// passed without one, and falls back once per lapse.
func TestFreshnessFallsBackOncePerLapse(t *testing.T) {
	clock := newMovingClock(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	fresh := newFreshness(clock.now)

	if !fresh.pendingFallback() {
		t.Fatal("a node with no fresh poll of its own is not behind")
	}
	fresh.replied(time.Hour, true)
	if behind, _ := fresh.report(); !behind {
		t.Fatal("the last poll was fresh, but the node does not report it")
	}

	clock.advance(time.Hour)
	fresh.unanswered()
	if fresh.pendingFallback() {
		t.Fatal("a node within its limit fell back")
	}
	clock.advance(time.Second)
	if !fresh.pendingFallback() {
		t.Fatal("a node past its limit did not fall back")
	}

	fresh.noteFallback()
	if fresh.pendingFallback() || !fresh.fellBackToBase() {
		t.Fatal("the fallback runs again before a fresh poll")
	}

	fresh.replied(time.Hour, true)
	if fresh.fellBackToBase() {
		t.Fatal("a fresh poll left the node on its base allowlist")
	}
	clock.advance(2 * time.Hour)
	if !fresh.pendingFallback() {
		t.Fatal("the node did not fall back again after a later lapse")
	}
}

// A reply that names a document the node does not apply leaves it behind,
// however many such replies arrive.
func TestFreshnessStaleReplyDoesNotMoveTheFreshReading(t *testing.T) {
	clock := newMovingClock(time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC))
	fresh := newFreshness(clock.now)
	fresh.replied(time.Hour, true)

	clock.advance(time.Hour + time.Second)
	fresh.replied(time.Hour, false)
	if behind, _ := fresh.report(); behind {
		t.Fatal("a reply naming another document reports the node fresh")
	}
	if !fresh.pendingFallback() {
		t.Fatal("replies naming another document kept the node from falling back")
	}
}
