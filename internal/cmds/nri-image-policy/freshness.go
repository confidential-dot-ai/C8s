package nriimagepolicy

import (
	"sync"
	"time"
)

// freshnessLimitCap is the longest limit a node takes, whatever lifetime Trust Authority
// reports (issuer.MaxLeafTTL).
const freshnessLimitCap = 24 * time.Hour

// freshness is how far this node may be behind the Trust Authority. A poll is fresh when
// its reply names, by ETag, the document admission applies; the limit is the
// certificate lifetime Trust Authority reports, capped. Past the limit the served
// document is dropped and the base allowlist alone judges, so the host gains
// nothing by cutting a node off, holding a write back, or feeding a node a
// document it refuses.
//
// The limit is counted on the local clock, which no reply moves.
type freshness struct {
	now func() time.Time

	mu         sync.Mutex
	limit      time.Duration
	at         time.Time // local reading of the last fresh poll; zero before the first
	atLastPoll bool
	fellBack   bool
}

func newFreshness(now func() time.Time) *freshness {
	return &freshness{now: now, limit: freshnessLimitCap}
}

// replied takes a poll reply: the lifetime it reports, and whether it names
// the document admission applies. A reply without a lifetime leaves the cap.
func (f *freshness) replied(lifetime time.Duration, fresh bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.limit = freshnessLimitCap
	if lifetime > 0 {
		f.limit = min(lifetime, freshnessLimitCap)
	}
	f.atLastPoll = fresh
	if fresh {
		f.at, f.fellBack = f.now(), false
	}
}

// unanswered takes a poll the Trust Authority did not answer.
func (f *freshness) unanswered() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.atLastPoll = false
}

// pendingFallback reports whether the limit has passed without a fresh poll
// and the node has not yet fallen back. Before the first fresh poll of this
// process there is no fresh reading, so the limit has already passed.
func (f *freshness) pendingFallback() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return !f.fellBack && (f.at.IsZero() || f.now().Sub(f.at) > f.limit)
}

// noteFallback records the fallback, so it runs once until a fresh poll.
func (f *freshness) noteFallback() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fellBack = true
}

// fellBackToBase reports the node running on its base allowlist alone, where
// a container the policy no longer admits ends its whole pod.
func (f *freshness) fellBackToBase() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fellBack
}

// report is what the health endpoint serves: the last poll's freshness and
// the limit in force.
func (f *freshness) report() (fresh bool, limit time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.atLastPoll, f.limit
}
