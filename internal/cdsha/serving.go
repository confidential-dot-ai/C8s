// What a replica answers about itself: whether it serves reads, and whether
// the cluster would keep a majority while one of its replicas is replaced.
//
// Both answers carry the reason they do not hold, because both are what an
// operator waits for: the readiness probe of a replica, and the gate between
// two steps of a roll.

package cdsha

import (
	"fmt"
	"sync"
	"time"
)

type Serving struct {
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
	SinceMS int64  `json:"since_ms"`
}

// A replica serves a read once it holds a read lease whose watermark has
// applied here (lease.go).
func (n *Node) Serving() Serving {
	ok, reason := n.servesReads()
	return n.servingSince.holding(ok, reason, time.Now())
}

func (n *Node) servesReads() (bool, string) {
	if !n.fsm.ClusterState().Joined() {
		return false, "this replica holds no cluster"
	}
	if stuck := n.fsm.Stuck(); stuck != "" {
		return false, "this replica stopped following the log: " + stuck
	}
	if fence := n.Fenced(); fence != nil {
		return false, fence.Reason
	}
	lease := n.lease.Load()
	if lease == nil || !n.holdsNow(lease) {
		return false, n.outageReason()
	}
	if applied := n.fsm.AppliedIndex(); applied < lease.index {
		return false, fmt.Sprintf("the cluster's watermark is log index %d, and this replica has applied %d",
			lease.index, applied)
	}
	return true, ""
}

func (n *Node) outageReason() string {
	if outage := n.outage.Load(); outage != nil {
		return outage.reason
	}
	return "this replica has confirmed no read with its cluster"
}

// Keeps when the answer last changed, so a reader of it sees a replica that flaps.
type servingState struct {
	mu    sync.Mutex
	ok    bool
	since time.Time
}

func (s *servingState) holding(ok bool, reason string, now time.Time) Serving {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.changedTo(ok) {
		s.ok = ok
		s.since = now
	}
	return Serving{
		OK:      ok,
		Reason:  reason,
		SinceMS: now.Sub(s.since).Milliseconds(),
	}
}

// s.mu held. The first answer of all counts as a change.
func (s *servingState) changedTo(ok bool) bool {
	return s.since.IsZero() || ok != s.ok
}

type RollSafety struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Only the leader knows the seats, so a replica that does not lead reports
// none of this. It asks no peer: its seat duty keeps what it answers from
// (seats.go).
func (n *Node) RollSafe() (RollSafety, bool) {
	if !n.leading() {
		return RollSafety{}, false
	}
	seen, held := n.seatingNow()
	if !held {
		return RollSafety{Reason: "this cluster has not started"}, true
	}
	if reason := n.unsafeToRoll(seen); reason != "" {
		return RollSafety{Reason: reason}, true
	}
	return RollSafety{OK: true}, true
}

func (n *Node) unsafeToRoll(seen seating) string {
	switch {
	case len(seen.deadVoters) > 0:
		return fmt.Sprintf("voter %s is still giving up its seat", seen.deadVoters[0].ID)
	case len(seen.staying) != seen.seats:
		return fmt.Sprintf("%d of the %d voter seats are filled", len(seen.staying), seen.seats)
	case !n.everyVoterAnsweredRecently(seen):
		return "a voter seat has not answered this leader's last pass"
	case !n.everyVoterHolds(seen):
		return "a seat change has not reached every voter"
	}
	return ""
}

// INVARIANT: a seat change waits DeadAfter before it counts a voter dead, and
// a roll does not: a replica whose VM is gone holds its vote that long, and an
// operator who took the next replica away meanwhile would leave the cluster
// two seats no replica answers at.
func (n *Node) everyVoterAnsweredRecently(seen seating) bool {
	// Discovery re-checks every member it knows once a tick.
	within := 2 * n.cfg.Timing.Tick
	now := time.Now()
	for _, server := range seen.voters {
		if string(server.ID) == string(n.member) {
			continue
		}
		if now.Sub(n.lastAnswerOrFirstSight(server.ID, now)) > within {
			return false
		}
	}
	return true
}
