// What this leader's Raft makes of the members it replicates to: a member it
// cannot reach holds no copy of the log, however well that member answers the
// control channel, so the voter seats are judged on both (seats.go).
//
// The record belongs to the term this replica leads: the replication streams
// that reported it are a leader's own. Raft reports a failure with the
// member's last contact, which is where the wait before that member counts
// dead begins; a stream outlives the member's removal, and no resume ever
// clears what it reported, so a failure older than this leader's membership
// of the member is not this membership's.

package cdsha

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Since when Raft's replication to each member has been failing, in the term
// this replica leads.
type heartbeatFailures struct {
	mu    sync.Mutex
	term  uint64
	since map[raft.ServerID]time.Time
}

func newHeartbeatFailures() *heartbeatFailures {
	return &heartbeatFailures{since: map[raft.ServerID]time.Time{}}
}

// The first time recorded for a member stands: the run of failures is one run.
func (f *heartbeatFailures) failing(term uint64, member raft.ServerID, since time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.term != term {
		f.term = term
		clear(f.since)
	}
	if _, failing := f.since[member]; failing {
		return
	}
	f.since[member] = since
}

func (f *heartbeatFailures) reached(member raft.ServerID) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.since, member)
}

// Zero for a member Raft reaches, and for every term but the one recorded.
func (f *heartbeatFailures) failingFor(term uint64, member raft.ServerID, now time.Time) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	since, failing := f.since[member]
	if !failing || f.term != term {
		return 0
	}
	return now.Sub(since)
}

const observations = 64

func (n *Node) watchHeartbeats(ctx context.Context) {
	// Raft drops an observation this replica has no room for instead of
	// holding the goroutine that reports it.
	const dropWhenFull = false
	var everyKind raft.FilterFn
	seen := make(chan raft.Observation, observations)
	observer := raft.NewObserver(seen, dropWhenFull, everyKind)
	n.raft.RegisterObserver(observer)
	defer n.raft.DeregisterObserver(observer)
	for {
		select {
		case <-ctx.Done():
			return
		case observation := <-seen:
			n.note(observation)
		}
	}
}

func (n *Node) note(observation raft.Observation) {
	switch reported := observation.Data.(type) {
	case raft.FailedHeartbeatObservation:
		n.noteFailure(reported.PeerID, reported.LastContact, time.Now())
	case raft.ResumedHeartbeatObservation:
		n.failures.reached(reported.PeerID)
	}
}

// Recorded as of the member's last contact, so the wait before it counts dead
// starts where the member went silent.
func (n *Node) noteFailure(member raft.ServerID, lastContact, now time.Time) {
	if lastContact.IsZero() {
		n.failures.failing(n.raft.CurrentTerm(), member, now)
		return
	}
	if n.fromAnEndedMembership(member, lastContact) {
		return
	}
	n.failures.failing(n.raft.CurrentTerm(), member, lastContact)
}

// A stream that outlived a re-add: its last contact with the member is from
// before this leader took that member in.
func (n *Node) fromAnEndedMembership(member raft.ServerID, lastContact time.Time) bool {
	return lastContact.Before(n.seatbook.firstSight(member))
}
