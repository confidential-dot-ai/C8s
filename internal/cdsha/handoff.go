// Handing the cluster over. Heartbeats keep a leader's leadership and say
// nothing about its state machine, so no election takes out a leader that
// stopped following the log or trails so far behind it that it certifies no
// read. Such a leader serves nobody, and commits no write for anyone: it
// hands the cluster to a voter that follows the log. Its own seat is left
// alone.
//
// Raft v1.8 queues one transfer per target in that target's replicator until
// the request in flight to it returns. A second transfer to the same target
// meanwhile blocks Raft's transfer monitor, and the leader then refuses every
// write and every barrier until the slot drains, for good if it steps down
// first (hashicorp/raft#696). A target therefore takes one transfer per
// cooldown.

package cdsha

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

type transfers struct {
	mu   sync.Mutex
	sent map[raft.ServerID]time.Time
}

func newTransfers() *transfers {
	return &transfers{sent: map[raft.ServerID]time.Time{}}
}

func (t *transfers) send(target raft.ServerID, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sent[target] = now
}

func (t *transfers) holding(target raft.ServerID, now time.Time, cooldown time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	sent, held := t.sent[target]
	return held && now.Sub(sent) < cooldown
}

func (t *transfers) forget(target raft.ServerID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sent, target)
}

// The longest one Raft request to a target can take, plus the transfer's own
// timeout.
func (n *Node) transferCooldown() time.Duration {
	return peerRPCTimeout + n.cfg.Timing.Election
}

func (n *Node) handOverTo(target raft.Server) error {
	if n.peers.clockQuarantined(string(target.ID)) {
		return errors.New("cds-ha: the handover target is clock-quarantined")
	}
	if n.ClockError() != nil {
		answer, eligible := n.transferStanding(target)
		if !eligible || answer.Stuck != "" || answer.Applied < n.fsm.AppliedIndex() {
			return errors.New("cds-ha: no current clock-eligible handover target")
		}
	}

	n.transfers.send(target.ID, time.Now())
	err := n.raft.LeadershipTransferToServer(target.ID, target.Address).Error()
	if queuedNothing(err) {
		n.transfers.forget(target.ID)
	}
	return err
}

// The refusal Raft answers before it queued a transfer leaves the target free
// to take the next one; every other outcome leaves it holding this one.
func queuedNothing(err error) bool {
	return errors.Is(err, raft.ErrLeadershipTransferInProgress)
}

// A loop of its own: the duties loop can wait behind the very state machine
// it would judge, and a transfer waits on Raft.
func (n *Node) watchHandover(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	var watch slowLeader
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if n.ClockError() != nil {
			n.handOverWhenClockQuarantined()
			continue
		}
		n.handOverWhenStuck()
		n.handOverWhenSlow(&watch, time.Now())
	}
}

// Run ends this process once the voters that follow the log keep a majority
// without it (stuck.go).
func (n *Node) handOverWhenStuck() {
	reason := n.fsm.Stuck()
	if !n.leading() || reason == "" {
		return
	}
	target, found := n.aVoterThatApplied(n.fsm.AppliedIndex())
	if !found {
		if n.stuckLog.changed(reason) {
			slog.Warn("cds-ha: this leader stopped following the log and no voter of its cluster is fit to take it over",
				"reason", reason)
		}
		return
	}
	slog.Warn("cds-ha: this leader stopped following the log; it hands the cluster over",
		"reason", reason,
		"member", target.ID)
	if err := n.handOverTo(target); err != nil {
		slog.Warn("cds-ha: this leader could not hand the cluster over",
			"member", target.ID,
			"error", err)
	}
}

func (n *Node) handOverWhenSlow(watch *slowLeader, now time.Time) {
	if !n.leading() || n.fsm.Stuck() != "" {
		return
	}
	led := n.following()
	watch.follow(led, now)
	if !watch.certifiesNoRead(n.certifiedARead(led), now, n.cfg.Timing) {
		return
	}
	target, further := n.aVoterThatApplied(n.fsm.AppliedIndex() + slowLeaderMargin)
	if !further {
		return
	}
	watch.tried(now)
	slog.Warn("cds-ha: this leader's own state machine keeps every replica from answering a read; it hands the cluster over",
		"member", target.ID, "applied_index", n.fsm.AppliedIndex(), "commit_index", n.raft.CommitIndex())
	if err := n.handOverTo(target); err != nil {
		slog.Warn("cds-ha: this leader could not hand the cluster over",
			"member", target.ID,
			"error", err)
	}
}

// INVARIANT: applied is an index of a state machine, not Raft's commit index,
// which counts configuration entries no state machine applies. A voter that
// trails would leave the transfer queued inside Raft.
func (n *Node) aVoterThatApplied(applied uint64) (raft.Server, bool) {
	var furthest raft.Server
	var most uint64
	found := false
	for _, candidate := range n.handoverCandidates() {
		answer, eligible := n.transferStanding(candidate)
		if !eligible || answer.Stuck != "" || answer.Applied < applied {
			continue
		}
		if !found || answer.Applied > most {
			furthest = candidate
			most = answer.Applied
			found = true
		}
	}
	return furthest, found
}

func (n *Node) handoverCandidates() []raft.Server {
	term := n.following().term
	now := time.Now()
	var candidates []raft.Server
	for _, server := range n.configuration() {
		if n.couldTakeTheCluster(server, term, now) {
			candidates = append(candidates, server)
		}
	}
	return candidates
}

func (n *Node) couldTakeTheCluster(server raft.Server, term uint64, now time.Time) bool {
	switch {
	case server.Suffrage != raft.Voter:
		return false
	case string(server.ID) == string(n.member):
		return false
	case n.failures.failingFor(term, server.ID, now) > 0:
		return false
	case n.peers.clockQuarantined(string(server.ID)):
		return false
	case n.transfers.holding(server.ID, now, n.transferCooldown()):
		return false
	}
	return true
}

// Two replicas of one cluster apply the same entries, so one entry of
// difference is a moment rather than a slow leader.
const slowLeaderMargin = 2

// Only the handover loop touches it.
type slowLeader struct {
	term    uint64
	since   time.Time
	lastTry time.Time
}

// The last attempt at a transfer stands, so a leader cannot try one per term.
func (s *slowLeader) follow(led leadership, now time.Time) {
	if s.term == led.term {
		return
	}
	s.term = led.term
	s.since = now
}

func (s *slowLeader) certifiesNoRead(certified, now time.Time, timing Timing) bool {
	if s.withoutCertifyingARead(certified, now) < timing.Lease {
		return false
	}
	return now.Sub(s.lastTry) >= timing.DeadAfter
}

// Counted from the term this leader took where it has certified none in it.
func (s *slowLeader) withoutCertifyingARead(certified, now time.Time) time.Duration {
	if certified.After(s.since) {
		return now.Sub(certified)
	}
	return now.Sub(s.since)
}

func (s *slowLeader) tried(now time.Time) {
	s.lastTry = now
}

// A lease of this leadership is a read certified for every replica that asked
// (lease.go).
func (n *Node) certifiedARead(led leadership) time.Time {
	lease := n.lease.Load()
	if lease == nil || !lease.same(led) {
		return time.Time{}
	}
	return lease.taken
}

func (n *Node) handOverWhenClockQuarantined() {
	reason := n.ClockError()
	if !n.leading() || reason == nil {
		return
	}
	target, found := n.aVoterThatApplied(n.fsm.AppliedIndex())
	if !found {
		if n.stuckLog.changed(reason.Error()) {
			slog.Warn("cds-ha: clock-quarantined leader has no eligible voter to take over", "reason", reason)
		}
		return
	}
	if err := n.handOverTo(target); err != nil {
		slog.Warn("cds-ha: clock-quarantined leader could not hand the cluster over", "member", target.ID, "error", err)
	}
}

func (n *Node) transferStanding(candidate raft.Server) (controlAnswer, bool) {
	core := n.fsm.ClusterState()
	held, reached := n.peers.knownAt(string(candidate.ID))
	if !core.Joined() || !reached || candidate.Suffrage != raft.Voter {
		return controlAnswer{}, false
	}
	answer, err := held.control.exchange(controlRequest{Op: opStanding}, controlTimeout)
	if err != nil || answer.Err != "" || !answer.Joined || (n.ClockError() != nil && answer.Clock == nil) || !slices.Contains(answer.Voters, string(candidate.ID)) {
		return controlAnswer{}, false
	}
	if err := held.control.attested().admittedBy(n.admits()); err != nil {
		return controlAnswer{}, false
	}
	n.fsm.mu.RLock()
	defer n.fsm.mu.RUnlock()
	if !n.fsm.core.Joined() || n.fsm.core.Version != core.Version {
		return controlAnswer{}, false
	}
	current := n.configuration()
	if !slices.Contains(current, candidate) {
		return controlAnswer{}, false
	}
	if answer.Clock != nil {
		n.peers.recordClock(held.member, answer.Clock.Quarantined, current)
	}
	return answer, !n.peers.clockQuarantined(held.member)
}
