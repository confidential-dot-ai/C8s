// Read leases: a replica answers a read under a watermark the cluster's
// leader confirmed behind a barrier, applied here, and younger than
// Timing.Lease.
//
// Raft's heartbeats say that a leader is alive and nothing about this
// replica's own state, so a replica that went by them would answer from state
// the cluster has moved past: an allowlist entry it revoked, or an image a
// decree unpinned.
//
// A worker of its own confirms the reads, so answering one under the lease
// makes no network call. A confirmation that failed renews no lease, and
// leaves a lease that still holds to run out on its own.

package cdsha

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// readLease is a watermark a quorum confirmed and this replica applied.
type readLease struct {
	leadership
	// taken is the start of the request that confirmed the watermark: delay
	// on the way cannot date a lease later than the state it stands for.
	taken time.Time
	index uint64
	// version is the cluster's version the lease was taken under: a decree
	// applied since changes the trust a read is answered from.
	version uint64
	// jumps is the clock jumps this replica had seen when it took the lease.
	jumps uint64
}

// leadership is the leader a replica follows, in the term it follows it.
type leadership struct {
	leader raft.ServerAddress
	member raft.ServerID
	term   uint64
}

// following is the leadership this replica follows now. Raft answers the
// leader and the term one at a time, so a term that moves between the two
// answers is no leadership at all.
func (n *Node) following() leadership {
	term := n.raft.Load().CurrentTerm()
	leader, member := n.raft.Load().LeaderWithID()
	if n.raft.Load().CurrentTerm() != term {
		return leadership{}
	}
	return leadership{
		leader: leader,
		member: member,
		term:   term,
	}
}

func (l leadership) known() bool {
	return l.leader != ""
}

func (l leadership) same(other leadership) bool {
	return l.leader == other.leader && l.member == other.member && l.term == other.term
}

func (n *Node) leadsAs(led leadership) bool {
	return n.leading() && n.following().same(led)
}

// holdsNow: the leader, term, cluster version and clock the lease was taken
// under are the ones of this moment.
func (n *Node) holdsNow(lease *readLease) bool {
	if time.Since(lease.taken) >= n.cfg.Timing.Lease {
		return false
	}
	return lease.same(n.following()) && lease.version == n.fsm.ClusterState().Version && lease.jumps == n.clockJumps.Load()
}

// ConfirmRead returns once the watermark the cluster confirmed has applied
// here. It leaves the lease the refresh worker publishes alone.
func (n *Node) ConfirmRead() error {
	_, err := n.confirmRead()
	return err
}

// readTimeout bounds one read confirmation: a confirmation that took a whole
// lease leaves a lease too old to answer a read under.
func (n *Node) readTimeout() time.Duration {
	return min(n.cfg.Timing.Apply, n.cfg.Timing.Lease)
}

// confirmRead takes a lease: the watermark the leader confirmed, and the wait
// for this replica's own state machine to reach it.
func (n *Node) confirmRead() (*readLease, error) {
	if n.raft.Load() == nil {
		return nil, errors.New("cds-ha: this replica is not started")
	}
	core := n.fsm.ClusterState()
	if !core.Joined() {
		return nil, errors.New("cds-ha: this replica holds no cluster")
	}
	if reason := n.fsm.Stuck(); reason != "" {
		return nil, errors.New("cds-ha: this replica stopped following the log: " + reason)
	}
	leader := n.following()
	if !leader.known() {
		return nil, errors.New("cds-ha: this replica follows no leader")
	}
	taken := time.Now()
	jumps := n.clockJumps.Load()
	confirmed, err := n.confirmedWatermark(leader)
	if err != nil {
		return nil, err
	}
	// A committed index holds the same entry on every replica of the cluster,
	// so this replica waits for its own state machine to reach it.
	if !n.awaitApplied(confirmed, n.readTimeout()-time.Since(taken)) {
		return nil, fmt.Errorf("cds-ha: the cluster's watermark is log index %d, and this replica has applied %d", confirmed, n.fsm.AppliedIndex())
	}
	lease := &readLease{
		leadership: leader,
		taken:      taken,
		index:      confirmed,
		version:    core.Version,
		jumps:      jumps,
	}
	if !n.holdsNow(lease) {
		return nil, errors.New("cds-ha: the leader, term, cluster version or clock changed while the read was confirmed")
	}
	return lease, nil
}

// confirmedWatermark is a watermark a quorum confirmed: the leader passes a
// barrier of its own, and every other replica asks the leader for one.
func (n *Node) confirmedWatermark(leader leadership) (uint64, error) {
	if n.leading() {
		return n.barrier()
	}
	return n.askLeaderToConfirm(leader)
}

// oneBarrier admits one barrier at a time. The barrier in flight holds the
// slot until it finishes, so a caller that gave up cannot pile another
// barrier onto a log no snapshot compacts while the state machine is stuck.
type oneBarrier struct {
	slot chan struct{}
}

func newOneBarrier() oneBarrier {
	return oneBarrier{slot: make(chan struct{}, 1)}
}

// take waits until deadline for a barrier in flight to finish.
func (b oneBarrier) take(deadline time.Time) bool {
	waiting := time.NewTimer(time.Until(deadline))
	defer waiting.Stop()
	select {
	case b.slot <- struct{}{}:
		return true
	case <-waiting.C:
		return false
	}
}

func (b oneBarrier) give() {
	<-b.slot
}

// barrier passes a Raft barrier on this leader, which answers once a quorum
// holds every entry the leader appended and its state machine applied them.
// Raft's timeout bounds enqueueing it, so the deadline here bounds the whole
// confirmation.
func (n *Node) barrier() (uint64, error) {
	if reason := n.fsm.Stuck(); reason != "" {
		return 0, errors.New("cds-ha: this leader stopped following the log: " + reason)
	}
	// A fenced leader confirms no read, for itself or for the replicas that
	// ask it, so the leases every replica answers reads under run out.
	if fenced := n.fenced(); fenced != nil {
		return 0, fenced
	}
	deadline := time.Now().Add(n.readTimeout())
	if !n.barriers.take(deadline) {
		return 0, errors.New("cds-ha: a barrier of this leader was in flight for a whole read")
	}
	passed := make(chan barrierResult, 1)
	go n.passBarrier(passed)
	return barrierPassed(passed, deadline)
}

type barrierResult struct {
	confirmed uint64
	err       error
}

// barrierPassed: a barrier that did not pass by the deadline stays in flight,
// holding the slot until it finishes.
func barrierPassed(passed <-chan barrierResult, deadline time.Time) (uint64, error) {
	waiting := time.NewTimer(time.Until(deadline))
	defer waiting.Stop()
	select {
	case result := <-passed:
		return result.confirmed, result.err
	case <-waiting.C:
		return 0, errors.New("cds-ha: this leader's barrier did not pass within a read")
	}
}

// passBarrier gives the slot back once the barrier passed. The watermark is
// what the leader's state machine had applied behind it, which is every
// command a quorum held then.
func (n *Node) passBarrier(passed chan<- barrierResult) {
	defer n.barriers.give()
	leader := n.following()
	err := n.raft.Load().Barrier(n.readTimeout()).Error()
	n.refusals.record(leader.term, err)
	if err != nil {
		passed <- barrierResult{err: err}
		return
	}
	if !n.leadsAs(leader) || n.fsm.Stuck() != "" {
		passed <- barrierResult{err: errors.New("cds-ha: this leader's leadership or state machine changed while its barrier passed")}
		return
	}
	appliedBehindBarrier := n.fsm.AppliedIndex()
	passed <- barrierResult{confirmed: appliedBehindBarrier}
}

// askLeaderToConfirm takes the watermark the leader's own barrier confirmed.
// The connection refuses an answer from any other member.
func (n *Node) askLeaderToConfirm(leader leadership) (uint64, error) {
	held, reached := n.peers.knownAt(string(leader.member))
	if !reached {
		return 0, fmt.Errorf("cds-ha: this replica has not reached the leader, member %s", leader.member)
	}
	answer, err := held.control.exchange(
		controlRequest{
			Op:      opRead,
			Digests: n.fsm.dig.report(),
		},
		n.readTimeout(),
	)
	if err != nil {
		return 0, err
	}
	if answer.Diverged != "" {
		return 0, n.stopOnVerdict(answer, leader)
	}
	if answer.Err != "" {
		return 0, errors.New("cds-ha: the leader confirmed no read: " + answer.Err)
	}
	// An index of 0 is no watermark: a barrier always passes above it.
	if answer.Index == 0 {
		return 0, errors.New("cds-ha: the leader confirmed no watermark")
	}
	return answer.Index, nil
}

// answerRead confirms a read for the peer that asked, which only the leader
// can do, and which it does one barrier at a time. The barrier applies
// everything the cluster committed, so the peer's digests are compared with a
// state that holds every entry up to the watermark.
func (n *Node) answerRead(from peer, request controlRequest, answer controlAnswer) controlAnswer {
	if !n.leading() {
		return n.redirectToLeader(answer)
	}
	confirmed, err := n.barrier()
	if err != nil {
		answer.Err = err.Error()
		return answer
	}
	answer.Term = n.following().term
	if diverged := n.takeReport(raft.ServerID(from.member), request.Digests, confirmed); diverged != "" {
		answer.Diverged = diverged
		return answer
	}
	answer.Index = confirmed
	return answer
}

// The verdict counts only from the leadership this replica follows.
func (n *Node) stopOnVerdict(answer controlAnswer, led leadership) error {
	if answer.Term != led.term {
		return fmt.Errorf("cds-ha: the leader answered in term %d, and this replica follows term %d", answer.Term, led.term)
	}
	return n.fsm.stopLocal(fmt.Errorf("%w: %s", ErrDiverged, answer.Diverged))
}

// serveReads keeps this replica's lease fresh until ctx ends. Stopping drops
// the lease before Raft goes, so a replica on its way out answers no read.
func (n *Node) serveReads(ctx context.Context) func() {
	reads, stop := context.WithCancel(ctx)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); n.refreshReads(reads) }()
	go func() { defer workers.Done(); n.watchClock(reads) }()
	return func() {
		stop()
		workers.Wait()
		n.lease.Store(nil)
	}
}

// refreshReads confirms a read once the lease is past a third of its life.
func (n *Node) refreshReads(ctx context.Context) {
	refresh := time.NewTicker(n.cfg.Timing.Tick)
	defer refresh.Stop()
	// A confirmation outlasts a tick, so the loop looks at ctx itself: a
	// select between two ready channels may take either.
	for ctx.Err() == nil {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
		}
		if n.leaseFresh() {
			continue
		}
		lease, err := n.confirmRead()
		if err != nil {
			n.refreshFailed(err)
			continue
		}
		n.refreshed(lease)
	}
}

func (n *Node) leaseFresh() bool {
	lease := n.lease.Load()
	return lease != nil && n.holdsNow(lease) && time.Since(lease.taken) < n.cfg.Timing.Lease/3
}

// readOutage is why this replica confirms no read with its cluster, and since
// when. Only the refresh worker writes it.
type readOutage struct {
	reason string
	since  time.Time
}

// refreshFailed leaves the lease this replica holds to run out: a failed
// confirmation says nothing about the state that lease stands for.
func (n *Node) refreshFailed(err error) {
	since := time.Now()
	if begun := n.outage.Load(); begun != nil {
		since = begun.since
	} else {
		slog.Warn("cds-ha: this replica confirms no read with its cluster", "reason", err)
	}
	n.outage.Store(&readOutage{
		reason: err.Error(),
		since:  since,
	})
}

// refreshed publishes the lease reads are answered under.
func (n *Node) refreshed(lease *readLease) {
	n.lease.Store(lease)
	if begun := n.outage.Swap(nil); begun != nil {
		slog.Info("cds-ha: this replica confirms reads with its cluster again", "after", time.Since(begun.since).Round(time.Millisecond))
	}
}

// The clock is looked at this often, and it jumped when the wall clock has
// moved this far from the monotonic one since the last look.
const (
	clockLook  = 200 * time.Millisecond
	clockSlack = 2 * time.Second
)

// watchClock counts the wall clock moving apart from the monotonic one: a
// host stepping the guest's clock, or a VM it suspended. A lease taken before
// a jump is refused, so reads stop until one is confirmed under the clock
// this replica has now.
func (n *Node) watchClock(ctx context.Context) {
	look := time.NewTicker(clockLook)
	defer look.Stop()
	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-look.C:
			wall := wallClock(now).Sub(wallClock(last))
			mono := now.Sub(last)
			if clockJumped(wall, mono) {
				n.clockJumps.Add(1)
				slog.Warn("cds-ha: this replica's clock jumped; it answers no read until it has confirmed one again", "wall", wall, "monotonic", mono)
			}
			last = now
		}
	}
}

// wallClock is t without its monotonic reading, so the difference of two of
// them is the wall clock's own.
func wallClock(t time.Time) time.Time {
	return t.Round(0)
}

func clockJumped(wall, mono time.Duration) bool {
	return (wall - mono).Abs() > clockSlack
}
