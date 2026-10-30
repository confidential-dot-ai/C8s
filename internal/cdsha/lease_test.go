package cdsha

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// Every replica of a settled cluster answers reads, under a watermark it has
// applied.
func TestEveryReplicaOfTheClusterAnswersReads(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	for _, r := range c.replicas {
		eventually(t, 5*time.Second, "the replica answers reads", r.node.Serving)
		lease := r.node.lease.Load()
		if lease == nil || r.node.fsm.AppliedIndex() < lease.index {
			t.Fatalf("the replica answers reads under %+v, having applied index %d", lease, r.node.fsm.AppliedIndex())
		}
	}
}

// A lease stands for a watermark: until the replica has applied it, it
// answers no read, however fresh the lease is.
func TestAReplicaAnswersNoReadBeforeItAppliedTheWatermark(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	follower := c.follower()
	lease, err := follower.node.confirmRead()
	if err != nil {
		t.Fatalf("confirm a read: %v", err)
	}
	ahead := *lease
	ahead.index = follower.node.fsm.AppliedIndex() + 1
	follower.node.lease.Store(&ahead)
	if follower.node.Serving() {
		t.Fatal("a replica answered reads under a watermark it had not applied")
	}
}

// A lease holds for the leader, term, cluster version and clock it was taken
// under, and for a lease's life.
func TestALeaseEndsWithWhatItWasTakenUnder(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	node := c.leader().node
	lease, err := node.confirmRead()
	if err != nil {
		t.Fatalf("confirm a read: %v", err)
	}
	if !node.holdsNow(lease) {
		t.Fatal("the replica refused the lease it just took")
	}
	for name, outdate := range map[string]func(*readLease){
		"a lease as old as a lease's life": func(l *readLease) { l.taken = time.Now().Add(-testTiming.Lease) },
		"another leader":                   func(l *readLease) { l.member = "another-member" },
		"another leader address":           func(l *readLease) { l.leader = raft.ServerAddress("127.0.0.1:1#another-member") },
		"a later term":                     func(l *readLease) { l.term++ },
		"another cluster version":          func(l *readLease) { l.version++ },
		"a clock that jumped":              func(l *readLease) { l.jumps++ },
	} {
		t.Run(name, func(t *testing.T) {
			outdated := *lease
			outdate(&outdated)
			if node.holdsNow(&outdated) {
				t.Fatal("the replica answers reads under an outdated lease")
			}
		})
	}
}

// A replica cut off from its cluster answers no read once its lease runs out,
// says why, and answers again when the cut is over.
func TestACutOffReplicaAnswersNoReadAndSaysWhy(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	cut := c.follower()
	c.partition(cut, true)
	eventually(t, 5*time.Second, "the cut replica answers no read", func() bool {
		return !cut.node.Serving()
	})
	eventually(t, 5*time.Second, "the cut replica says why it confirms no read", func() bool {
		return cut.node.outage.Load() != nil
	})
	if outage := cut.node.outage.Load(); outage.reason == "" || outage.since.IsZero() {
		t.Fatalf("the cut replica reports the outage as %+v", outage)
	}
	if err := cut.node.ConfirmRead(); err == nil {
		t.Fatal("the cut replica confirmed a read with the cluster")
	}
	c.partition(cut, false)
	eventually(t, 15*time.Second, "the replica that returned confirms reads again", func() bool {
		return cut.node.Serving() && cut.node.outage.Load() == nil
	})
}

// The lease a replica took from one leader is no lease under the next, so the
// state a new leader holds is confirmed before any read is answered from it.
func TestANewLeaderNeedsANewLease(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	gone := c.leader()
	var follower *liveReplica
	for _, r := range c.replicas {
		if r != gone {
			follower = r
			break
		}
	}
	lease, err := follower.node.confirmRead()
	if err != nil {
		t.Fatalf("confirm a read: %v", err)
	}
	c.stop(gone)
	eventually(t, 10*time.Second, "another leader", func() bool {
		elected := follower.node.following()
		return elected.known() && elected.member != lease.member
	})
	// Taken now, so what the lease names is what ends it, not its age.
	underTheOldLeader := *lease
	underTheOldLeader.taken = time.Now()
	if follower.node.holdsNow(&underTheOldLeader) {
		t.Fatal("a replica answers reads under the lease of a leader that is gone")
	}
	eventually(t, 10*time.Second, "a lease from the new leader", follower.node.Serving)
}

// A leader that lost its quorum confirms no read: a barrier needs one, so a
// leader's own state is no proof that the cluster is still behind it.
func TestALeaderWithoutAQuorumConfirmsNoRead(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	for _, r := range slices.Clone(c.replicas) {
		if r != leader {
			c.stop(r)
		}
	}
	if err := leader.node.ConfirmRead(); err == nil {
		t.Fatal("a leader whose peers are gone confirmed a read")
	}
	eventually(t, 5*time.Second, "the leader answers no read", func() bool {
		return !leader.node.Serving()
	})
}

// A leader passes one barrier at a time: while one is in flight, whoever
// asks next, a peer included, is refused instead of appending another.
func TestALeaderPassesOneBarrierAtATime(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader().node
	if !leader.barriers.take(time.Now().Add(testTiming.Lease)) {
		t.Fatal("a barrier was in flight before the test asked for one")
	}
	defer leader.barriers.give()
	appended := leader.raft.LastIndex()
	refusedForItself, err := leader.barrier()
	if err == nil {
		t.Fatalf("a leader passed two barriers at once: %+v", refusedForItself)
	}
	asking := peer{member: string(c.follower().node.member)}
	if answer := leader.answerControl(asking, controlRequest{Op: opRead}); answer.Err == "" || answer.Index != 0 {
		t.Fatalf("a leader with a barrier in flight answered a peer %+v", answer)
	}
	if last := leader.raft.LastIndex(); last != appended {
		t.Fatalf("a refused barrier appended to the log: index %d, was %d", last, appended)
	}
}

// A follower confirms its reads with the member it follows, over the control
// channel, and takes the watermark that member's barrier confirmed.
func TestAFollowerConfirmsItsReadsWithTheLeader(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	follower := c.follower()
	leader := follower.node.following()
	confirmed, err := follower.node.askLeaderToConfirm(leader)
	if err != nil {
		t.Fatalf("ask the leader to confirm a read: %v", err)
	}
	if applied := c.leader().node.fsm.AppliedIndex(); confirmed < applied {
		t.Fatalf("the leader confirmed log index %d, having applied %d", confirmed, applied)
	}
}

// The control channel answers a peer's read confirmation, which only the
// leader can give.
func TestOnlyTheLeaderConfirmsAReadForAPeer(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader().node
	follower := c.follower().node
	asking := peer{member: string(follower.member)}
	confirmed := leader.answerControl(asking, controlRequest{Op: opRead})
	if confirmed.Err != "" || confirmed.Index == 0 {
		t.Fatalf("the leader answered a read confirmation with %+v", confirmed)
	}
	refused := follower.answerControl(peer{member: string(leader.member)}, controlRequest{Op: opRead})
	if refused.Err == "" || refused.Index != 0 || refused.Leader != string(leader.member) {
		t.Fatalf("a replica that does not lead answered %+v", refused)
	}
}

// A replica whose clock jumped answers no read until it has confirmed one
// under the clock it has now.
func TestAClockJumpStopsReadsUntilTheNextLease(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	node := c.follower().node
	eventually(t, 5*time.Second, "the replica answers reads", node.Serving)
	node.clockJumps.Add(1)
	if node.Serving() {
		t.Fatal("a replica whose clock jumped answered a read under the lease it held")
	}
	eventually(t, 5*time.Second, "a lease under the clock it has now", node.Serving)
}

// The wall clock moving apart from the monotonic one is a jump: the host
// stepped the clock, or it suspended the VM, whose monotonic clock stopped
// while the wall clock ran on. A loaded host, whose two clocks keep up with
// each other, is none.
func TestClockJumped(t *testing.T) {
	for name, look := range map[string]struct {
		wall, mono time.Duration
		want       bool
	}{
		"two clocks that keep up":    {wall: clockLook, mono: clockLook, want: false},
		"drift within the slack":     {wall: clockLook + time.Second, mono: clockLook, want: false},
		"the clock stepped ahead":    {wall: time.Hour, mono: clockLook, want: true},
		"the clock stepped back":     {wall: -time.Hour, mono: clockLook, want: true},
		"a VM the host suspended":    {wall: time.Minute, mono: clockLook, want: true},
		"a look a whole minute late": {wall: time.Minute, mono: time.Minute, want: false},
		"a look the host made wait":  {wall: 5 * clockLook, mono: 5 * clockLook, want: false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := clockJumped(look.wall, look.mono); got != look.want {
				t.Fatalf("a look %s after the one before, with the wall clock %s on: %v", look.mono, look.wall, got)
			}
		})
	}
}

// A replica that holds no cluster answers no read, and says so.
func TestAReplicaWithNoClusterAnswersNoRead(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	eventually(t, 5*time.Second, "the replica reports why it answers no read", func() bool {
		return r.node.outage.Load() != nil
	})
	if reason := r.node.outage.Load().reason; !strings.Contains(reason, "holds no cluster") {
		t.Fatalf("a replica with no cluster reports %q", reason)
	}
	if r.node.Serving() {
		t.Fatal("a replica with no cluster answered a read")
	}
}

// A replica on its way out answers no read: its lease is gone before its
// Raft is.
func TestAStoppingReplicaAnswersNoRead(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leaving := c.follower()
	eventually(t, 5*time.Second, "the replica answers reads", leaving.node.Serving)
	c.stop(leaving)
	if leaving.node.lease.Load() != nil {
		t.Fatal("a replica that stopped kept the lease it answered reads under")
	}
}

// A confirmation that failed leaves a lease that still holds standing: it
// says nothing about the state the lease stands for, and the replica keeps
// answering reads until the lease runs out.
func TestAFailedConfirmationLeavesAStandingLeaseAlone(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	follower := c.follower()
	eventually(t, 5*time.Second, "the replica answers reads", follower.node.Serving)
	follower.node.refreshFailed(errors.New("the leader did not answer"))
	if follower.node.lease.Load() == nil || !follower.node.Serving() {
		t.Fatal("a confirmation that failed ended a lease that still holds")
	}
	eventually(t, 5*time.Second, "the replica confirms reads again", func() bool {
		return follower.node.outage.Load() == nil && follower.node.Serving()
	})
}

// A replica whose Raft is not started confirms no read, and answers none.
func TestAReplicaThatIsNotStartedConfirmsNoRead(t *testing.T) {
	c := newLiveCluster(t)
	node, err := NewNode(c.replicaConfig(c.attestationAPI()))
	if err != nil {
		t.Fatal(err)
	}
	if err := node.ConfirmRead(); err == nil {
		t.Fatal("a replica that is not started confirmed a read")
	}
	if node.Serving() {
		t.Fatal("a replica that is not started answered a read")
	}
}
