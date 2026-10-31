package cdsha

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// A replica that stopped following the log: when it leaves its cluster, when
// it stays with the log it holds, and the command that holds its state
// machine for good.

var errStoreFault = errors.New("test: this replica's allowlist store")

// A fault of one replica's disk must not take it out of its cluster for good.
func TestAStuckReplicaLeavesWhileTheOthersKeepAMajority(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	stuck := c.follower()
	stuck.mayLeave()

	stuck.node.fsm.stopLocal(errStoreFault)

	left := c.leftWithin(stuck, c.timing.Lease+c.timing.Apply+5*time.Second)
	if !errors.Is(left, ErrLeftItsCluster) {
		t.Fatalf("a replica that stopped following the log ended its loop with %v", left)
	}
}

// The leader is the only replica that appends to the log, so a cluster whose
// leader walked out takes no write until it elects another.
func TestAStuckLeaderHandsTheClusterOverBeforeItLeaves(t *testing.T) {
	c := newLiveCluster(t)
	c.timing.DeadAfter = shortlyDead
	c.genesis(3)
	stuck := c.leader()
	stuck.mayLeave()

	stuck.node.fsm.stopLocal(errStoreFault)

	eventually(t, 30*time.Second, "another replica of the cluster leading", func() bool {
		if left, gone := stuck.left(); gone {
			t.Fatalf("the stuck leader left before another replica led: %v", left)
		}
		led := c.leader()
		return led != nil && led != stuck
	})

	left := c.leftWithin(stuck, c.timing.DeadAfter+c.timing.Apply+5*time.Second)
	if !errors.Is(left, ErrLeftItsCluster) {
		t.Fatalf("the stuck leader ended its loop with %v after it handed the cluster over", left)
	}
}

// One fault can strike every replica at the same entry. Were each of them to
// exit and rejoin, the cluster would lose the log they hold between them.
func TestAFaultOnEveryReplicaKeepsTheLogAndTheCluster(t *testing.T) {
	c := newLiveCluster(t)
	c.timing.DeadAfter = shortlyDead
	c.genesis(3)
	held := c.leader().node.raft.Load().LastIndex()

	for _, r := range c.replicas {
		r.node.fsm.stopLocal(errStoreFault)
	}
	c.stuckPastEveryWaitToLeave()

	for _, r := range c.replicas {
		if left, gone := r.left(); gone {
			t.Errorf("replica %s left a cluster no majority follows the log of: %v",
				r.node.member, left)
			continue
		}
		if holds := r.node.raft.Load().LastIndex(); holds < held {
			t.Errorf("replica %s holds the log up to index %d, want the %d it held",
				r.node.member, holds, held)
		}
		if overdue := r.node.StuckOverdue(); overdue != "" {
			t.Errorf("replica %s is overdue to leave: %s", r.node.member, overdue)
		}
	}
}

// A replica that stays past this has stayed because it may not leave.
func (c *liveCluster) stuckPastEveryWaitToLeave() {
	c.t.Helper()
	past := c.timing.DeadAfter + c.timing.Lease
	stopped := fmt.Sprintf("every replica stopped for longer than the %s it would leave after", past)
	eventually(c.t, 30*time.Second, stopped, func() bool {
		for _, r := range c.replicas {
			if r.node.fsm.stuckFor() < past {
				return false
			}
		}
		return true
	})
}

// Without a leader that follows the log, and without a majority answering for
// that leader, a voter stays.
func TestAVoterLeavesOnlyOnTheWordOfItsLeader(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	follower := c.follower()

	// The majority is counted over the control connections discovery opens.
	free := "a voter whose leader and fellow voter follow the log to be free to leave"
	eventually(t, 30*time.Second, free, func() bool {
		return follower.node.leaveKeepsQuorum()
	})
	if leader.node.leaveKeepsQuorum() {
		t.Error("a leader leaves before it hands the cluster over")
	}
	for _, other := range slices.Clone(c.replicas) {
		if other != follower {
			c.stop(other)
		}
	}
	eventually(t, 30*time.Second, "the last replica of the cluster to follow no leader", func() bool {
		return !follower.node.following().known()
	})
	if follower.node.leaveKeepsQuorum() {
		t.Error("the last voter of a cluster that holds no majority leaves it")
	}
}

// Run ends a stuck replica from its own loop, and that loop can be the one
// waiting behind the fault (internal/cmds/cds).
func TestAReplicaOverdueToLeaveIsReportedWithoutItsLoop(t *testing.T) {
	timing := testTiming
	timing.DeadAfter = 200 * time.Millisecond
	overdueAfter := timing.Lease + timing.DeadAfter
	node := aMember(t, timing)

	node.fsm.stopLocal(errStoreFault)

	if overdue := node.StuckOverdue(); overdue != "" && node.fsm.stuckFor() < overdueAfter {
		t.Errorf("a replica stopped for %s is overdue to leave: %s", node.fsm.stuckFor(), overdue)
	}
	eventually(t, 30*time.Second, "the replica reported overdue to leave", func() bool {
		return node.StuckOverdue() != ""
	})
}

// A stalled replica stops serving, and follows the log again when the command
// returns.
func TestACommandThatDoesNotReturnStallsTheStateMachine(t *testing.T) {
	node := aMember(t, testTiming)
	// No budget for a command, so the one being applied has outrun it.
	node.cfg.Timing.DeadAfter = 0
	node.cfg.Timing.Apply = 0
	returned := node.fsm.began()

	node.stallLongCommand()

	if node.fsm.Stuck() == "" {
		t.Fatal("a state machine on one command for longer than a write stalls nothing")
	}
	if node.fsm.StuckLocal() {
		t.Error("a stalled command is a fault of this replica's own, which only a restart cures")
	}
	returned()
	node.fsm.endStall()
	if stuck := node.fsm.Stuck(); stuck != "" {
		t.Errorf("the command returned and the replica is stopped: %s", stuck)
	}
}

// The restart that replays the log is what takes such a replica back into its
// cluster.
func TestAStallTheClusterOutlastsBecomesAFaultOfItsOwn(t *testing.T) {
	node := aMember(t, testTiming)
	// No wait for the majority, so the pass that finds it finds it held.
	node.cfg.Timing.DeadAfter = 0
	returned := node.fsm.began()
	defer returned()
	node.fsm.Stall(errors.New("test: one command of the state machine"))

	node.hangLastingStall(&stallWatch{})

	if !node.fsm.StuckLocal() {
		t.Error("a stall the cluster outlasted is no fault of this replica's own")
	}
}

// The pass that first sees the majority takes its own moment as the start, and
// a majority that ends starts the wait again.
func TestTheMajorityWithoutAStalledReplicaHoldsForDeadAfter(t *testing.T) {
	var watch stallWatch
	seen := time.Now()

	if watch.heldFor(seen, shortlyDead) {
		t.Error("the pass that first saw a majority without this replica reports it held")
	}
	if !watch.heldFor(seen.Add(shortlyDead), shortlyDead) {
		t.Error("a majority without this replica that held for DeadAfter reports otherwise")
	}
	watch.ended()
	if watch.heldFor(seen.Add(2*shortlyDead), shortlyDead) {
		t.Error("a majority that ended and began again reports it held")
	}
}
