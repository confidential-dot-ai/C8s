package cdsha

import (
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// Handing the cluster over: the target that may take a transfer now, and the
// leader that no replica can answer a read under.

// Another target has a slot of its own.
func TestATargetTakesOneTransferPerCooldown(t *testing.T) {
	const cooldown = time.Minute
	sent := newTransfers()
	target := raft.ServerID("eqk7")
	another := raft.ServerID("zm4p")
	now := time.Now()

	sent.send(target, now)

	if !sent.holding(target, now.Add(cooldown/2), cooldown) {
		t.Error("a target sent a transfer within the cooldown holds none")
	}
	if sent.holding(another, now.Add(cooldown/2), cooldown) {
		t.Error("a target of its own holds the transfer of another")
	}
	if sent.holding(target, now.Add(2*cooldown), cooldown) {
		t.Error("a target holds a transfer past the cooldown")
	}
}

func TestATransferRaftQueuedNothingForLeavesTheTargetFree(t *testing.T) {
	const cooldown = time.Minute
	sent := newTransfers()
	target := raft.ServerID("eqk7")
	now := time.Now()
	sent.send(target, now)

	sent.forget(target)

	if sent.holding(target, now, cooldown) {
		t.Error("a target Raft queued no transfer for holds one")
	}
}

// It took the term a lease ago and certified no read in it.
func TestALeaderHandsOverOnlyOnceItCertifiesNoRead(t *testing.T) {
	timing := testTiming.orRelease()
	led := leadership{member: "eqk7", term: 3}
	var watch slowLeader
	now := time.Now()
	watch.follow(led, now)

	if watch.certifiesNoRead(time.Time{}, now, timing) {
		t.Error("a leader certifies no read in the term it just took")
	}
	if !watch.certifiesNoRead(time.Time{}, now.Add(timing.Lease), timing) {
		t.Error("a leader that has certified no read for a lease certifies one")
	}
	if watch.certifiesNoRead(now.Add(timing.Lease), now.Add(timing.Lease), timing) {
		t.Error("a leader that just certified a read certifies none")
	}
}

// The term a leader takes itself starts its wait again.
func TestALeaderWaitsBetweenTheTransfersItTries(t *testing.T) {
	timing := testTiming.orRelease()
	led := leadership{member: "eqk7", term: 3}
	var watch slowLeader
	now := time.Now()
	watch.follow(led, now)
	watch.tried(now)

	if watch.certifiesNoRead(time.Time{}, now.Add(timing.Lease), timing) {
		t.Error("a leader tried a second transfer within DeadAfter of the first")
	}
	if !watch.certifiesNoRead(time.Time{}, now.Add(timing.DeadAfter+timing.Lease), timing) {
		t.Error("a leader that tried a transfer DeadAfter ago tries no other")
	}
	theNextTerm := leadership{member: "eqk7", term: led.term + 1}
	watch.follow(theNextTerm, now.Add(timing.DeadAfter+timing.Lease))

	if watch.certifiesNoRead(time.Time{}, now.Add(timing.DeadAfter+timing.Lease), timing) {
		t.Error("a leader certifies no read in the term it just took")
	}
}

// And to none where no voter answers.
func TestALeaderHandsTheClusterToACaughtUpVoter(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()

	// A voter learns the leader's commit index with the next entry sent to
	// it, so one check can just miss it.
	var target raft.Server
	eventually(t, 10*time.Second, "a voter of this cluster to hand the log to", func() bool {
		caught, found := leader.node.aVoterThatApplied(leader.node.fsm.AppliedIndex())
		target = caught
		return found
	})

	if !slices.Contains(c.voters(leader), target.ID) || string(target.ID) == string(leader.node.member) {
		t.Errorf("the target is member %s, want a voter besides the leader %s",
			target.ID, leader.node.member)
	}
	for _, other := range slices.Clone(c.replicas) {
		if other != leader {
			c.stop(other)
		}
	}
	if target, found := leader.node.aVoterThatApplied(leader.node.fsm.AppliedIndex()); found {
		t.Errorf("a leader whose voters are gone hands the log to member %s", target.ID)
	}
}
