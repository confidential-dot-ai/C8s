package cdsha

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A cluster serves nothing while a Recover decree may have handed it to a
// member of its own, and while its leader cannot read the board that would
// carry such a decree. The tests below watch both fences, and the member they
// cut out of the cluster.

// newFenceCluster is a cluster whose members count dead soon enough for a
// test to watch the fence that follows one being cut off.
func newFenceCluster(t *testing.T) *liveCluster {
	t.Helper()
	c := newLiveCluster(t)
	c.timing.DeadAfter = shortlyDead
	return c
}

// withholdTheBoardFrom stops the board from answering these replicas, as a
// host that serves some replicas a view of their own does.
func withholdTheBoardFrom(replicas ...*liveReplica) {
	for _, r := range replicas {
		r.board.withholds(true)
	}
}

// besides are the replicas of the cluster other than r.
func (c *liveCluster) besides(r *liveReplica) []*liveReplica {
	var rest []*liveReplica
	for _, held := range c.replicas {
		if held != r {
			rest = append(rest, held)
		}
	}
	return rest
}

// servingBesides are the members of the cluster other than r that answer
// reads.
func (c *liveCluster) servingBesides(r *liveReplica) []string {
	var serving []string
	for _, held := range c.besides(r) {
		if held.node.Serving().OK {
			serving = append(serving, string(held.node.member))
		}
	}
	return serving
}

// leaderBesides is the replica leading a cluster, where that is not r.
func (c *liveCluster) leaderBesides(r *liveReplica) *liveReplica {
	for _, held := range c.besides(r) {
		if held.node.leading() {
			return held
		}
	}
	return nil
}

// cutOffAVoter starts a cluster of three and cuts one voter that does not
// lead off from the rest, long enough for its leader to count it dead.
func cutOffAVoter(t *testing.T) (c *liveCluster, cut *liveReplica) {
	t.Helper()
	c = newFenceCluster(t)
	c.genesis(3)
	cut = c.follower()
	c.partition(cut, true)
	eventually(t, 10*time.Second, "the cluster counting the cut-off voter dead", func() bool {
		leader := c.leaderBesides(cut)
		if leader == nil {
			return false
		}
		term := leader.node.raft.Load().CurrentTerm()
		return slices.Contains(memberIDs(leader.node.membersCutOff(term)), string(cut.node.member))
	})
	return c, cut
}

// writeASecret is one client write at a replica, and what the cluster made of
// it.
func writeASecret(r *liveReplica, path string) error {
	_, _, err := r.node.Secrets().PutIfAbsent(context.Background(), path, []byte("secret"), secrets.WorkloadHolder("web"))
	return err
}

// The figures the cluster runs on: a leader goes blind to the board after
// twice the time a member counts dead in, and the replica a Recover names
// holds off for that lease, a write, a read lease and two turns of its loop.
func TestTheRecoverHoldOutlastsTheFenceOfTheOtherSide(t *testing.T) {
	for name, timing := range map[string]Timing{"a release": releaseTiming, "the tests": testTiming.orRelease()} {
		t.Run(name, func(t *testing.T) {
			lease := timing.boardLease()
			hold := timing.recoverHold()
			// The other side fences itself within the board lease and the
			// write that doubt takes, and the reads it answered run out one
			// read lease later.
			if fenced := lease + timing.Apply + timing.Lease; hold <= fenced {
				t.Errorf("the hold is %s, and the other side serves for %s", hold, fenced)
			}
			if lease <= timing.DeadAfter {
				t.Errorf("a leader goes blind after %s, and counts a member dead after %s", lease, timing.DeadAfter)
			}
		})
	}
	if lease, hold := releaseTiming.boardLease(), releaseTiming.recoverHold(); lease != 40*time.Second || hold != 57*time.Second {
		t.Errorf("a release goes blind after %s and holds a Recover for %s, want 40s and 57s", lease, hold)
	}
}

// No member of a cluster is reached at the address of a member its cluster
// cut out: every address a member answers at names an endpoint, and the
// excluded address names the member alone.
func TestNoMemberIsReachedAtTheExcludedAddress(t *testing.T) {
	address := excludedAddress(testMember)
	if _, err := parseRaftAddr(address); err == nil {
		t.Fatalf("the excluded address %q reaches a member", address)
	}
	if address == excludedAddress("another-member") {
		t.Fatalf("two members cut out share the address %q, and a configuration holds none twice", address)
	}
}

// blindWithEveryMemberAnswering reports a leader whose reading of the board
// has gone stale while every member of its cluster answers it.
func blindWithEveryMemberAnswering(leader *liveReplica) bool {
	node := leader.node
	term := node.raft.Load().CurrentTerm()
	sighted, inThisTerm := node.boardSightedThisTerm()
	if !inThisTerm || time.Since(sighted) < node.cfg.Timing.boardLease() {
		return false
	}
	return len(node.membersCutOff(term)) == 0
}

// A board no replica can read while every member answers fences nothing: a
// Recover decree hands the cluster to a member that is gone, and none of
// these is. One sample of the cluster holds all of it, so a member that falls
// quiet for a moment under load fails no assertion.
func TestABoardNoReplicaCanReadWithEveryMemberAnsweringKeepsTheClusterServing(t *testing.T) {
	c := newFenceCluster(t)
	c.genesis(3)
	withholdTheBoardFrom(c.replicas...)

	eventually(t, 30*time.Second, "a blind leader serving a cluster whose members all answer", func() bool {
		leader := c.leader()
		if leader == nil || !blindWithEveryMemberAnswering(leader) {
			return false
		}
		return leader.node.Fenced() == nil && leader.node.Serving().OK
	})

	eventually(t, 30*time.Second, "a write a cluster whose members all answer takes", func() bool {
		leader := c.leader()
		return leader != nil && writeASecret(leader, "/web/token") == nil
	})
	for _, r := range c.replicas {
		eventually(t, 30*time.Second, "replica "+string(r.node.member)+" answering reads", serves(r.node))
	}
}

// A leader that cannot read the board while a member is cut off serves
// nothing: the decree it cannot see may hand the cluster to that member. It
// cuts that member out, and serves again once it can read the board.
func TestALeaderBlindToTheBoardWithAMemberCutOffFencesTheCluster(t *testing.T) {
	c, cut := cutOffAVoter(t)
	withholdTheBoardFrom(c.besides(cut)...)

	eventually(t, c.timing.boardLease()+30*time.Second, "the leader fenced over the member it cannot reach", func() bool {
		fence := c.fenceOfTheMajority(cut)
		return fence != nil && slices.Contains(fence.CutOff, string(cut.node.member)) && strings.Contains(fence.Reason, "board")
	})

	eventually(t, 30*time.Second, "the fenced cluster taking no write", func() bool {
		return c.refusesEveryWrite(cut, "/web/token")
	})
	for _, r := range c.besides(cut) {
		eventually(t, c.timing.Lease+30*time.Second, "replica "+string(r.node.member)+" serving no read", func() bool {
			return !r.node.Serving().OK
		})
	}
	eventually(t, 30*time.Second, "the cut-off member cut out of the cluster", func() bool {
		leader := c.leaderBesides(cut)
		if leader == nil {
			return false
		}
		server, named := c.serverFor(leader, string(cut.node.member))
		return named && cutOutOfTheGroup(server)
	})

	for _, r := range c.besides(cut) {
		r.board.withholds(false)
	}

	eventually(t, 30*time.Second, "the cluster serving again and taking a write", func() bool {
		leader := c.leaderBesides(cut)
		if leader == nil || leader.node.Fenced() != nil || !leader.node.Serving().OK {
			return false
		}
		return writeASecret(leader, "/web/again") == nil
	})
}

// A Recover decree naming a member that answers this cluster is refused and
// nothing more: that member recovered nothing, so the cluster carries on.
func TestARecoverDecreeNamingAMemberThatAnswersIsRefused(t *testing.T) {
	// Every member must answer throughout, so this cluster counts a member
	// dead by the release's own wait rather than the short one.
	c := newLiveCluster(t)
	c.genesis(3)
	follower := c.follower()

	decree := c.decreeFor(follower, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))

	c.afterBoardCycles(3)
	for _, r := range c.replicas {
		if doubts := r.node.ClusterState().Doubts; len(doubts) != 0 {
			t.Fatalf("replica %s doubts %+v", r.node.member, doubts)
		}
		if serving := r.node.Serving(); !serving.OK {
			t.Fatalf("replica %s serves no read: %s", r.node.member, serving.Reason)
		}
	}
	if follower.node.leading() {
		t.Fatal("the member the decree names carried a cluster of its own on while it had a leader")
	}
}

// A Recover decree is judged every cycle: one of a member that answers is
// refused, and the same decree becomes a doubt once that member stops
// answering, because by then it may be carrying the cluster on alone.
func TestARefusedRecoverIsDoubtedOnceItsMemberStopsAnswering(t *testing.T) {
	c := newFenceCluster(t)
	c.genesis(3)
	leader := c.leader()
	target := c.follower()

	decree := c.decreeFor(target, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))
	c.afterBoardCycles(3)
	if doubts := leader.node.ClusterState().Doubts; len(doubts) != 0 {
		t.Fatalf("the cluster doubts %+v while the member the decree names answers it", doubts)
	}

	c.partition(target, true)

	eventually(t, 20*time.Second, "the cluster doubting the Recover decree", func() bool {
		return slices.ContainsFunc(leader.node.ClusterState().Doubts, raisedBy(decree.IntentID))
	})
}

// A Recover decree naming a member this cluster cannot account for becomes a
// doubt on its log: that member may be carrying the cluster on alone, so no
// replica serves until the operator dismisses the decree. The doubt is the
// cluster's own, so it outlives the leader that saw the decree.
func TestASightedRecoverFencesEveryReplicaUntilItIsDismissed(t *testing.T) {
	c, cut := cutOffAVoter(t)
	majority := c.besides(cut)
	version := majority[0].node.ClusterState().Version

	decree := c.decreeFor(cut, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))

	for _, r := range c.besides(cut) {
		eventually(t, 15*time.Second, "replica "+string(r.node.member)+" doubting the Recover decree", func() bool {
			return slices.ContainsFunc(r.node.ClusterState().Doubts, raisedBy(decree.IntentID))
		})
		eventually(t, c.timing.DeadAfter+5*time.Second, "replica "+string(r.node.member)+" fenced by the doubt", func() bool {
			fence := r.node.Status().Fenced
			return fence != nil && fence.Doubt == decree.IntentID && fence.Member == string(cut.node.member)
		})
		eventually(t, c.timing.Lease+5*time.Second, "replica "+string(r.node.member)+" serving no read", func() bool {
			return !r.node.Serving().OK
		})
	}
	eventually(t, 30*time.Second, "the fenced cluster taking no write", func() bool {
		return c.refusesEveryWrite(cut, "/web/token")
	})
	if applied := majority[0].node.ClusterState().Version; applied != version {
		t.Fatalf("the cluster is at version %d, and a doubt is no operator command", applied)
	}

	dismiss := c.decreeFor(majority[0], cdsdecree.DismissRecover)
	dismiss.RecoverIntent = decree.IntentID
	c.board.holds(c.signDecree(dismiss))

	for _, r := range majority {
		eventually(t, 30*time.Second, "replica "+string(r.node.member)+" serving again", func() bool {
			return slices.Contains(r.node.ClusterState().AppliedDecrees, dismiss.IntentID) && r.node.Fenced() == nil && r.node.Serving().OK
		})
	}
	eventually(t, 30*time.Second, "the cluster whose doubt was dismissed taking a write", func() bool {
		leader := c.leaderBesides(cut)
		return leader != nil && writeASecret(leader, "/web/token") == nil
	})
}

// A Recover decree that expired before this cluster saw it raises the doubt
// like any other: its target judges the expiry on a clock of its own, which
// no replica here can see, so this side gives the member up either way.
func TestAnExpiredRecoverIsDoubtedAndFencesTheCluster(t *testing.T) {
	c, cut := cutOffAVoter(t)
	decree := expiredDecree(c.decreeFor(cut, cdsdecree.Recover))
	c.board.holds(c.signDecree(decree))

	for _, r := range c.besides(cut) {
		eventually(t, 15*time.Second, "replica "+string(r.node.member)+" doubting the expired Recover decree", func() bool {
			return slices.ContainsFunc(r.node.ClusterState().Doubts, raisedBy(decree.IntentID))
		})
	}
	eventually(t, c.timing.Lease+15*time.Second, "the doubting majority serving no read", func() bool {
		return len(c.servingBesides(cut)) == 0
	})
}

// A member its cluster cut out rejoins only as a new member: its log may hold
// the entries of a recovered cluster, which no replica can tell from this
// cluster's. Its process ends its own loop, and the restart that takes its
// place joins with an empty log and fills its seat.
func TestACutOutMemberRejoinsOnlyAsANewMember(t *testing.T) {
	c, cut := cutOffAVoter(t)
	address := cut.peerAddress()
	withholdTheBoardFrom(c.besides(cut)...)
	cut.mayLeave()

	eventually(t, c.timing.boardLease()+30*time.Second, "the cut-off member cut out of the cluster", func() bool {
		leader := c.leaderBesides(cut)
		if leader == nil {
			return false
		}
		server, named := c.serverFor(leader, string(cut.node.member))
		return named && cutOutOfTheGroup(server)
	})
	c.partition(cut, false)

	left := c.leftWithin(cut, 30*time.Second)
	if !errors.Is(left, ErrLeftItsCluster) || !strings.Contains(left.Error(), "cut this member out") {
		t.Fatalf("the cut-out member ended its loop with %v, want it left because it was cut out", left)
	}
	c.stop(cut)
	for _, r := range c.besides(cut) {
		r.board.withholds(false)
	}
	restarted := c.startAt(address)

	eventually(t, 60*time.Second, "the cut-out member retired from the cluster", func() bool {
		leader := c.leader()
		return leader != nil && !slices.Contains(c.voters(leader), raft.ServerID(cut.node.member))
	})
	c.votersSeated(c.launch.Voters)
	eventually(t, 30*time.Second, "the restarted replica serving", serves(restarted.node))
	c.rollSafe()
}

// A non-voter its cluster cut out keeps its place in the group at the excluded
// address: a member the configuration no longer names learns nothing when it
// asks to come back, and returns with the state it applied.
func TestACutOutNonVoterKeepsItsPlaceWhileItsLeaderIsFenced(t *testing.T) {
	c := newFenceCluster(t)
	c.genesis(4)
	nonVoters := c.nonVoters(c.leader())
	if len(nonVoters) != 1 {
		t.Fatalf("the cluster holds the non-voters %v, want the one replica its seats do not hold", nonVoters)
	}
	spare := c.replicaNamed(string(nonVoters[0]))
	// The board goes dark first, so the leader is blind to the Recover
	// decrees it may carry by the time the non-voter stops answering.
	withholdTheBoardFrom(c.besides(spare)...)
	time.Sleep(c.timing.boardLease())
	c.partition(spare, true)
	spare.mayLeave()

	eventually(t, c.timing.boardLease()+30*time.Second, "the cut-off non-voter cut out of the cluster", func() bool {
		leader := c.leaderBesides(spare)
		if leader == nil {
			return false
		}
		server, named := c.serverFor(leader, string(spare.node.member))
		return named && cutOutOfTheGroup(server)
	})

	// A fenced leader lets no member go: the seating pass leaves the one it
	// cut out in the group.
	time.Sleep(3 * c.timing.Tick)
	leader := c.leaderBesides(spare)
	if leader == nil {
		t.Fatal("the cluster that cut its non-voter out leads nothing")
	}
	if server, named := c.serverFor(leader, string(spare.node.member)); !named || !cutOutOfTheGroup(server) {
		t.Fatalf("the group holds the cut-out non-voter as %+v, want it at the excluded address", server)
	}

	c.partition(spare, false)
	left := c.leftWithin(spare, 30*time.Second)
	if !errors.Is(left, ErrLeftItsCluster) || !strings.Contains(left.Error(), "cut this member out") {
		t.Fatalf("the cut-out non-voter ended its loop with %v, want it left because it was cut out", left)
	}
	// A member that answers again is followed to the address it answers at,
	// and one the cluster cut out stays cut out.
	if server, named := c.serverFor(leader, string(spare.node.member)); !named || !cutOutOfTheGroup(server) {
		t.Fatalf("the group holds the member it cut out as %+v once it answered again", server)
	}

	// A leader that reads its board again lets the member go, and its place
	// with it.
	for _, r := range c.besides(spare) {
		r.board.withholds(false)
	}
	eventually(t, 30*time.Second, "the cut-out non-voter taken out of the group", func() bool {
		leader := c.leaderBesides(spare)
		if leader == nil {
			return false
		}
		_, named := c.serverFor(leader, string(spare.node.member))
		return !named
	})
}

// An election while no replica can read the board does not fence a cluster
// whose members all answer: the leader elected has read no board in its term,
// and every member reports it as their leader, so none of them can be acting
// on a Recover decree.
func TestAnElectionWhileTheBoardCannotBeReadKeepsTheClusterServing(t *testing.T) {
	c := newFenceCluster(t)
	c.genesis(3)
	old := c.leader()
	withholdTheBoardFrom(c.replicas...)

	if err := old.node.raft.Load().LeadershipTransfer().Error(); err != nil {
		t.Fatalf("hand the cluster over: %v", err)
	}

	var elected *liveReplica
	eventually(t, 30*time.Second, "another replica of the cluster leading", func() bool {
		elected = c.leader()
		return elected != nil && elected != old
	})
	eventually(t, 15*time.Second, "the elected leader serving with no reading of the board in its term", func() bool {
		_, read := elected.node.boardSightedThisTerm()
		return !read && elected.node.Fenced() == nil && elected.node.Serving().OK
	})
	eventually(t, 30*time.Second, "the elected leader taking a write", func() bool {
		return writeASecret(elected, "/web/token") == nil
	})
}

// A doubted member that comes back ends the doubt itself: asked over the
// attested channel, it gives the Recover decree up for good, the leader puts
// that renunciation on the log, and the cluster serves again with no operator
// step. The host served the decree to the majority alone here, so the member
// it names never acted on it.
func TestADoubtEndsWhenItsMemberRenouncesTheRecover(t *testing.T) {
	c, cut := cutOffAVoter(t)
	withholdTheBoardFrom(cut)
	decree := c.decreeFor(cut, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))
	majority := c.besides(cut)
	for _, r := range majority {
		eventually(t, 15*time.Second, "replica "+string(r.node.member)+" doubting the Recover decree", func() bool {
			return slices.ContainsFunc(r.node.ClusterState().Doubts, raisedBy(decree.IntentID))
		})
	}
	// Its cluster cut the member out, so it ends its own loop once the doubt
	// it renounced is over.
	cut.mayLeave()

	c.partition(cut, false)

	for _, r := range majority {
		eventually(t, 30*time.Second, "replica "+string(r.node.member)+" serving once the doubted member renounced the decree", func() bool {
			return len(r.node.ClusterState().Doubts) == 0 && r.node.Fenced() == nil && r.node.Serving().OK
		})
	}
	if !cut.node.renouncedRecover(decree.IntentID) {
		t.Fatal("the member the decree names did not give it up")
	}
	eventually(t, 30*time.Second, "the cluster whose doubt ended taking a write", func() bool {
		leader := c.leaderBesides(cut)
		return leader != nil && writeASecret(leader, "/web/token") == nil
	})
}

// A member that carried the cluster on under the decree renounces nothing, so
// the doubt of it outlives the partition that raised it: a healed network
// leaves the majority serving nothing beside the life that member started.
func TestAHealedPartitionLeavesTheDoubtOfARecoveredMember(t *testing.T) {
	c, cut := cutOffAVoter(t)
	decree := c.decreeFor(cut, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))
	majority := c.besides(cut)
	for _, r := range majority {
		eventually(t, 15*time.Second, "replica "+string(r.node.member)+" doubting the Recover decree", func() bool {
			return slices.ContainsFunc(r.node.ClusterState().Doubts, raisedBy(decree.IntentID))
		})
	}
	eventually(t, c.timing.recoverHold()+30*time.Second, "the cut-off voter carrying the cluster on alone", func() bool {
		return aloneWithTheCluster(cut)
	})

	c.partition(cut, false)
	c.afterBoardCycles(3)

	// An election is the host's to force, and a leader that has just taken
	// over has no heartbeat of its own to the doubted member: the doubt is
	// what fences it, not what it can reach.
	leading := c.leaderBesides(cut)
	if leading == nil {
		t.Fatal("the majority of the cluster leads nothing")
	}
	if err := leading.node.raft.Load().LeadershipTransfer().Error(); err != nil {
		t.Fatalf("hand the cluster over inside the majority: %v", err)
	}
	eventually(t, 30*time.Second, "another replica of the majority leading", func() bool {
		elected := c.leaderBesides(cut)
		return elected != nil && elected != leading
	})

	for _, r := range majority {
		if doubts := r.node.ClusterState().Doubts; len(doubts) != 1 || doubts[0].Intent != decree.IntentID {
			t.Fatalf("replica %s holds the doubts %+v once the member it doubts answered again", r.node.member, doubts)
		}
		if serving := r.node.Serving(); serving.OK {
			t.Fatalf("replica %s serves beside the cluster the doubted member carried on", r.node.member)
		}
		if fence := r.node.Fenced(); fence == nil || fence.Doubt != decree.IntentID {
			t.Fatalf("replica %s is fenced by %+v, want the doubt of the recovered member", r.node.member, fence)
		}
	}
}
