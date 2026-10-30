package cdsha

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// A cluster whose majority is gone for good carries on in the one voter the
// operator decrees, with the state that voter holds. The tests below watch it
// hold off while its cluster answers, and refuse to act where it holds no
// vote.

// aloneWithTheCluster reports a replica leading a cluster of itself alone.
func aloneWithTheCluster(r *liveReplica) bool {
	status := r.node.Status()
	return status.State == raft.Leader.String() && slices.Equal(status.Voters, []string{string(r.node.member)}) && len(status.NonVoters) == 0
}

// lostTheMajority starts a cluster of count replicas, writes one secret into
// it, and stops every replica but one voter, which is then left with no
// leader to follow.
func lostTheMajority(t *testing.T, count int) (c *liveCluster, survivor *liveReplica) {
	t.Helper()
	c = newFenceCluster(t)
	c.genesis(count)
	leader := c.leader()
	if err := writeASecret(leader, "/web/token"); err != nil {
		t.Fatalf("a write before the majority was lost: %v", err)
	}
	survivor = c.follower()
	c.caughtUp(survivor, leader, 10*time.Second)
	for _, lost := range c.besides(survivor) {
		c.stop(lost)
	}
	eventually(t, 10*time.Second, "the surviving voter left without a leader", func() bool {
		return !survivor.node.following().known()
	})
	return c, survivor
}

// The voter the operator decrees carries the cluster on alone with the state
// it holds: it leads a group of itself, serves reads again, keeps what the
// cluster wrote, and records the decree, so no replay of it starts a second
// cluster.
func TestTheDecreedVoterCarriesTheClusterOnAlone(t *testing.T) {
	c, survivor := lostTheMajority(t, 3)
	version := survivor.node.ClusterState().Version

	decree := c.decreeFor(survivor, cdsdecree.Recover)
	decreed := time.Now()
	c.board.holds(c.signDecree(decree))

	eventually(t, c.timing.recoverHold()+30*time.Second, "the decreed voter carrying the cluster on alone", func() bool {
		return aloneWithTheCluster(survivor)
	})

	if held := time.Since(decreed); held < c.timing.recoverHold() {
		t.Fatalf("the decreed voter carried the cluster on %s after the decree, and the hold is %s", held, c.timing.recoverHold())
	}

	eventually(t, 15*time.Second, "the recovered cluster serving reads", serves(survivor.node))
	eventually(t, 15*time.Second, "the recovered cluster recording the Recover decree", func() bool {
		return slices.Contains(survivor.node.ClusterState().AppliedDecrees, decree.IntentID)
	})
	if value, err := survivor.node.Secrets().Get(context.Background(), "/web/token"); err != nil || string(value) != "secret" {
		t.Fatalf("the recovered cluster holds %q: %v", value, err)
	}
	if err := writeASecret(survivor, "/web/another"); err != nil {
		t.Fatalf("the recovered cluster took no write: %v", err)
	}
	if applied := survivor.node.ClusterState().Version; applied <= version {
		t.Fatalf("the recovered cluster is at version %d, and the Recover applied on %d", applied, version)
	}
	if applied := survivor.node.Decrees(); applied[len(applied)-1].Decree.Decree.IntentID != decree.IntentID {
		t.Fatalf("the decree record of the recovered cluster ends with %+v", applied[len(applied)-1].Decree.Decree)
	}
}

// A Recover decree is acted on by the member it names and no other, and a
// replay of one the cluster recorded starts no second cluster.
func TestOnlyTheMemberARecoverNamesActsOnIt(t *testing.T) {
	c, survivor := lostTheMajority(t, 3)
	elsewhere := c.decreeFor(survivor, cdsdecree.Recover)
	elsewhere.TargetMember = "another-member-of-another-replica"
	c.board.holds(c.signDecree(elsewhere))

	time.Sleep(c.timing.recoverHold() + 2*time.Second)

	if aloneWithTheCluster(survivor) {
		t.Fatal("a replica carried the cluster on alone for a decree naming another member")
	}
	if doubts := survivor.node.ClusterState().Doubts; len(doubts) != 0 {
		t.Fatalf("a replica that leads nothing doubted the decree: %+v", doubts)
	}
}

// Only a voter carries the cluster on: a non-voter's log need not hold every
// entry the cluster committed, so the state it holds is no cluster's.
func TestOnlyAVoterCarriesTheClusterOnAlone(t *testing.T) {
	c := newFenceCluster(t)
	c.genesis(4)
	leader := c.leader()
	nonVoters := c.nonVoters(leader)
	if len(nonVoters) != 1 {
		t.Fatalf("the cluster holds the non-voters %v, want the one replica its seats do not hold", nonVoters)
	}
	spare := c.replicaNamed(string(nonVoters[0]))
	for _, voter := range c.besides(spare) {
		c.stop(voter)
	}
	eventually(t, 10*time.Second, "the surviving non-voter left without a leader", func() bool {
		return !spare.node.following().known()
	})

	decree := c.decreeFor(spare, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))

	time.Sleep(c.timing.recoverHold() + 2*time.Second)
	if spare.node.leading() {
		t.Fatalf("a non-voter carried the cluster on alone: %+v", spare.node.Status())
	}
	if spare.node.awaitsRecovery() {
		t.Fatal("a non-voter awaits a Recover decree")
	}
}

// A member of the cluster that answers with a leader stops the recovery: a
// majority is carrying the cluster, and a second one must not start beside
// it. A member that answers with no leader is no sign of a majority.
func TestARecoverStopsWhileAMemberAnswersWithALeader(t *testing.T) {
	c := newFenceCluster(t)
	c.genesis(3)
	follower := c.follower()

	if !follower.node.aMemberAnswersWithALeader() {
		t.Fatal("a replica of a cluster with a leader found no member answering with one")
	}
	if follower.node.awaitsRecovery() {
		t.Fatal("a replica that follows a leader awaits a Recover decree")
	}

	for _, lost := range c.besides(follower) {
		c.stop(lost)
	}

	eventually(t, 10*time.Second, "the surviving voter finding no member with a leader", func() bool {
		return !follower.node.aMemberAnswersWithALeader() && follower.node.awaitsRecovery()
	})
}

// A cluster that carried on alone takes a replica back in as a new member,
// and hands it the state it holds.
func TestAReplicaJoinsTheClusterThatCarriedOnAlone(t *testing.T) {
	c, survivor := lostTheMajority(t, 3)
	decree := c.decreeFor(survivor, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))
	eventually(t, c.timing.recoverHold()+15*time.Second, "the decreed voter carrying the cluster on alone", func() bool {
		return aloneWithTheCluster(survivor)
	})

	joiner := c.start()

	c.followsWithoutAVote(joiner)
	eventually(t, 20*time.Second, "the replica that joined serving reads", serves(joiner.node))
	if value, err := joiner.node.Secrets().Get(context.Background(), "/web/token"); err != nil || string(value) != "secret" {
		t.Fatalf("the replica that joined the recovered cluster holds %q: %v", value, err)
	}
}

// splitWatch samples whether a replica that carried the cluster on alone and
// a replica of the majority it left behind ever serve at the same time.
type splitWatch struct {
	mu sync.Mutex
	// bothServed is every sample where the two sides served at once.
	bothServed []string
	stop       chan struct{}
	done       chan struct{}
}

// watchForASplit samples the cluster every turn of its replicas' loops until
// the test is over.
func watchForASplit(t *testing.T, c *liveCluster, recovering *liveReplica) *splitWatch {
	t.Helper()
	w := &splitWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stop:
				return
			case <-time.After(c.timing.Tick / 2):
			}
			w.sample(c, recovering)
		}
	}()
	t.Cleanup(func() {
		close(w.stop)
		<-w.done
	})
	return w
}

func (w *splitWatch) sample(c *liveCluster, recovering *liveReplica) {
	alone := aloneWithTheCluster(recovering)
	serving := recovering.node.Serving().OK
	majority := c.servingBesides(recovering)
	if !alone || !serving || len(majority) == 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bothServed = append(w.bothServed, fmt.Sprintf("%s: %s serves alone while %v serve", time.Now().Format("15:04:05.000"), recovering.node.member, majority))
}

// servedAtOnce fails the test if the two sides ever served at the same time.
func (w *splitWatch) servedAtOnce(t *testing.T) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.bothServed) > 0 {
		t.Fatalf("two clusters served at once in %d samples, the first: %s", len(w.bothServed), w.bothServed[0])
	}
}

// A host withholding the board from the majority while it cuts the member a
// Recover decree names off from it is the closest it comes to two clusters:
// the majority sees no decree, and the member it cannot reach acts on one.
// The majority fences itself while it is blind, which is well before the hold
// passes, so the two never serve at once; it refuses to merge with the
// recovered cluster when the network comes back.
func TestAMajorityThatCannotSeeTheBoardFencesBeforeTheDecreedVoterRecovers(t *testing.T) {
	c, cut := cutOffAVoter(t)
	withholdTheBoardFrom(c.besides(cut)...)
	watch := watchForASplit(t, c, cut)

	decree := c.decreeFor(cut, cdsdecree.Recover)
	c.board.holds(c.signDecree(decree))

	eventually(t, c.timing.recoverHold()+30*time.Second, "the cut-off voter carrying the cluster on alone", func() bool {
		return aloneWithTheCluster(cut)
	})
	// Whichever replica of the majority leads is fenced, and the reads it
	// answered under its last lease have run out.
	eventually(t, c.timing.Lease+30*time.Second, "the fenced majority serving no read", func() bool {
		return c.fenceOfTheMajority(cut) != nil && len(c.servingBesides(cut)) == 0
	})
	watch.servedAtOnce(t)
	eventually(t, 30*time.Second, "the fenced majority taking no write", func() bool {
		return c.refusesEveryWrite(cut, "/web/majority")
	})
	eventually(t, 30*time.Second, "the recovered cluster taking a write", func() bool {
		return writeASecret(cut, "/web/recovered") == nil
	})

	// The board answers the majority again: it doubts the decree it now sees
	// and stays fenced on the doubt.
	for _, r := range c.besides(cut) {
		r.board.withholds(false)
	}
	eventually(t, 30*time.Second, "the majority doubting the decree it now sees", func() bool {
		fence := c.fenceOfTheMajority(cut)
		return fence != nil && fence.Doubt == decree.IntentID
	})

	// The network comes back: the two histories are not merged, the
	// recovered cluster keeps what it wrote, and the majority serves nothing.
	c.partition(cut, false)
	eventually(t, 30*time.Second, "the recovered replica reaching the old majority again", func() bool {
		return c.answeredRecently(cut, c.besides(cut))
	})
	watch.servedAtOnce(t)
	if !aloneWithTheCluster(cut) {
		t.Fatalf("the recovered cluster was merged back into the old one: %+v", cut.node.Status())
	}
	if value, err := cut.node.Secrets().Get(context.Background(), "/web/recovered"); err != nil || string(value) != "secret" {
		t.Fatalf("the recovered cluster holds %q of its own write: %v", value, err)
	}
	if fence := c.fenceOfTheMajority(cut); fence == nil {
		t.Fatal("the old majority serves again beside the recovered cluster")
	}
}

// fenceOfTheMajority is the fence the replica leading the cluster besides r
// is under, and nil while none of them leads or the one that does serves. The
// replica that leads changes under load, so no test holds on to one.
func (c *liveCluster) fenceOfTheMajority(r *liveReplica) *Fence {
	leader := c.leaderBesides(r)
	if leader == nil {
		return nil
	}
	return leader.node.Fenced()
}

// refusesEveryWrite reports every replica of the cluster besides r refusing a
// write because the cluster is fenced: the replica that took it is fenced
// itself, or the leader it forwarded to is.
func (c *liveCluster) refusesEveryWrite(r *liveReplica, path string) bool {
	for _, held := range c.besides(r) {
		err := writeASecret(held, path)
		if err == nil || !strings.Contains(err.Error(), ErrFenced.Error()) {
			return false
		}
	}
	return true
}

// answeredRecently reports r having heard one of these replicas answer within
// the time an answer counts as live.
func (c *liveCluster) answeredRecently(r *liveReplica, others []*liveReplica) bool {
	for _, held := range others {
		answered := r.node.peers.lastAnswer(string(held.node.member))
		if !answered.IsZero() && time.Since(answered) < c.timing.DeadAfter {
			return true
		}
	}
	return false
}
