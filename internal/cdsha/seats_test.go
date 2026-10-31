package cdsha

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// The seats of a cluster are filled by its own leader: the tests below watch
// it seat the members that caught up, replace a dead voter, and follow the
// seat count the operator decrees.

// The DeadAfter the tests below run with: one a test waits out, and one a
// replica the test starts joins well inside.
const (
	shortlyDead             = 2 * time.Second
	afterAReplacementJoined = 10 * time.Second
)

func newSeatCluster(t *testing.T, deadAfter time.Duration) *liveCluster {
	t.Helper()
	c := newLiveCluster(t)
	c.timing.DeadAfter = deadAfter
	return c
}

func TestTheSeatsHoldAsManyVotersAsTheConfigurationNames(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(5)
	leader := c.leader()

	if voters := c.voters(leader); len(voters) != c.launch.Voters {
		t.Fatalf("the cluster holds %d voters, want the %d its configuration names",
			len(voters), c.launch.Voters)
	}
	if nonVoters := c.nonVoters(leader); len(nonVoters) != len(c.replicas)-c.launch.Voters {
		t.Fatalf("the cluster holds %d non-voters, want the %d replicas the seats do not hold",
			len(nonVoters), len(c.replicas)-c.launch.Voters)
	}
	for _, r := range c.replicas {
		eventually(t, 10*time.Second, "every replica of the cluster answers reads", serves(r.node))
	}
	c.rollSafe()
}

func (c *liveCluster) rollSafe() {
	c.t.Helper()
	eventually(c.t, 10*time.Second, "the cluster to report one replica of it replaceable", func() bool {
		leader := c.leader()
		if leader == nil {
			return false
		}
		safe, leading := leader.node.RollSafe()
		return leading && safe.OK
	})
}

// The log lives in the replicas' memory, so a majority that does not carry it
// is a lost cluster.
func TestADeadVoterKeepsItsVoteUntilAReplacementIsSeated(t *testing.T) {
	c := newSeatCluster(t, shortlyDead)
	c.genesis(5)
	leader := c.leader()
	dying := c.aVoterBesides(leader)
	spares := c.nonVoters(leader)

	c.stop(dying)

	eventually(t, 30*time.Second, "a spare replica seated for the dead voter", func() bool {
		return slices.ContainsFunc(c.voters(c.leader()), func(voter raft.ServerID) bool {
			return slices.Contains(spares, voter)
		})
	})
	c.votersSeated(c.launch.Voters)
	if voters := c.voters(c.leader()); slices.Contains(voters, raft.ServerID(dying.node.member)) {
		t.Fatalf("the cluster holds voters %v, want the dead voter %s retired",
			voters, dying.node.member)
	}
}

// A process the host restarts comes back at the address of the process it
// replaces.
func TestTheReplicaAtADeadVotersAddressTakesItsSeat(t *testing.T) {
	c := newSeatCluster(t, afterAReplacementJoined)
	c.genesis(4)
	leader := c.leader()
	dying := c.aVoterBesides(leader)
	address := dying.peerAddress()

	c.stop(dying)
	restarted := c.startAt(address)
	c.followsWithoutAVote(restarted)

	eventually(t, 30*time.Second, "the replica at the dead voter's address seated", func() bool {
		return slices.Contains(c.voters(c.leader()), raft.ServerID(restarted.node.member))
	})
	c.votersSeated(c.launch.Voters)
}

func (c *liveCluster) followsWithoutAVote(r *liveReplica) {
	c.t.Helper()
	reached := fmt.Sprintf("member %s following the log without a vote", r.node.member)
	eventually(c.t, 30*time.Second, reached, func() bool {
		leader := c.leader()
		return leader != nil && slices.Contains(c.nonVoters(leader), raft.ServerID(r.node.member))
	})
}

// A replica the host cuts off for a moment is no replica's to replace.
func TestALiveVoterIsNotReplacedBeforeItCountsDead(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(4)
	leader := c.leader()
	cut := c.aVoterBesides(leader)
	seated := c.voters(leader)

	c.partition(cut, true)
	time.Sleep(20 * testTiming.Tick)

	if voters := c.voters(c.leader()); !slices.Equal(voters, seated) {
		t.Fatalf("the cluster holds voters %v, want the %v it seated while the cut voter answers again within DeadAfter",
			voters, seated)
	}
	c.partition(cut, false)
	eventually(t, 15*time.Second, "the voter that returned answering reads", serves(cut.node))
}

// A SetVoters decree lowering the count leaves a surplus voter behind.
func TestASurplusVoterGivesUpItsVote(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)

	c.decreeVoters(1)

	c.votersSeated(1)
	if nonVoters := c.nonVoters(c.leader()); len(nonVoters) != 2 {
		t.Fatalf("the cluster holds %d non-voters, want the two the seats no longer hold",
			len(nonVoters))
	}
	for _, r := range c.replicas {
		eventually(t, 10*time.Second, "every replica of the cluster answers reads", serves(r.node))
	}
}

func (c *liveCluster) decreeVoters(seats int) {
	c.t.Helper()
	leader := c.leader()
	decree := c.fixture(leader).decree(cdsdecree.SetVoters)
	decree.Voters = seats
	if delivered := c.posted(leader, c.signDecree(decree)); delivered.Refused != "" {
		c.t.Fatalf("the cluster refused the SetVoters decree: %s", delivered.Refused)
	}
	held := fmt.Sprintf("the cluster to hold %d voter seats", seats)
	eventually(c.t, 20*time.Second, held, func() bool {
		leader := c.leader()
		return leader != nil && leader.node.seats() == seats
	})
}

func (c *liveCluster) aVoterBesides(r *liveReplica) *liveReplica {
	c.t.Helper()
	voters := c.voters(r)
	for _, other := range c.replicas {
		if other != r && slices.Contains(voters, raft.ServerID(other.node.member)) {
			return other
		}
	}
	c.t.Fatalf("the cluster holds no voter besides member %s", r.node.member)
	return nil
}

// The host decides which replicas answer, and each one holds a copy of the
// state. The leader alone holds the bound, and a cluster of one voter commits
// every seat change it makes without another voter to contact.
func TestAClusterTakesNoMoreNonVotersThanItServesReadsFrom(t *testing.T) {
	c := newLiveCluster(t)
	c.launch.Voters = 1
	c.genesis(1)
	leader := c.leader()
	for i := range maxNonVoters {
		member := fmt.Sprintf("follower-%02d", i)
		address := raftAddr{
			endpoint: leader.peerAddress(),
			member:   member,
		}.serverAddress()
		added := leader.node.raft.AddNonvoter(raft.ServerID(member), address, 0, testTiming.Apply)
		if err := added.Error(); err != nil {
			t.Fatalf("add non-voter %s: %v", member, err)
		}
	}

	answer := leader.node.answerJoin(
		peer{member: testMember},
		leader.node.fsm.LocalPolicy(),
		controlAnswer{},
	)

	if !strings.Contains(answer.Err, "non-voters") {
		t.Fatalf("a cluster holding %d non-voters answered a joiner %q", maxNonVoters, answer.Err)
	}
}

// The cluster writes an encoding only the replicas it holds can read.
func TestTheAgreedFormatRisesOnceEverySeatReadsIt(t *testing.T) {
	c := newLiveCluster(t)
	c.reads = Format + 1
	c.genesis(3)

	agreed := "the cluster to agree on the format every seat reads"
	eventually(t, 15*time.Second, agreed, func() bool {
		return c.leader() != nil && c.leader().node.fsm.ClusterState().format() == Format+1
	})
	for _, r := range c.replicas {
		held := "every replica to hold the format the cluster agreed"
		eventually(t, 10*time.Second, held, func() bool {
			return r.node.fsm.ClusterState().format() == Format+1
		})
	}
}

// An old replica in a seat keeps the group writing the encoding it can read.
func TestTheAgreedFormatStaysWhileASeatReadsNoNewerOne(t *testing.T) {
	c := newLiveCluster(t)
	c.reads = Format + 1
	c.start()
	c.reads = Format
	c.genesis(3)

	time.Sleep(20 * testTiming.Tick)

	if held := c.leader().node.fsm.ClusterState().format(); held != Format {
		t.Fatalf("the cluster agreed on format %d while a seat of it reads up to %d", held, Format)
	}
}
