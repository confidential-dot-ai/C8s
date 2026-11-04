package cdsha

import (
	"strings"
	"testing"
	"time"
)

// What a replica answers about itself: the readiness probe of a replica and
// the gate between two steps of a roll read the same answers.

// An operator reading the answer needs no log.
func TestAReplicaSaysWhyItAnswersNoRead(t *testing.T) {
	c := newLiveCluster(t)
	unjoined := c.start().node.Serving()
	if unjoined.OK || !strings.Contains(unjoined.Reason, "holds no cluster") {
		t.Fatalf("a replica outside a cluster reports %+v", unjoined)
	}

	c.genesis(3)
	cut := c.follower()
	c.partition(cut, true)

	eventually(t, 10*time.Second, "the cut replica to say why it answers no read", func() bool {
		return !cut.node.Serving().OK
	})
	if serving := cut.node.Serving(); serving.Reason == "" {
		t.Fatalf("the cut replica reports %+v, want why it answers no read", serving)
	}
}

// A replica that flaps is one an operator can tell from one that settled.
func TestHowLongAReplicaHasBeenAnsweringReadsIsReported(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	eventually(t, 10*time.Second, "the leader answers reads", serves(leader.node))

	first := leader.node.Serving()
	time.Sleep(20 * testTiming.Tick)
	later := leader.node.Serving()

	if !later.OK || later.SinceMS < first.SinceMS {
		t.Fatalf("the leader reported %+v and then %+v, want the time it has been answering reads",
			first, later)
	}
}

// A voter keeps its vote for DeadAfter, and a roll that waited for that would
// take a second replica away while the first is already gone.
func TestAVoterSeatThatStopsAnsweringEndsTheRollGate(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	c.rollSafe()

	c.partition(c.follower(), true)

	eventually(t, 5*time.Second, "the cluster to report no replica of it replaceable", func() bool {
		safe, leading := leader.node.RollSafe()
		return leading && !safe.OK && strings.Contains(safe.Reason, "answered")
	})
	if dead := leader.node.fsm.ClusterState(); dead.Voters != 3 {
		t.Fatalf("the cluster holds %d voter seats, want the three it still seats", dead.Voters)
	}
}

// The roll gate names the seats it waits for.
func TestAClusterWithAFreeSeatIsNoClusterToRollReplicasOf(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)

	safe, leading := c.replicas[0].node.RollSafe()

	if !leading || safe.OK || !strings.Contains(safe.Reason, "voter seats") {
		t.Fatalf("a cluster of one replica with %d seats reports %+v", c.launch.Voters, safe)
	}
}
