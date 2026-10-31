package cdsha

import (
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// neverCuts is a relay that holds its connections, as a route does.
const neverCuts = 0

// The leader takes a replica in at the address it reached that replica at
// itself. A replica it has not reached is left out: its address would be one
// only the joiner vouches for, and a member no one can reach holds no copy of
// the cluster's log.
func TestAReplicaTheLeaderHasNotReachedDoesNotJoin(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	joiner := c.start()
	leader.resolve.holds(leader.peerAddress())

	time.Sleep(20 * testTiming.Tick)
	if leader.node.memberOfCluster(string(joiner.node.member)) {
		t.Fatal("the leader took in a replica it has not reached")
	}

	c.resolveEachOther()
	c.joined(2)
}

// A member that answers at another address is the same member: the leader
// gives Raft the address it answers at now, and the cluster keeps replicating
// to it. This cluster holds one voter seat, so the joiner stays the non-voter
// whose address the leader follows.
func TestTheLeaderFollowsAMemberThatMovesAddress(t *testing.T) {
	c := newLiveCluster(t)
	c.launch.Voters = 1
	c.genesis(1)
	leader := c.leader()
	joiner := c.start()
	// The cluster reaches the joiner through the host's routing, which is
	// where it moves.
	was := newRelay(t, neverCuts, joiner.peerAddress())
	leader.resolve.holds(leader.peerAddress(), was.address())
	c.reaches(leader, joiner, was.address())
	if server, _ := c.serverFor(leader, string(joiner.node.member)); server.Suffrage != raft.Nonvoter {
		t.Fatalf("the joiner is a %v, and the leader follows the address of a non-voter", server.Suffrage)
	}

	moved := newRelay(t, neverCuts, joiner.peerAddress())
	leader.resolve.holds(leader.peerAddress(), moved.address())
	was.close()

	c.reaches(leader, joiner, moved.address())
	if _, err := leader.node.Secrets().Put(t.Context(), "/after-the-move", []byte("v")); err != nil {
		t.Fatalf("a write with the member at its new address: %v", err)
	}
	c.caughtUp(joiner, leader, 15*time.Second)
}
