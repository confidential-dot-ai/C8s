package cdsha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// A decree an operator left on the cluster's board reaches it without being
// posted to any replica: the leader reads the board for itself and applies
// what it finds there through the log.
func TestTheLeaderAppliesADecreeOfItsBoard(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	version := leader.node.fsm.ClusterState().Version
	decree := c.pinDecree(leader, version, testCDSDigest, rolledCDSDigest)

	c.board.holds(c.signDecree(decree))

	c.applied(decree.IntentID, 15*time.Second)
	if core := leader.node.fsm.ClusterState(); core.PinsDecree.Decree.IntentID != decree.IntentID {
		t.Fatalf("the cluster pins decree %s", core.PinsDecree.Decree.IntentID)
	}
}

// The board is the host's to serve, so an object on it that no operator key
// of this cluster signed is no decree of it and never reaches the log.
func TestAnObjectOnTheBoardNoOperatorKeySignedIsNoDecree(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	version := leader.node.fsm.ClusterState().Version
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	decree := c.pinDecree(leader, version, testCDSDigest, rolledCDSDigest)
	signed, err := cdsdecree.Sign(decree, stranger)
	if err != nil {
		t.Fatal(err)
	}

	c.board.holds(signed)

	time.Sleep(20 * testTiming.Tick)
	core := leader.node.fsm.ClusterState()
	if core.Version != version || slices.Contains(core.AppliedDecrees, decree.IntentID) {
		t.Fatalf("the cluster is at version %d and accounted for %v", core.Version, core.AppliedDecrees)
	}
}
