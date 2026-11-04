package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// The leader applies the decrees an operator posts to any replica of the
// cluster, and judges a pin set against the images its voters are attested to
// run.

// pinDecree is the pin decree the operator signs against version.
func (c *liveCluster) pinDecree(r *liveReplica, version uint64, digests ...byte) cdsdecree.Decree {
	c.t.Helper()
	decree := c.fixture(r).decree(cdsdecree.UpdateMeasurements)
	decree.BaseVersion = version
	decree.CDSPins = testPins(c.t, digests...)
	return decree
}

// decreePins posts a pin decree to r against the version r holds.
func (c *liveCluster) decreePins(r *liveReplica, digests ...byte) (cdsdecree.Decree, Delivered) {
	c.t.Helper()
	decree := c.pinDecree(r, r.node.fsm.ClusterState().Version, digests...)
	return decree, c.posted(r, c.signDecree(decree))
}

// applied waits until every replica has accounted for the decree.
func (c *liveCluster) applied(intent string, within time.Duration) {
	c.t.Helper()
	eventually(c.t, within, "decree "+intent+" applied at every replica", func() bool {
		return !slices.ContainsFunc(c.replicas, func(r *liveReplica) bool {
			return !slices.Contains(r.node.fsm.ClusterState().AppliedDecrees, intent)
		})
	})
}

// A pin decree posted to the leader is applied through the log, the operator
// is answered with the version it produced, and every replica then pins the
// images it names.
func TestTheLeaderAppliesAPinDecreePostedToIt(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	version := leader.node.fsm.ClusterState().Version

	decree, delivered := c.decreePins(leader, testCDSDigest, rolledCDSDigest)

	if delivered.Version != version+1 || delivered.Refused != "" {
		t.Fatalf("the cluster answered %+v, want the decree applied at version %d", delivered, version+1)
	}
	c.applied(decree.IntentID, 15*time.Second)
	for _, r := range c.replicas {
		core := r.node.fsm.ClusterState()
		if core.PinsDecree == nil || core.PinsDecree.Decree.IntentID != decree.IntentID {
			t.Fatalf("replica %s pins the decree %+v", r.node.member, core.PinsDecree)
		}
		if core.Version != version+1 {
			t.Fatalf("replica %s is at version %d, and the decree applied on %d", r.node.member, core.Version, version)
		}
	}
}

// A decree posted to a replica that does not lead is applied by the leader,
// which answers the replica that took it, so an operator may post to any
// replica of the cluster.
func TestADecreePostedToAFollowerIsAppliedByTheLeader(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	follower := c.follower()
	version := follower.node.fsm.ClusterState().Version

	decree, delivered := c.decreePins(follower, testCDSDigest, rolledCDSDigest)

	if delivered.Version != version+1 || delivered.Refused != "" {
		t.Fatalf("the cluster answered %+v, want the decree applied at version %d", delivered, version+1)
	}
	c.applied(decree.IntentID, 15*time.Second)
}

// A pin set a majority of the voters are not attested to run is refused
// before it reaches the log: peers admit each other by that set, so it would
// leave the cluster without a leader, and with no leader no later decree
// could take it back. The operator reads the reason.
func TestAPinSetThatUnpinsAVoterMajorityIsRefused(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	pinned := leader.node.fsm.ClusterState().PinsDecree.Decree.IntentID

	decree, delivered := c.decreePins(leader, rolledCDSDigest)

	if !strings.Contains(delivered.Refused, "voters") {
		t.Fatalf("the cluster answered %+v, want the pin set refused", delivered)
	}
	core := leader.node.fsm.ClusterState()
	if core.PinsDecree.Decree.IntentID != pinned {
		t.Fatalf("the cluster pins decree %s", core.PinsDecree.Decree.IntentID)
	}
	if slices.Contains(core.AppliedDecrees, decree.IntentID) {
		t.Fatal("the refused decree is on the log")
	}
}

// The one voter of a cluster that has just started counts its own image: a
// leader that judged only its peers would refuse every pin decree while it is
// the cluster's only voter.
func TestTheOnlyVoterCountsItsOwnImage(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)

	decree, _ := c.decreePins(c.leader(), testCDSDigest, rolledCDSDigest)

	c.applied(decree.IntentID, 15*time.Second)
}

// A RotateKey decree forks the mesh: the leader mints a key, and every
// replica of the cluster serves the certificate the log carries.
func TestRotateKeyGivesTheClusterAMeshCAOfItsOwn(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	before := leader.node.fsm.ClusterState().MeshCACert

	decree := c.fixture(leader).decree(cdsdecree.RotateKey)
	c.posted(leader, c.signDecree(decree))

	c.applied(decree.IntentID, 15*time.Second)
	for _, r := range c.replicas {
		core := r.node.fsm.ClusterState()
		ca := r.node.fsm.CA()
		switch {
		case bytes.Equal(core.MeshCACert, before):
			t.Fatalf("replica %s serves the mesh CA the cluster started with", r.node.member)
		case !bytes.Equal(core.MeshCACert, leader.node.fsm.ClusterState().MeshCACert):
			t.Fatalf("replica %s serves another mesh CA than the leader", r.node.member)
		case ca == nil || !bytes.Equal(ca.Cert.Raw, core.MeshCACert):
			t.Fatalf("replica %s signs leaves under another CA than it holds", r.node.member)
		}
	}
}

// Each decree names the version it applies on, which the decree before it
// produced, so one posted out of that order is refused and applies once the
// operator posts it again.
func TestADecreeAppliesOnTheVersionItNames(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	version := leader.node.fsm.ClusterState().Version
	first := c.pinDecree(leader, version, testCDSDigest, rolledCDSDigest)
	second := c.pinDecree(leader, version+1, testCDSDigest)

	if refused := c.posted(leader, c.signDecree(second)); refused.Refused == "" {
		t.Fatalf("a decree applying above the cluster's version answered %+v", refused)
	}
	c.posted(leader, c.signDecree(first))
	c.posted(leader, c.signDecree(second))

	c.applied(second.IntentID, 15*time.Second)
	core := leader.node.fsm.ClusterState()
	if !slices.Contains(core.AppliedDecrees, first.IntentID) {
		t.Fatal("the second decree applied without the first")
	}
	if core.PinsDecree.Decree.IntentID != second.IntentID {
		t.Fatalf("the cluster pins decree %s", core.PinsDecree.Decree.IntentID)
	}
}

// A decree no operator key of this cluster signed is no decree of it: the
// replica it is posted to does not take it, and nothing reaches the log.
func TestADecreeNoOperatorKeySignedIsNotTaken(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	version := leader.node.fsm.ClusterState().Version
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(c.pinDecree(leader, version, testCDSDigest, rolledCDSDigest), stranger)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := leader.node.TakeDecree(signed); err == nil {
		t.Fatal("a replica took a decree the cluster's operator did not sign")
	}

	if core := leader.node.fsm.ClusterState(); core.Version != version {
		t.Fatalf("the cluster moved to version %d", core.Version)
	}
}

// A decree past its expiry is refused by the state machine, and the operator
// reads the reason.
func TestAnExpiredDecreeIsRefusedWithItsReason(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	version := leader.node.fsm.ClusterState().Version
	decree := c.pinDecree(leader, version, testCDSDigest, rolledCDSDigest)
	decree.ExpiresAt = time.Now().Add(-time.Minute)

	delivered := c.posted(leader, c.signDecree(decree))

	if !strings.Contains(delivered.Refused, "expired") {
		t.Fatalf("the cluster answered %+v, want the expired decree refused", delivered)
	}
	if core := leader.node.fsm.ClusterState(); core.Version != version {
		t.Fatalf("the cluster moved to version %d", core.Version)
	}
}
