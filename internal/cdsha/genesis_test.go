package cdsha

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// The replica the operator's Genesis decree names starts the cluster as its
// one voter, with the mesh CA the decree names, and the replicas that did not
// start it join as non-voters.
func TestTheDecreedReplicaStartsTheClusterAndTheRestJoin(t *testing.T) {
	c := newLiveCluster(t)
	first := c.start()
	second := c.start()
	third := c.start()

	decreed := c.genesisCAOf(first)
	c.decreeGenesis(first, false)
	c.started(first)
	c.joined(3)

	if fingerprint := certutil.CertFingerprint(first.node.fsm.ClusterState().MeshCACert); fingerprint != decreed {
		t.Fatalf("the cluster holds mesh CA %s, and its Genesis names %s", fingerprint, decreed)
	}
	for _, joiner := range []*liveReplica{second, third} {
		c.reaches(first, joiner, joiner.peerAddress())
		server, _ := c.serverFor(first, string(joiner.node.member))
		if server.Suffrage != raft.Nonvoter {
			t.Fatalf("a replica joined as %v, want a non-voter", server.Suffrage)
		}
		eventually(t, 10*time.Second, "the joiner holds the cluster", func() bool {
			return joiner.node.fsm.ClusterState().Joined()
		})
	}
}

// A Genesis decree names the member id its target minted at its start, so no
// other replica acts on it: neither one the operator did not decree, nor one
// replaying a decree recorded from the cluster's own start. A replica takes
// no decree naming another member in the first place.
func TestOnlyTheProcessAGenesisNamesStartsAnything(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	decreed := c.genesisFor(r, true)
	decreed.TargetMember = testMember

	if _, err := r.node.TakeDecree(c.signDecree(decreed)); err == nil {
		t.Fatal("a replica took a Genesis decree naming another member")
	}

	c.noClusterStarts()
}

// A Genesis the cluster's operator did not sign starts nothing: the replica
// it is posted to does not take it.
func TestAGenesisAnotherKeySignedStartsNothing(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	host, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := cdsdecree.Sign(c.genesisFor(r, true), host)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := r.node.TakeDecree(signed); err == nil {
		t.Fatal("a replica took a Genesis decree the cluster's operator did not sign")
	}

	c.noClusterStarts()
}

// A replica that cannot resolve every replica of its cluster cannot say that
// no cluster exists, so it starts none. It starts one once discovery answers
// for them all.
func TestADecreedReplicaStartsNoClusterWhileDiscoveryIsIncomplete(t *testing.T) {
	c := newLiveCluster(t)
	first := c.start()
	c.start()
	first.resolve.fails()
	c.decreeGenesis(first, false)

	c.noClusterStarts()

	c.resolveEachOther()
	c.started(first)
}

// A replica whose peers answer nothing starts no cluster either: the host
// answers every lookup, and a hidden cluster is one a second Genesis would
// run beside. The operator signs `alone` for the cluster that has no second
// replica to answer.
func TestADecreedReplicaStartsNoClusterWhileNoPeerAnswers(t *testing.T) {
	c := newLiveCluster(t)
	first := c.start()
	hidden := c.start()
	c.partition(hidden, true)
	c.decreeGenesis(first, false)

	c.noClusterStarts()

	c.partition(hidden, false)
	c.started(first)
}

// A replica that already holds a cluster starts no second one, whatever is
// posted to it.
func TestAReplicaHoldingAClusterStartsNoSecondOne(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	leader := c.leader()
	second := c.genesisFor(leader, true)
	// A replica holding a cluster offers no mesh CA to install, so the
	// decree names the one its cluster already holds.
	second.GenesisCA = certutil.CertFingerprint(leader.node.fsm.ClusterState().MeshCACert)

	c.posted(leader, c.signDecree(second))

	time.Sleep(20 * testTiming.Tick)
	if slices.Contains(leader.node.fsm.ClusterState().AppliedDecrees, second.IntentID) {
		t.Fatalf("a second Genesis applied to a cluster that had started: %s", second.IntentID)
	}
}
