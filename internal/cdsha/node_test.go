package cdsha

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// Every store the leader writes is held by every replica of the cluster.
func TestEveryReplicaHoldsWhatTheLeaderWrote(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	added, retired, err := leader.node.Allowlist().SeedWorkloads(map[string]pkgallowlist.Workload{"web": testWorkload(t, 1)})
	if err != nil || added != 1 || retired != 0 {
		t.Fatalf("seeding the allowlist added %d and retired %d: %v", added, retired, err)
	}
	stored, held, err := leader.node.Secrets().PutIfAbsent(t.Context(), "/web/token", []byte("secret"), secrets.WorkloadHolder("web"))
	if err != nil || string(stored) != "secret" || held.Exists {
		t.Fatalf("putting a secret stored %q over held %+v: %v", stored, held, err)
	}
	if !leader.node.Bindings().Record("sandbox-1", "10.0.0.1") {
		t.Fatal("the ledger refused a binding")
	}
	version, err := leader.node.Allowlist().Version()
	if err != nil {
		t.Fatal(err)
	}
	ca := leader.node.fsm.ClusterState().MeshCACert
	for _, r := range c.replicas {
		c.caughtUp(r, leader, 5*time.Second)
		heldVersion, err := r.node.Allowlist().Version()
		if err != nil || heldVersion != version {
			t.Fatalf("replica holds allowlist version %q, the leader wrote %q: %v", heldVersion, version, err)
		}
		if value, err := r.node.Secrets().Get(t.Context(), "/web/token"); err != nil || string(value) != "secret" {
			t.Fatalf("replica holds secret %q: %v", value, err)
		}
		if host, bound := r.node.Bindings().Lookup("sandbox-1"); !bound || host != "10.0.0.1" {
			t.Fatalf("replica holds binding %q, %v", host, bound)
		}
		if !bytes.Equal(r.node.fsm.ClusterState().MeshCACert, ca) {
			t.Fatal("replica holds another mesh CA than the leader")
		}
	}
}

// A sandbox binding taken at the leader is visible at a replica that has not
// applied it yet: the lookup catches up with the log.
func TestALookupCatchesUpWithTheLog(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	if !c.leader().node.Bindings().Record("sandbox-2", "10.0.0.2") {
		t.Fatal("the ledger refused a binding")
	}
	follower := c.follower()
	if host, bound := follower.node.Bindings().Lookup("sandbox-2"); !bound || host != "10.0.0.2" {
		t.Fatalf("a follower looked up %q, %v", host, bound)
	}
}

// A replica that has reached no leader takes no write: its store reports the
// cluster unavailable, which its handlers answer as retryable.
func TestAReplicaThatReachedNoLeaderTakesNoWrite(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	cut := c.follower()
	c.partition(cut, true)

	eventually(t, 10*time.Second, "the cut replica reaching no leader", func() bool {
		_, err := cut.node.Secrets().Put(t.Context(), "/during", []byte("v"))
		return errors.Is(err, secrets.ErrUnavailable)
	})
}

// A replica that holds no cluster takes no store write: applying one would
// stop every replica of a cluster it is not in.
func TestAReplicaWithNoClusterTakesNoWrite(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	_, err := r.node.Secrets().Put(t.Context(), "/early", []byte("v"))
	if !errors.Is(err, secrets.ErrUnavailable) || !strings.Contains(err.Error(), "holds no cluster") {
		t.Fatalf("a write before Genesis answered %v", err)
	}
	if reason := r.node.fsm.Stuck(); reason != "" {
		t.Fatalf("the refused write stopped the replica: %s", reason)
	}
}

// The leader's process is gone: the rest elect another leader, which holds
// what the old one committed and takes writes.
func TestAnotherLeaderTakesOverWhenOneStops(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	gone := c.leader()
	if _, _, err := gone.node.Allowlist().SeedWorkloads(map[string]pkgallowlist.Workload{"web": testWorkload(t, 3)}); err != nil {
		t.Fatal(err)
	}
	version, err := gone.node.Allowlist().Version()
	if err != nil {
		t.Fatal(err)
	}
	c.stop(gone)
	eventually(t, 10*time.Second, "another leader holding what the old one wrote", func() bool {
		elected := c.leader()
		if elected == nil {
			return false
		}
		held, err := elected.node.Allowlist().Version()
		return err == nil && held == version
	})
	eventually(t, 10*time.Second, "a write at the new leader", func() bool {
		elected := c.leader()
		if elected == nil {
			return false
		}
		_, _, err := elected.node.Secrets().PutIfAbsent(t.Context(), "/after", []byte("v"), secrets.WorkloadHolder("web"))
		return err == nil
	})
}

// A replica added once compaction has dropped the entries it is missing takes
// the whole state from the snapshot its peer sends, and serves it.
func TestAReplicaJoiningTakesTheStateFromASnapshot(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	pastTheEntriesRaftKeeps := trailingLogs + 32
	for i := range pastTheEntriesRaftKeeps {
		if _, err := leader.node.Secrets().Put(t.Context(), fmt.Sprintf("/s/%d", i), []byte("v")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	if err := leader.node.raft.Snapshot().Error(); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	joiner := c.start()
	c.caughtUp(joiner, leader, 15*time.Second)
	if index, _, _ := joiner.node.snaps.latest(); index == 0 {
		t.Fatal("the joining replica installed no snapshot")
	}
	if value, err := joiner.node.Secrets().Get(t.Context(), "/s/0"); err != nil || string(value) != "v" {
		t.Fatalf("the joining replica holds secret %q: %v", value, err)
	}
	if !joiner.node.fsm.ClusterState().Joined() {
		t.Fatal("the joining replica holds no cluster")
	}
}

// A replica cut off from its peers stops following the log, and catches up
// once the cut is over.
func TestACutOffReplicaCatchesUpWhenItReturns(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	cut := c.follower()
	c.partition(cut, true)
	if _, err := leader.node.Secrets().Put(t.Context(), "/during", []byte("v")); err != nil {
		t.Fatalf("a write with one replica cut off: %v", err)
	}
	if value, err := cut.node.Secrets().Get(t.Context(), "/during"); err == nil && len(value) > 0 {
		t.Fatalf("the cut replica holds %q, written while it was cut off", value)
	}
	if cut.node.fsm.AppliedIndex() >= leader.node.fsm.AppliedIndex() {
		t.Fatal("the cut replica kept following the log")
	}
	c.partition(cut, false)
	c.caughtUp(cut, leader, 15*time.Second)
	if value, err := cut.node.Secrets().Get(t.Context(), "/during"); err != nil || string(value) != "v" {
		t.Fatalf("the replica that returned holds secret %q: %v", value, err)
	}
}

// An entry no replica can apply stops them all at it: every replica reports
// the same stop, and takes no write afterwards.
func TestAnEntryNoReplicaCanApplyStopsThemAll(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	c.commitRaw(leader, []byte(`{"kind":"nonsense"}`))
	for _, r := range c.replicas {
		eventually(t, 5*time.Second, "the replica stopped following the log", func() bool {
			return r.node.fsm.Stuck() != ""
		})
		if r.node.fsm.StuckLocal() {
			t.Fatal("an entry every replica refuses was taken for a local fault")
		}
	}
	if _, err := leader.node.Secrets().Put(t.Context(), "/after", []byte("v")); !errors.Is(err, secrets.ErrUnavailable) {
		t.Fatalf("a stopped leader answered %v", err)
	}
}

// Run drives a replica its caller started.
func TestRunNeedsAStartedReplica(t *testing.T) {
	c := newLiveCluster(t)
	node, err := NewNode(c.replicaConfig(c.attestationAPI()))
	if err != nil {
		t.Fatal(err)
	}
	if err := node.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("Run on a replica that is not started: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(node.stop)
	if err := node.Start(); err == nil {
		t.Fatal("a replica started twice")
	}
}

// When its context ends, the replica leaves no Raft running and no peer port
// open.
func TestRunEndsWithItsContext(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	r.cancel()
	<-r.done
	if err := r.node.raft.Apply([]byte("{}"), time.Second).Error(); !errors.Is(err, raft.ErrRaftShutdown) {
		t.Fatalf("Raft kept running: %v", err)
	}
	if !r.node.mux.closed() {
		t.Fatal("the peer port stayed open")
	}
}

// A replica refuses a configuration it could not serve its cluster on.
func TestNewNodeRefusesAConfigurationItCannotServe(t *testing.T) {
	c := newLiveCluster(t)
	for name, spoil := range map[string]func(*Config){
		"no launch file":                        func(cfg *Config) { cfg.LaunchFile = nil },
		"no peer address":                       func(cfg *Config) { cfg.Peer = netip.AddrPort{} },
		"a peer address of no host":             func(cfg *Config) { cfg.Peer = netip.MustParseAddrPort("0.0.0.0:8444") },
		"a read lease shorter than three ticks": func(cfg *Config) { cfg.Timing.Lease = 2 * testTiming.Tick },
		"an election shorter than the heartbeat": func(cfg *Config) {
			cfg.Timing = Timing{
				Heartbeat: time.Second,
				Election:  time.Millisecond,
			}
		},
		"no allowlist store":        func(cfg *Config) { cfg.Allowlist = nil },
		"no secret store":           func(cfg *Config) { cfg.Secrets = nil },
		"no ledger":                 func(cfg *Config) { cfg.Ledger = nil },
		"an attestation-api abroad": func(cfg *Config) { cfg.AttestationURL = "https://attestation.example.org" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := c.replicaConfig(c.attestationAPI())
			spoil(&cfg)
			if _, err := NewNode(cfg); err == nil {
				t.Fatal("the replica started")
			}
		})
	}
}

// Every start is a member of its own, and the peer port answers for it.
func TestEveryStartIsANewMember(t *testing.T) {
	c := newLiveCluster(t)
	first := c.start()
	second := c.start()
	if first.node.member == second.node.member {
		t.Fatal("two replicas minted the same member id")
	}
	if answering := first.node.mux.advert.member; answering != string(first.node.member) {
		t.Fatalf("the peer port answers for member %q, the replica is %q", answering, first.node.member)
	}
}

// A replica admits peers by its own image until the cluster names the images
// a CDS of it may run.
func TestAReplicaAdmitsItsOwnImageUntilTheClusterNamesThem(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()
	own := r.node.admits()
	if len(own) != 1 || hex.EncodeToString(own[0].Digest) != testCDSImage {
		t.Fatalf("a replica holding no cluster admits %+v", own)
	}
	c.decreeGenesis(r, true)
	c.started(r)
	pinned := r.node.admits()
	if len(pinned) != 1 || hex.EncodeToString(pinned[0].Digest) != testCDSImage {
		t.Fatalf("a replica of the cluster admits %+v", pinned)
	}
	if !bytes.Equal(pinned[0].LaunchFile, testLaunchFile) {
		t.Fatal("the cluster's images are not bound to the launch file this replica boots")
	}
}

// A pin decree that names another image leaves the replicas admitting no
// peer, so every connection between them is cut and the cluster has no
// leader.
func TestAPinDecreeThatDropsTheirImageCutsThePeersOff(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	res, err := leader.node.propose(Entry{
		Kind:   KindDecree,
		Decree: c.decreeEntry(leader, cdsdecree.UpdateMeasurements),
	})
	if err != nil {
		t.Fatalf("commit a pin decree: %v", err)
	}
	if res.Decree == nil || res.Decree.Refused != "" {
		t.Fatalf("the pin decree was refused: %+v", res.Decree)
	}
	if slices.ContainsFunc(leader.node.admits(), runningImage) {
		t.Fatalf("the pin decree still names the image these replicas run: %+v", leader.node.admits())
	}
	eventually(t, 10*time.Second, "the cluster to be left without a leader", func() bool {
		return c.leader() == nil
	})
}

// runningImage reports the image the test cluster's replicas report running.
func runningImage(pinned remote.ImagePin) bool {
	return hex.EncodeToString(pinned.Digest) == testCDSImage
}

// A write the admission cap refused is the store's full error; one the
// cluster could not commit is its unavailable error.
func TestTheCapRefusesAWriteAsFullNotUnavailable(t *testing.T) {
	full := secretsErrors.uncommitted(fmt.Errorf("refused: %w", ErrCapacity))
	if !errors.Is(full, secrets.ErrCapacity) || errors.Is(full, secrets.ErrUnavailable) {
		t.Fatalf("a write over the cap answered %v", full)
	}
	unavailable := secretsErrors.uncommitted(raft.ErrNotLeader)
	if !errors.Is(unavailable, secrets.ErrUnavailable) || errors.Is(unavailable, secrets.ErrCapacity) {
		t.Fatalf("a write that did not commit answered %v", unavailable)
	}
}
