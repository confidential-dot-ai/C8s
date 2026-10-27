package cdsha

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
)

// One-shot decrees are bound to one process (target_member), Genesis
// needs a peer unless it says alone, and a backup replaces only its own
// ancestor. The tests model a host where the decree objects are pending
// again (status stripped, or re-created from a recorded copy), peer
// discovery answers what the host wants, and the guest clock is still
// before ExpiresAt (every decree here expires in an hour).

func (c *cluster) selfOnlyDNS(name string, on bool) {
	c.mu.Lock()
	c.dnsSelfOnly[c.ipOf[name]] = on
	c.mu.Unlock()
}

func (c *cluster) stripDecreeStatus() {
	c.decrees.mu.Lock()
	c.decrees.status = map[string]DecreeStatus{}
	c.decrees.mu.Unlock()
}

// never fails if ok holds at any point within d.
func never(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
		if ok() {
			t.Fatal(what)
		}
	}
}

// The used Genesis, replayed to a restarted replica on its node whose
// discovery the host empties, must not start a second cluster.
func TestGenesisReplayToFreshReplicaRefused(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	fp := c.leader().node.Status().CAFingerprint
	c.stripDecreeStatus()
	c.stopReplica(c.nodes["n0"])
	c.selfOnlyDNS("n0", true)
	fresh := c.start("n0", "m1")
	never(t, 3*time.Second, "the replayed Genesis started a second cluster on the restarted n0", func() bool {
		return fresh.node.member() || fresh.node.Core().Joined()
	})
	c.selfOnlyDNS("n0", false)
	eventually(t, 15*time.Second, "n0 joins the original cluster", func() bool {
		return fresh.node.Status().Serving && fresh.node.Status().CAFingerprint == fp
	})
}

// After a total loss every replica is fresh and finds only fresh peers: the
// host replaying the used Genesis must not mint a new mesh CA in place of
// the operator's Restore.
func TestGenesisReplayAfterTotalLossRefused(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	for _, r := range c.live() {
		c.stopReplica(r)
	}
	c.stripDecreeStatus()
	var fresh []*replica
	for _, n := range []string{"n0", "n1", "n2"} {
		fresh = append(fresh, c.start(n, "m1"))
	}
	never(t, 4*time.Second, "the replayed Genesis started a new cluster after the total loss", func() bool {
		for _, r := range fresh {
			if r.node.member() || r.node.Core().Joined() {
				return true
			}
		}
		return false
	})
}

// Genesis bound to the replica, but discovery finds nobody: it waits, unless
// the operator signed it alone.
func TestGenesisEmptyDiscoveryNeedsAlone(t *testing.T) {
	c := newCluster(t, 3)
	c.start("n0", "m1")
	c.selfOnlyDNS("n0", true)
	c.start("n1", "m1") // exists, but n0's discovery does not show it
	g := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	never(t, 3*time.Second, "Genesis started a cluster although discovery found no other replica", func() bool {
		return c.nodes["n0"].node.member()
	})
	if _, ok := c.decrees.get(g); ok {
		t.Fatal("the waiting Genesis got a status")
	}
	c.decrees.mu.Lock()
	delete(c.decrees.items, g) // the operator replaces it
	c.decrees.mu.Unlock()
	c.decree(Decree{Kind: Genesis, BootstrapNode: "n0", Alone: true})
	eventually(t, 10*time.Second, "an alone Genesis starts the cluster", func() bool {
		return c.nodes["n0"].node.Core().Joined()
	})
}

// A Recover decree is for the process the operator saw, not a later one.
func TestRecoverDecreeBoundToMember(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	n1 := c.nodes["n1"].node
	epoch := n1.Core().Epoch
	c.decrees.failStatus.Store(true) // the leader's refusal must not hide the decrees from n1
	c.decree(Decree{Kind: Recover, BootstrapNode: "n1", TargetMember: "n1/1-000000000000", BaseEpoch: epoch})
	if p, ok := n1.pendingDecree(context.Background(), Recover); ok {
		t.Fatalf("a Recover for another process on n1 is usable: %s", p.Name)
	}
	c.decree(Decree{Kind: Recover, BootstrapNode: "n1", BaseEpoch: epoch}) // names n1's member
	if _, ok := n1.pendingDecree(context.Background(), Recover); !ok {
		t.Fatal("a Recover for n1's own process is not usable")
	}
}

// A Restore decree the operator signed for one process (with the plaintext
// snapshot it names), replayed to the replica's next start, is refused.
func TestRestoreReplayToFreshReplicaRefused(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if err := l.al.PutWorkload("old", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	want := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "backup", func() bool { b, ok := c.backups.get(); return ok && b.Meta.Index >= want })
	bk, _ := c.backups.get()
	snap, err := OpenBackup(c.recKey, bk)
	if err != nil {
		t.Fatal(err)
	}
	rd := signDecree(t, c.opKey, Decree{Kind: Restore, BootstrapNode: "n2", TargetMember: c.memberOf("n2"), SnapshotSHA256: SnapshotSHA256(snap)})
	if _, err := c.leader().al.DeleteWorkload("old"); err != nil {
		t.Fatal(err)
	}
	c.stopReplica(c.nodes["n2"])
	c.selfOnlyDNS("n2", true)
	fresh := c.start("n2", "m1")
	time.Sleep(time.Second)
	if err := fresh.node.CheckRestore(rd); !errors.Is(err, ErrNotForThisNode) {
		t.Fatalf("CheckRestore of the replayed decree: %v, want ErrNotForThisNode", err)
	}
	if res, err := fresh.node.Restore(context.Background(), rd, snap); !errors.Is(err, ErrNotForThisNode) {
		t.Fatalf("replayed Restore: %v %+v, want ErrNotForThisNode", err, res)
	}
	if fresh.node.member() || fresh.node.Core().Joined() {
		t.Fatal("the replayed Restore started a cluster")
	}
}

// Even an operator-signed restore of an older backup next to the live
// cluster (an operator mistake, or a Recover next to a live majority) must not take the backup
// slot: its history lacks the live cluster's later writes.
func TestRestoredOldBackupCannotTakeBackupSlot(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if err := l.al.PutWorkload("old", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	want := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "backup", func() bool { b, ok := c.backups.get(); return ok && b.Meta.Index >= want })
	old, _ := c.backups.get()
	snap, err := OpenBackup(c.recKey, old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.leader().al.DeleteWorkload("old"); err != nil {
		t.Fatal(err)
	}
	want = c.leader().node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "backup of the revocation", func() bool { b, ok := c.backups.get(); return ok && b.Meta.Index >= want })
	c.stopReplica(c.nodes["n2"])
	c.selfOnlyDNS("n2", true)
	fresh := c.start("n2", "m1")
	time.Sleep(time.Second)
	// The mistake: the operator says alone, and the host's DNS agrees.
	rd := signDecree(t, c.opKey, Decree{Kind: Restore, BootstrapNode: "n2", TargetMember: fresh.node.ID(), SnapshotSHA256: SnapshotSHA256(snap), Alone: true})
	if _, err := fresh.node.Restore(context.Background(), rd, snap); err != nil {
		t.Fatalf("restore: %v", err)
	}
	eventually(t, 5*time.Second, "the restored side serves", fresh.node.Serving)
	eventually(t, 5*time.Second, "the restored side's backup is refused", func() bool {
		return strings.Contains(fresh.node.Status().BackupError, "backup refused")
	})
	if b, _ := c.backups.get(); b.Meta.Epoch != 1 {
		t.Fatalf("the restored side (epoch 2) took the backup slot: stored epoch %d index %d", b.Meta.Epoch, b.Meta.Index)
	}
	var live *replica
	for _, r := range c.live() {
		if r != fresh && r.node.leading() {
			live = r
		}
	}
	if live == nil {
		t.Fatal("no live-cluster leader")
	}
	if err := live.al.PutWorkload("after", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
	want = live.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "the live cluster's backups go on", func() bool {
		b, ok := c.backups.get()
		return ok && b.Meta.Epoch == 1 && b.Meta.Index >= want
	})
}

func TestBackupMetaFollows(t *testing.T) {
	stored := BackupMeta{ClusterID: "c", Epoch: 1, Index: 50, AppliedDecrees: []string{"g"}, EpochFrom: []uint64{0}}
	for _, tc := range []struct {
		name string
		m    BackupMeta
		want bool
	}{
		{"later index, same epoch", BackupMeta{ClusterID: "c", Epoch: 1, Index: 51, AppliedDecrees: []string{"g"}, EpochFrom: []uint64{0}}, true},
		{"same index", stored, false},
		{"decree after the stored index", BackupMeta{ClusterID: "c", Epoch: 2, Index: 60, AppliedDecrees: []string{"g", "d"}, EpochFrom: []uint64{0, 55}}, true},
		{"restore of the stored backup", BackupMeta{ClusterID: "c", Epoch: 2, Index: 3, AppliedDecrees: []string{"g", "r"}, EpochFrom: []uint64{0, 50}}, true},
		{"restore of an older backup", BackupMeta{ClusterID: "c", Epoch: 2, Index: 3, AppliedDecrees: []string{"g", "r"}, EpochFrom: []uint64{0, 20}}, false},
		{"another Genesis", BackupMeta{ClusterID: "c", Epoch: 1, Index: 90, AppliedDecrees: []string{"g2"}, EpochFrom: []uint64{0}}, false},
		{"another Genesis, later epoch", BackupMeta{ClusterID: "c", Epoch: 2, Index: 90, AppliedDecrees: []string{"g2", "d"}, EpochFrom: []uint64{0, 80}}, false},
		{"older epoch", BackupMeta{ClusterID: "c", Epoch: 0, Index: 99}, false},
		{"another cluster", BackupMeta{ClusterID: "x", Epoch: 1, Index: 51, AppliedDecrees: []string{"g"}, EpochFrom: []uint64{0}}, false},
		{"later epoch without epoch_from", BackupMeta{ClusterID: "c", Epoch: 2, Index: 60, AppliedDecrees: []string{"g", "d"}}, false},
	} {
		if got := tc.m.Follows(stored); got != tc.want {
			t.Errorf("%s: Follows = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// KubeDecrees.PutBackup keeps the stored backup against one of another
// history, and takes its own descendant.
func TestPutBackupRefusesAnotherHistory(t *testing.T) {
	ctx := context.Background()
	st := KubeDecrees{Client: fake.NewClientset(), Namespace: "decrees", ClusterID: testCluster}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	put := func(m BackupMeta) error {
		m.ClusterID = testCluster
		b, err := SealBackup(&rk.PublicKey, m, []byte("snapshot"))
		if err != nil {
			t.Fatal(err)
		}
		return st.PutBackup(ctx, b)
	}
	if err := put(BackupMeta{Epoch: 1, Index: 50, AppliedDecrees: []string{"g"}, EpochFrom: []uint64{0}}); err != nil {
		t.Fatal(err)
	}
	if err := put(BackupMeta{Epoch: 2, Index: 3, AppliedDecrees: []string{"g", "r"}, EpochFrom: []uint64{0, 20}}); !errors.Is(err, ErrBackupNotNewer) {
		t.Fatalf("a restore of an older backup replaced the stored one: %v", err)
	}
	if err := put(BackupMeta{Epoch: 1, Index: 90, AppliedDecrees: []string{"g2"}, EpochFrom: []uint64{0}}); !errors.Is(err, ErrBackupNotNewer) {
		t.Fatalf("another Genesis replaced the stored backup: %v", err)
	}
	if err := put(BackupMeta{Epoch: 2, Index: 3, AppliedDecrees: []string{"g", "r"}, EpochFrom: []uint64{0, 50}}); err != nil {
		t.Fatalf("a restore of the stored backup: %v", err)
	}
	if b, err := st.GetBackup(ctx); err != nil || b.Meta.Epoch != 2 || !slices.Equal(b.Meta.EpochFrom, []uint64{0, 50}) {
		t.Fatalf("stored: %+v %v", b.Meta, err)
	}
}

// Backups sealed before format 4 (HPKE info c8s-cds-ha-backup-v2) do not
// open: their metadata has no epoch_from to check lineage with.
func TestBackupSealedAsV2IsRefused(t *testing.T) {
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	meta := BackupMeta{ClusterID: testCluster, Epoch: 1, Index: 5, AppliedDecrees: []string{"g"}}
	j, _ := json.Marshal(meta)
	ecdh, _ := rk.PublicKey.ECDH()
	pk, err := hpke.NewDHKEMPublicKey(ecdh)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), append([]byte("c8s-cds-ha-backup-v2\n"), j...), []byte("snapshot"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(rk, Backup{Meta: meta, Ciphertext: ct}); err == nil {
		t.Fatal("a v2 backup opened")
	}
	v3, _ := SealBackup(&rk.PublicKey, meta, []byte("snapshot"))
	if _, err := OpenBackup(rk, v3); err != nil {
		t.Fatalf("control: %v", err)
	}
}
