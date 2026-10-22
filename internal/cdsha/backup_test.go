package cdsha

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestBackupStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	if _, err := st.GetBackup(ctx); err == nil {
		t.Fatal("a backup where none was stored")
	}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	snap := make([]byte, 5000) // random: gzip cannot shrink it below several parts
	_, _ = rand.Read(snap)
	orig := backupPartBytes
	backupPartBytes = 1000 // several parts
	t.Cleanup(func() { backupPartBytes = orig })
	meta := BackupMeta{ClusterID: testCluster, Epoch: 2, Index: 9}
	b, err := SealBackup(&rk.PublicKey, meta, snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutBackup(ctx, b); err != nil {
		t.Fatal(err)
	}
	// The same state again, or older state, never replaces it: a deposed
	// leader or a cut-off replica must not overwrite the majority's backup.
	if err := st.PutBackup(ctx, b); !errors.Is(err, ErrBackupNotNewer) {
		t.Fatalf("same backup again: %v", err)
	}
	older, _ := SealBackup(&rk.PublicKey, BackupMeta{ClusterID: testCluster, Epoch: 2, Index: 8}, snap)
	if err := st.PutBackup(ctx, older); !errors.Is(err, ErrBackupNotNewer) {
		t.Fatalf("older index: %v", err)
	}
	olderEpoch, _ := SealBackup(&rk.PublicKey, BackupMeta{ClusterID: testCluster, Epoch: 1, Index: 99}, snap)
	if err := st.PutBackup(ctx, olderEpoch); !errors.Is(err, ErrBackupNotNewer) {
		t.Fatalf("older epoch, later index: %v", err)
	}
	// Later state replaces it in place (a Restore restarts the index at a
	// higher epoch).
	b, _ = SealBackup(&rk.PublicKey, BackupMeta{ClusterID: testCluster, Epoch: 2, Index: 10}, snap)
	if err := st.PutBackup(ctx, b); err != nil {
		t.Fatal(err)
	}
	meta.Index = 10
	got, err := st.GetBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := OpenBackup(rk, got)
	if err != nil || string(plain) != string(snap) || got.Meta.Epoch != 2 {
		t.Fatalf("round trip: %v", err)
	}
	list, _ := kube.CoreV1().ConfigMaps("decrees").List(ctx, metav1.ListOptions{})
	items := list.Items
	var man backupManifest
	for _, cm := range items {
		if cm.Name == BackupName(testCluster) {
			_ = json.Unmarshal([]byte(cm.Data[keyBackup]), &man)
		}
	}
	// Only the stored backup's parts remain: the earlier one's were deleted.
	if man.Gen == "" || len(items) != man.Parts+1 || man.Parts < 3 {
		t.Fatalf("want the manifest and its %d parts (gen %q), got %d objects", man.Parts, man.Gen, len(items))
	}
	tamperedOne := false
	if _, err := BackupFromConfigMaps("other", items); err == nil {
		t.Fatal("a backup for another cluster")
	}
	for i := range items {
		if items[i].Name == man.partName(testCluster, 1) {
			tamperedOne = true
			bad := append([]byte{}, items[i].BinaryData[keyPart]...)
			bad[0] ^= 1
			tampered := append(items[:0:0], items...)
			tampered[i].BinaryData = map[string][]byte{keyPart: bad}
			if _, err := BackupFromConfigMaps(testCluster, tampered); err == nil {
				t.Fatal("a tampered part assembled")
			}
			missing := append(append(items[:0:0], items[:i]...), items[i+1:]...)
			if _, err := BackupFromConfigMaps(testCluster, missing); err == nil {
				t.Fatal("a backup with a missing part assembled")
			}
		}
		if items[i].Name == BackupName(testCluster) {
			broken := append(items[:0:0], items...)
			broken[i].Data = map[string]string{keyBackup: "{"}
			if _, err := BackupFromConfigMaps(testCluster, broken); err == nil {
				t.Fatal("a garbage manifest parsed")
			}
		}
	}
	if !tamperedOne {
		t.Fatal("part 1 not found")
	}
	bad := got
	bad.EphemeralPub = []byte("x")
	if _, err := OpenBackup(rk, bad); err == nil {
		t.Fatal("garbage ephemeral key accepted")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SealBackup(&p384.PublicKey, meta, snap); err != nil {
		// P-384 also converts; only check the call does not panic.
		_ = err
	}
}

// Restore entries are refused unless the decree, snapshot and cluster agree.
func TestApplyRestoreRefusals(t *testing.T) {
	al, sec, led := testStores(t)
	opKey, opPub := operatorKey(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	ca := mustCA(t)
	key, _ := x509.MarshalPKCS8PrivateKey(ca.Key)
	good := snapshot{Core: Core{ClusterID: testCluster, Epoch: 3, RootCert: ca.Cert.Raw, Measurements: []string{"m1"}, OperatorPubKey: opPub}, Key: key}
	enc := func(sn snapshot) []byte { b, _ := json.Marshal(sn); return b }
	sign := func(kind DecreeKind, s []byte) SignedDecree {
		d := Decree{ClusterID: testCluster, IntentID: "r" + string(kind), Kind: kind, BootstrapNode: "n0", ExpiresAt: time.Now().Add(time.Hour)}
		if kind == Restore {
			d.SnapshotSHA256 = SnapshotSHA256(s)
		}
		sd, _ := SignDecree(d, opKey)
		return sd
	}
	now := time.Now().UnixMilli()
	other := good
	other.Core.ClusterID = "other"
	otherOp := good
	otherOp.Core.OperatorPubKey = []byte("k")
	noCA := good
	noCA.Core.RootCert = nil
	for name, re := range map[string]RestoreEntry{
		"not a Restore decree": {Decree: sign(Genesis, nil), AtMS: now, Snapshot: enc(good)},
		"snapshot mismatch":    {Decree: sign(Restore, enc(good)), AtMS: now, Snapshot: enc(noCA)},
		"garbage snapshot":     {Decree: sign(Restore, []byte("{")), AtMS: now, Snapshot: []byte("{")},
		"other cluster":        {Decree: sign(Restore, enc(other)), AtMS: now, Snapshot: enc(other)},
		"other operator":       {Decree: sign(Restore, enc(otherOp)), AtMS: now, Snapshot: enc(otherOp)},
		"no mesh CA":           {Decree: sign(Restore, enc(noCA)), AtMS: now, Snapshot: enc(noCA)},
		"expired":              {Decree: sign(Restore, enc(good)), AtMS: time.Now().Add(2 * time.Hour).UnixMilli(), Snapshot: enc(good)},
	} {
		if res := f.applyRestore(re); res.Err == "" {
			t.Errorf("%s restored", name)
		}
	}
	res := f.applyRestore(RestoreEntry{Decree: sign(Restore, enc(good)), AtMS: now, Snapshot: enc(good)})
	if res.Err != "" || res.Epoch != 4 || f.CA() == nil {
		t.Fatalf("restore: %+v", res)
	}
	if res := f.applyRestore(RestoreEntry{Decree: sign(Restore, enc(good)), AtMS: now, Snapshot: enc(good)}); res.Err == "" {
		t.Fatal("restored over a cluster that has a key")
	}
	// Decree rules for Restore.
	pre := PreGenesis(testCluster, opPub)
	for name, d := range map[string]Decree{
		"no hash":        {Kind: Restore, BootstrapNode: "n0"},
		"no node":        {Kind: Restore, SnapshotSHA256: "aa"},
		"hash on update": {Kind: UpdateMeasurements, Measurements: []string{"m"}, SnapshotSHA256: "aa"},
	} {
		d.ClusterID, d.IntentID, d.ExpiresAt = testCluster, "x", time.Now().Add(time.Hour)
		sd, _ := SignDecree(d, opKey)
		if err := CheckDecree(sd, pre, time.Now()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// A backup stays whole while the next is written: a writer that dies after
// writing parts leaves the stored manifest and its parts as they were, and a
// writer that raced another loses instead of overwriting it.
func TestBackupWriteIsAtomic(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	orig := backupPartBytes
	backupPartBytes = 100
	t.Cleanup(func() { backupPartBytes = orig })
	seal := func(index uint64) Backup {
		snap := make([]byte, 400)
		_, _ = rand.Read(snap)
		b, err := SealBackup(&rk.PublicKey, BackupMeta{ClusterID: testCluster, Epoch: 1, Index: index}, snap)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	first := seal(5)
	if err := st.PutBackup(ctx, first); err != nil {
		t.Fatal(err)
	}
	// A crashed writer: its parts are there, its manifest never was.
	crashed := backupManifest{Gen: "e1-i6-dead", Parts: 2}
	for i := range crashed.Parts {
		cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: crashed.partName(testCluster, i), Namespace: "decrees",
			Labels: map[string]string{LabelBackup: testCluster}}, BinaryData: map[string][]byte{keyPart: []byte("junk")}}
		if _, err := kube.CoreV1().ConfigMaps("decrees").Create(ctx, cm, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.GetBackup(ctx)
	if err != nil || got.Meta.Index != 5 {
		t.Fatalf("the stored backup broke under a crashed write: %v", err)
	}
	// The next backup goes in and sweeps the crashed parts.
	if err := st.PutBackup(ctx, seal(7)); err != nil {
		t.Fatal(err)
	}
	list, _ := kube.CoreV1().ConfigMaps("decrees").List(ctx, metav1.ListOptions{})
	for _, cm := range list.Items {
		if strings.Contains(cm.Name, crashed.Gen) {
			t.Fatalf("crashed part %s left behind", cm.Name)
		}
	}
	// A writer whose manifest changed under it loses: the update is
	// conditional on the manifest it checked.
	kube.PrependReactor("update", "configmaps", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, BackupName(testCluster), errors.New("changed"))
	})
	if err := st.PutBackup(ctx, seal(9)); !errors.Is(err, ErrBackupNotNewer) {
		t.Fatalf("a raced write: %v", err)
	}
	if got, err := st.GetBackup(ctx); err != nil || got.Meta.Index != 7 {
		t.Fatalf("a raced write damaged the stored backup: %v %v", got.Meta.Index, err)
	}
}

// A snapshot's allowlist history is many near copies of one document. The
// backup must store the repeats as references: with gzip a backup grew by
// about one compressed document per version (5 MB for 464 versions of a
// 70 KiB allowlist on TDX), all of it rewritten into etcd every minute.
func TestBackupCompressesHistoryRepeats(t *testing.T) {
	rng := mathrand.New(mathrand.NewPCG(1, 2))
	doc := map[string]string{}
	for i := range 900 { // ~70 KiB of distinct-looking entries
		doc[fmt.Sprintf("w%03d", i)] = fmt.Sprintf("sha256:%064x", rng.Uint64())
	}
	var versions [][]byte
	for v := range 1000 {
		doc[fmt.Sprintf("w%03d", v%900)] = fmt.Sprintf("sha256:%064x", rng.Uint64())
		b, _ := json.Marshal(doc)
		versions = append(versions, b)
	}
	snapshot, _ := json.Marshal(versions) // base64 cells, as the store's snapshot
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := SealBackup(&rk.PublicKey, BackupMeta{ClusterID: testCluster, Epoch: 1, Index: 1}, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	one := len(versions[0])
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	_, _ = gw.Write(snapshot)
	_ = gw.Close()
	t.Logf("gzip would store %d KiB", gz.Len()>>10)
	t.Logf("snapshot %d KiB, %d versions of %d KiB, backup %d KiB", len(snapshot)>>10, len(versions), one>>10, len(b.Ciphertext)>>10)
	if len(b.Ciphertext) > 20*one {
		t.Fatalf("backup %d bytes for %d near-identical versions of %d bytes: repeats are not shared", len(b.Ciphertext), len(versions), one)
	}
	plain, err := OpenBackup(rk, b)
	if err != nil || !bytes.Equal(plain, snapshot) {
		t.Fatalf("round trip: %v", err)
	}
}

// Backups written before the switch to zstd (gzip) still open.
func TestOpenBackupReadsGzipBackups(t *testing.T) {
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write([]byte("old snapshot"))
	_ = zw.Close()
	got, err := decompressBackup(z.Bytes())
	if err != nil || string(got) != "old snapshot" {
		t.Fatalf("gzip backup: %q %v", got, err)
	}
	if _, err := decompressBackup([]byte("neither gzip nor zstd")); err == nil {
		t.Fatal("garbage decompressed")
	}
	if _, err := decompressBackup([]byte{0x1f, 0x8b, 0}); err == nil {
		t.Fatal("a broken gzip header decompressed")
	}
}
