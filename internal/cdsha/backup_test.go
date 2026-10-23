package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
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
	snap := make([]byte, 5000)
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
	// Only the recovery key opens it, and its metadata is authenticated.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := OpenBackup(other, got); err == nil || !strings.Contains(err.Error(), "recovery key") {
		t.Fatalf("opened with another key: %v", err)
	}
	relabeled := got
	relabeled.Meta.Epoch++
	if _, err := OpenBackup(rk, relabeled); err == nil {
		t.Fatal("opened with changed metadata")
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
	enc := func(sn snapshot) []byte {
		var b bytes.Buffer
		if err := encodeSnapshot(&b, sn); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}
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
	// A crashed writer: its parts are there, its manifest never was. And a
	// newer writer (a new leader) still writing its parts.
	crashed := backupManifest{Gen: "e1-i6-dead", Parts: 2}
	newer := backupManifest{Gen: "e1-i9-cccc", Parts: 1}
	for _, m := range []backupManifest{crashed, newer} {
		for i := range m.Parts {
			cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: m.partName(testCluster, i), Namespace: "decrees",
				Labels: map[string]string{LabelBackup: testCluster}}, BinaryData: map[string][]byte{keyPart: []byte("junk")}}
			if _, err := kube.CoreV1().ConfigMaps("decrees").Create(ctx, cm, metav1.CreateOptions{}); err != nil {
				t.Fatal(err)
			}
		}
	}
	got, err := st.GetBackup(ctx)
	if err != nil || got.Meta.Index != 5 {
		t.Fatalf("the stored backup broke under a crashed write: %v", err)
	}
	// The next backup goes in and sweeps the crashed parts, not the newer
	// writer's, which may still switch the manifest to them.
	if err := st.PutBackup(ctx, seal(7)); err != nil {
		t.Fatal(err)
	}
	parts := func() (names []string) {
		list, _ := kube.CoreV1().ConfigMaps("decrees").List(ctx, metav1.ListOptions{})
		for _, cm := range list.Items {
			names = append(names, cm.Name)
		}
		return names
	}
	if names := strings.Join(parts(), " "); strings.Contains(names, crashed.Gen) || !strings.Contains(names, newer.Gen) {
		t.Fatalf("after the sweep: %s", names)
	}
	// A write that fails part way deletes its own parts and only those.
	failing := true
	kube.PrependReactor("create", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		name := a.(k8stesting.CreateAction).GetObject().(*corev1.ConfigMap).Name
		return failing && strings.HasSuffix(name, "-1"), nil, errors.New("api down")
	})
	if err := st.PutBackup(ctx, seal(8)); err == nil {
		t.Fatal("a failed part write succeeded")
	}
	failing = false
	if names := strings.Join(parts(), " "); strings.Contains(names, "-e1-i8-") || !strings.Contains(names, newer.Gen) {
		t.Fatalf("after a failed write: %s", names)
	}
	// A writer whose manifest changed under it loses: the update is
	// conditional on the manifest it checked. The fake keeps no versions,
	// so the reactors play the API: every read is version "seen", and
	// another writer has stored since, so an update made at "seen" conflicts
	// (one made at no version would overwrite).
	kube.PrependReactor("get", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		obj, err := kube.Tracker().Get(corev1.SchemeGroupVersion.WithResource("configmaps"), "decrees", a.(k8stesting.GetAction).GetName())
		if err != nil {
			return true, nil, err
		}
		cm := obj.(*corev1.ConfigMap).DeepCopy()
		cm.ResourceVersion = "seen"
		return true, cm, nil
	})
	kube.PrependReactor("update", "configmaps", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.(k8stesting.UpdateAction).GetObject().(*corev1.ConfigMap).ResourceVersion == "seen" {
			return true, nil, apierrors.NewConflict(schema.GroupResource{Resource: "configmaps"}, BackupName(testCluster), errors.New("changed"))
		}
		return false, nil, nil
	})
	if err := st.PutBackup(ctx, seal(9)); !errors.Is(err, ErrBackupNotNewer) {
		t.Fatalf("a raced write: %v", err)
	}
	if got, err := st.GetBackup(ctx); err != nil || got.Meta.Index != 7 {
		t.Fatalf("a raced write damaged the stored backup: %v %v", got.Meta.Index, err)
	}
}

// Backups sealed to, or opened with, a key off P-256 fail closed.
func TestBackupRefusesOtherCurves(t *testing.T) {
	meta := BackupMeta{ClusterID: testCluster, Epoch: 1, Index: 2}
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SealBackup(&p224.PublicKey, meta, []byte("snap")); err == nil {
		t.Fatal("sealed to a P-224 key")
	}
	if _, err := SealBackup(&p384.PublicKey, meta, []byte("snap")); err == nil {
		t.Fatal("sealed to a P-384 key")
	}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, err := SealBackup(&rk.PublicKey, meta, []byte("snap"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBackup(p224, b); err == nil {
		t.Fatal("opened with a P-224 key")
	}
	if _, err := OpenBackup(p384, b); err == nil {
		t.Fatal("opened with a P-384 key")
	}
	if _, err := OpenBackup(rk, Backup{Meta: meta, Ciphertext: b.Ciphertext[:10]}); err == nil {
		t.Fatal("opened a truncated backup")
	}
	if got, err := OpenBackup(rk, b); err != nil || string(got) != "snap" {
		t.Fatalf("round trip %q: %v", got, err)
	}
}

// Reads of backups and decrees report the API's errors.
func TestDecreeStoreListErrors(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewClientset()
	kube.PrependReactor("list", "configmaps", failOn("list", nil))
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	if _, err := st.GetBackup(ctx); err == nil {
		t.Fatal("a backup read through a failing API")
	}
	if _, err := st.PendingDecrees(ctx); err == nil {
		t.Fatal("decrees listed through a failing API")
	}
}

func TestBackupFromConfigMapsRefusesAnotherClustersManifest(t *testing.T) {
	ctx := context.Background()
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b, _ := SealBackup(&rk.PublicKey, BackupMeta{ClusterID: "other", Epoch: 1, Index: 1}, []byte("snap"))
	kube := fake.NewClientset()
	st := KubeDecrees{Client: kube, Namespace: "decrees", ClusterID: testCluster}
	if err := st.PutBackup(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetBackup(ctx); err == nil || !strings.Contains(err.Error(), "another cluster") {
		t.Fatalf("a manifest for another cluster: %v", err)
	}
	list, _ := kube.CoreV1().ConfigMaps("decrees").List(ctx, metav1.ListOptions{})
	var man corev1.ConfigMap
	for _, cm := range list.Items {
		if cm.Name == BackupName(testCluster) {
			man = cm
		}
	}
	man.Data[keyBackup] = `{"meta":{"cluster_id":"c1"},"parts":0}`
	if _, err := BackupFromConfigMaps(testCluster, []corev1.ConfigMap{man}); err == nil {
		t.Fatal("a manifest naming no parts")
	}
}
