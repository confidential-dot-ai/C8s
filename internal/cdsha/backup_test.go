package cdsha

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
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
	if err := st.PutBackup(ctx, b); err != nil { // update in place
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
	if len(items) < 3 {
		t.Fatalf("expected several parts, got %d objects", len(items))
	}
	if _, err := BackupFromConfigMaps("other", items); err == nil {
		t.Fatal("a backup for another cluster")
	}
	for i := range items {
		if items[i].Name == BackupName(testCluster)+"-1" {
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
