package cdsha

import (
	"bytes"
	"crypto/x509"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
)

// An operator-authorized boundary snapshot is reachable through real FSM Apply.
// Exhausting the epoch must refuse the next decree without mutating state.
func TestNightAuthEpochBoundary(t *testing.T) {
	op, pub := operatorKey(t)
	f := newTestFSM(t, pub)
	ca := mustCA(t)
	der, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	image, err := f.allowlist.Dump()
	if err != nil {
		t.Fatal(err)
	}
	sn := snapshot{Format: Format, Key: der, Allowlist: image, Core: Core{
		Policy: f.LocalPolicy(), ClusterID: testCluster, OperatorPubKey: pub,
		RootCert: ca.Cert.Raw, Epoch: math.MaxUint64 - 1, Format: Format, Measurements: []string{"m1"},
	}}
	var buf bytes.Buffer
	if err := encodeSnapshot(&buf, sn); err != nil {
		t.Fatal(err)
	}
	sd := signDecree(t, op, Decree{Kind: Restore, IntentID: "boundary-restore", BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(buf.Bytes())})
	now := time.Now().UnixMilli()
	restored := applyAt(f, 1, Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: now, Snapshot: buf.Bytes()}}).(DecreeResult)
	if restored.Err != "" || restored.Epoch != math.MaxUint64 {
		t.Fatalf("restore boundary: %+v", restored)
	}
	before, records, beforeCA := f.Core(), f.Decrees(), f.CA()
	next := signDecree(t, op, Decree{Kind: SetVoters, IntentID: "boundary-next", BaseEpoch: math.MaxUint64, Voters: 3})
	result := applyAt(f, 2, Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: next, AtMS: now}}).(DecreeResult)
	if result.Err == "" || !strings.Contains(result.Err, "epoch") {
		t.Fatalf("exhausted epoch decree not refused: %+v; core=%+v", result, f.Core())
	}
	if result.Epoch != math.MaxUint64 || !reflect.DeepEqual(f.Core(), before) || !reflect.DeepEqual(f.Decrees(), records) || f.CA() != beforeCA || f.Stuck() != "" {
		t.Fatal("refusal mutated state or stopped FSM")
	}
	// The immediately preceding ordinary transition remains available.
	f2 := newTestFSM(t, pub)
	sn.Core.Epoch = math.MaxUint64 - 2
	buf.Reset()
	if err := encodeSnapshot(&buf, sn); err != nil {
		t.Fatal(err)
	}
	sd2 := signDecree(t, op, Decree{Kind: Restore, IntentID: "preceding-restore", BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(buf.Bytes())})
	r2 := applyAt(f2, 1, Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd2, AtMS: now, Snapshot: buf.Bytes()}}).(DecreeResult)
	if r2.Err != "" || r2.Epoch != math.MaxUint64-1 {
		t.Fatalf("preceding restore: %+v", r2)
	}
	d2 := signDecree(t, op, Decree{Kind: SetVoters, IntentID: "preceding-next", BaseEpoch: math.MaxUint64 - 1, Voters: 3})
	r2 = applyAt(f2, 2, Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: d2, AtMS: now}}).(DecreeResult)
	if r2.Err != "" || r2.Epoch != math.MaxUint64 || f2.Core().Seats != 3 {
		t.Fatalf("last valid increment: %+v", r2)
	}

}
