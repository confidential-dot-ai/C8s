package cdsha

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestCheckDecree(t *testing.T) {
	opKey, opPub := operatorKey(t)
	tail := Core{ClusterID: testCluster, OperatorPubKey: opPub, RootCert: []byte("ca"), Measurements: []string{"m1"}, AppliedDecrees: []string{"used"}}
	now := time.Now()
	good := Decree{ClusterID: testCluster, IntentID: "i1", BaseEpoch: 0, ExpiresAt: now.Add(time.Hour), Kind: UpdateMeasurements, Measurements: []string{"m1", "m2"}}
	sign := func(d Decree) SignedDecree {
		sd, err := SignDecree(d, opKey)
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	if err := CheckDecree(sign(good), tail, now); err != nil {
		t.Fatalf("good decree: %v", err)
	}
	bad := map[string]SignedDecree{}
	for name, f := range map[string]func(*Decree){
		"other cluster": func(d *Decree) { d.ClusterID = "tenant-b" },
		"replayed":      func(d *Decree) { d.IntentID = "used" },
		"stale base":    func(d *Decree) { d.BaseEpoch = 7 },
		"expired":       func(d *Decree) { d.ExpiresAt = now.Add(-time.Second) },
		"empty set":     func(d *Decree) { d.Measurements = nil },
		"unknown kind":  func(d *Decree) { d.Kind = "Nuke" },
	} {
		d := good
		f(&d)
		bad[name] = sign(d)
	}
	forged := sign(good)
	forged.Decree.Measurements = []string{"evil"}
	bad["field changed after signing"] = forged
	otherKey, _ := operatorKey(t)
	wrongSigner, _ := SignDecree(good, otherKey)
	bad["wrong signer"] = wrongSigner
	for name, sd := range bad {
		if err := CheckDecree(sd, tail, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	noOp := tail
	noOp.OperatorPubKey = nil
	if err := CheckDecree(sign(good), noOp, now); err != ErrNoOperatorKey {
		t.Errorf("cluster without operator key accepted a decree (G5): %v", err)
	}
	// Genesis: only against a keyless cluster, and never with measurements.
	g := Decree{ClusterID: testCluster, IntentID: "g1", ExpiresAt: now.Add(time.Hour), Kind: Genesis, BootstrapNode: "n0"}
	if err := CheckDecree(sign(g), PreGenesis(testCluster, opPub), now); err != nil {
		t.Errorf("genesis against a keyless cluster: %v", err)
	}
	if err := CheckDecree(sign(g), tail, now); err == nil {
		t.Error("genesis accepted by a cluster that already has a key")
	}
	g.Measurements = []string{"m1"}
	if err := CheckDecree(sign(g), PreGenesis(testCluster, opPub), now); err == nil {
		t.Error("genesis with measurements accepted")
	}
	g.Measurements, g.BootstrapNode = nil, ""
	if err := CheckDecree(sign(g), PreGenesis(testCluster, opPub), now); err == nil {
		t.Error("genesis without a bootstrap node accepted")
	}
	u := good
	u.BootstrapNode = "n0"
	if err := CheckDecree(sign(u), tail, now); err == nil {
		t.Error("a non-Genesis decree naming a bootstrap node accepted")
	}
}

// The decree record is bounded, oldest first out, and snapshots carry it.
func TestDecreeRecordBound(t *testing.T) {
	_, opPub := operatorKey(t)
	al, sec, led := testStores(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	f.mu.Lock()
	for i := range maxDecreeRecord + 10 {
		f.record(SignedDecree{Decree: Decree{IntentID: "d"}}, int64(i), uint64(i))
	}
	f.mu.Unlock()
	rec := f.Decrees()
	if len(rec) != maxDecreeRecord || rec[0].Epoch != 10 {
		t.Fatalf("bound: %d records, first epoch %d", len(rec), rec[0].Epoch)
	}
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	al2, sec2, led2 := testStores(t)
	g := NewFSM(PreGenesis(testCluster, opPub), al2, sec2, led2)
	if err := g.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err != nil || len(g.Decrees()) != maxDecreeRecord {
		t.Fatalf("restore: %v, %d records", err, len(g.Decrees()))
	}
}
