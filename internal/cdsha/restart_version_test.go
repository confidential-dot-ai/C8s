package cdsha

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"strconv"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// restartFixture is a joined FSM at a known version, and the backup of it
// that a later Restore installs.
type restartFixture struct {
	t     *testing.T
	op    *ecdsa.PrivateKey
	pub   []byte
	f     *FSM
	index uint64
}

func newRestartFixture(t *testing.T, genesisAt int64) *restartFixture {
	t.Helper()
	op, pub := operatorKey(t)
	x := &restartFixture{t: t, op: op, pub: pub, f: newTestFSM(t, pub)}
	ca := mustCA(t)
	key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	g := DecreeEntry{Policy: x.f.LocalPolicy(), Decree: signDecree(t, op, Decree{Kind: Genesis, BootstrapNode: "n0", GenesisCA: caFP(ca)}),
		AtMS: genesisAt, Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: key}
	x.apply(Entry{Kind: KindDecree, Decree: &g})
	return x
}

func (x *restartFixture) apply(e Entry) any {
	x.t.Helper()
	x.index++
	res := applyAt(x.f, x.index, e)
	if r, ok := res.(DecreeResult); ok && r.Err != "" {
		x.t.Fatalf("entry %d: %s", x.index, r.Err)
	}
	if r, ok := res.(allowlist.Result); ok && r.Error() != nil {
		x.t.Fatalf("entry %d: %v", x.index, r.Error())
	}
	return res
}

// write puts n workload entries, each one allowlist version.
func (x *restartFixture) write(n int) {
	x.t.Helper()
	for range n {
		w := mkWorkload(x.t, int(x.index))
		x.apply(Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, Name: fmt.Sprintf("w%d", x.index), Workload: &w, AtMS: time.Now().UnixMilli()}})
	}
}

func (x *restartFixture) backup() []byte {
	x.t.Helper()
	s, err := x.f.Snapshot()
	if err != nil {
		x.t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		x.t.Fatal(err)
	}
	return buf.Bytes()
}

func version(t *testing.T, f *FSM) uint64 {
	t.Helper()
	v, err := f.allowlist.Version()
	if err != nil {
		t.Fatal(err)
	}
	return mustUint(t, v)
}

func mustUint(t *testing.T, v string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The allowlist version is what node enforcers order documents by: they
// ignore a lower one and settle an equal one with 304. A cluster that starts
// again (Restore of a backup, Recover on a survivor that lacks writes, a new
// Genesis) must serve a version above every one served before, so the
// writes an operator applies again reach the nodes.
func TestRestartRaisesAllowlistVersion(t *testing.T) {
	genesisAt := time.Now().Add(-time.Hour).UnixMilli()
	x := newRestartFixture(t, genesisAt)
	if v := version(t, x.f); v < uint64(genesisAt) {
		t.Errorf("version %d after Genesis at %d: a node that served an earlier cluster would ignore it", v, genesisAt)
	}
	x.write(3)
	backup := x.backup()
	backupVersion := version(t, x.f)
	x.write(3)
	served := version(t, x.f)

	// Total loss; Restore the backup on a fresh replica.
	restoreAt := time.Now().UnixMilli()
	fresh := newTestFSM(t, x.pub)
	sd := signDecree(t, x.op, Decree{Kind: Restore, BootstrapNode: "n0", SnapshotSHA256: SnapshotSHA256(backup)})
	res := applyAt(fresh, 1, Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: restoreAt, Snapshot: backup}}).(DecreeResult)
	if res.Err != "" {
		t.Fatal(res.Err)
	}
	restored := version(t, fresh)
	if restored <= served || restored <= backupVersion || restored < uint64(restoreAt) {
		t.Errorf("restored version %d: served before the loss %d, backup %d, restore at %d", restored, served, backupVersion, restoreAt)
	}
	if fresh.Stuck() != "" {
		t.Fatal(fresh.Stuck())
	}

	// Recover on the old survivor x: its image may lack writes the lost
	// majority served, so the version moves past the Recover's time.
	recoverAt := restoreAt + 1000
	before := version(t, x.f)
	rd := signDecree(t, x.op, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: x.f.Core().Epoch})
	x.apply(Entry{Kind: KindDecree, Decree: &DecreeEntry{Decree: rd, AtMS: recoverAt}})
	if v := version(t, x.f); v <= before || v < uint64(recoverAt) {
		t.Errorf("version %d after Recover at %d (before %d)", v, recoverAt, before)
	}

	// The raise is part of the agreed state: a replica that installs the
	// restored replica's snapshot serves the same version and content.
	joiner := newTestFSM(t, x.pub)
	if err := restoreCopy(t, fresh, joiner); err != nil {
		t.Fatal(err)
	}
	if version(t, joiner) != restored || joiner.allowlist.Digest() != fresh.allowlist.Digest() {
		t.Fatalf("joiner version %d digest differs: want %d", version(t, joiner), restored)
	}
}

// Ordinary writes still add one: the raise applies only at a restart.
func TestWriteAddsOneToTheVersion(t *testing.T) {
	x := newRestartFixture(t, time.Now().UnixMilli())
	v := version(t, x.f)
	x.write(2)
	if got := version(t, x.f); got != v+2 {
		t.Fatalf("version %d after two writes from %d", got, v)
	}
}
