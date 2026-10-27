package cdsha

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// fsmWrites applies a mix of every store's writes to f from index i on and
// returns the next index.
func fsmWrites(t *testing.T, f *FSM, i uint64, tag int) uint64 {
	t.Helper()
	at := int64(1_800_000_000_000) + int64(tag)
	for k, e := range []Entry{
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, AtMS: at, Name: "w" + string(rune('a'+tag)), Workload: ptr(mkWorkload(t, tag))}},
		{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "p/" + string(rune('a'+tag)), Value: []byte{byte(tag)}}},
		{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s" + string(rune('a'+tag)), Host: "10.0.0.1", AtMS: at}},
		{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, AtMS: at, Token: "h.p" + string(rune('a'+tag)) + ".s"}},
	} {
		if res, ok := applyAt(f, i+uint64(k), e).(error); ok {
			t.Fatalf("entry %d: %v", i+uint64(k), res)
		}
	}
	return i + 4
}

func ptr[T any](v T) *T { return &v }

func lastCheckpoint(t *testing.T, f *FSM) Point {
	t.Helper()
	cps := f.dig.checkpointsCopy()
	if len(cps) == 0 {
		t.Fatal("no checkpoint")
	}
	return cps[len(cps)-1]
}

// Two replicas that applied the same log report the same chain and state
// digest at a checkpoint, however they got there: one replayed every entry
// and saw a refused command; the other installed a snapshot (a VACUUM INTO
// image) part way and replayed the rest.
func TestCheckpointAgreesAcrossLogReplayAndSnapshot(t *testing.T) {
	_, pub := operatorKey(t)
	a, b := newTestFSM(t, pub), newTestFSM(t, pub)
	i := fsmWrites(t, a, 1, 0)
	if err := restoreCopy(t, a, b); err != nil {
		t.Fatal(err)
	}
	for k := 1; k < 4; k++ {
		for _, f := range []*FSM{a, b} {
			fsmWrites(t, f, i, k)
		}
		i += 4
	}
	// A command every replica refuses alike (a reused token) is part of the
	// log, not a divergence.
	for _, f := range []*FSM{a, b} {
		applyAt(f, i, Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, Token: "h.pa.s"}})
		applyAt(f, i+1, Entry{Kind: KindCheckpoint})
	}
	pa, pb := lastCheckpoint(t, a), lastCheckpoint(t, b)
	if pa != pb || pa.State == "" {
		t.Fatalf("same log, different checkpoints:\n%+v\n%+v", pa, pb)
	}
	// One command applied by one replica only is seen at the next one.
	applyAt(b, i+2, Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "extra", Value: []byte("x")}})
	for _, f := range []*FSM{a, b} {
		applyAt(f, i+3, Entry{Kind: KindCheckpoint})
	}
	if pa, pb := lastCheckpoint(t, a), lastCheckpoint(t, b); pa.Chain == pb.Chain || pa.State == pb.State {
		t.Fatalf("an entry one replica alone applied left the checkpoints equal: %+v %+v", pa, pb)
	}
}

// snapshotBytes is f's snapshot as Persist writes it.
func snapshotBytes(t *testing.T, f *FSM) []byte {
	t.Helper()
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// reencode decodes a snapshot without its checks, changes it, and encodes
// it again with the digests it carried.
func reencode(t *testing.T, body []byte, change func(*snapshot)) []byte {
	t.Helper()
	sn, err := decodeSnapshotRaw(bytes.NewReader(body), Format, false)
	if err != nil {
		t.Fatal(err)
	}
	change(&sn)
	var buf bytes.Buffer
	if err := encodeSnapshot(&buf, sn); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A snapshot whose content is not what its digests name is refused before
// any store changes: by InstallSnapshot (FSM.Restore), by a Restore decree
// (KindRestore), and by the operator's check of a backup.
func TestSnapshotDigestRefusesChangedContent(t *testing.T) {
	_, pub := operatorKey(t)
	src := newTestFSM(t, pub)
	fsmWrites(t, src, 1, 0)
	body := snapshotBytes(t, src)
	other, _, _ := testStores(t)
	if err := other.PutWorkload("rotted", mkWorkload(t, 9)); err != nil {
		t.Fatal(err)
	}
	otherImage, err := other.Dump()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*snapshot){
		"secret value":  func(sn *snapshot) { sn.Secrets[0].Value = []byte("changed") },
		"binding":       func(sn *snapshot) { sn.Bindings[0].Host = "10.9.9.9" },
		"core":          func(sn *snapshot) { sn.Core.Seats = 7 },
		"decree record": func(sn *snapshot) { sn.Decrees = append(sn.Decrees, DecreeRecord{Epoch: 9}) },
		"allowlist":     func(sn *snapshot) { sn.Allowlist = otherImage },
		"state digest":  func(sn *snapshot) { sn.Digests.State = strings.Repeat("0", 64) },
		"no digests":    func(sn *snapshot) { sn.Digests = Digests{} },
	} {
		bad := reencode(t, body, change)
		dst := newTestFSM(t, pub)
		before := dst.allowlist.Digest()
		if err := dst.Restore(io.NopCloser(bytes.NewReader(bad))); !errors.Is(err, ErrSnapshotDigest) {
			t.Errorf("%s: InstallSnapshot took it: %v", name, err)
		}
		if dst.allowlist.Digest() != before || dst.AppliedIndex() != 0 {
			t.Errorf("%s: a refused snapshot changed the replica", name)
		}
		sn, _ := decodeSnapshotRaw(bytes.NewReader(bad), Format, false)
		meta := BackupMeta{ClusterID: sn.Core.ClusterID, Epoch: sn.Core.Epoch, Index: sn.Index, AppliedDecrees: sn.Core.AppliedDecrees, StateDigest: sn.Digests.State}
		if err := ValidateRecoverySnapshot(bad, meta, 0, 0); err == nil {
			t.Errorf("%s: the operator's backup check took it", name)
		}
	}
	dst := newTestFSM(t, pub)
	if err := dst.Restore(io.NopCloser(bytes.NewReader(body))); err != nil {
		t.Fatalf("untouched snapshot: %v", err)
	}
}

// Content that changed under a replica after it applied it (here a write
// through a connection without the digest hooks, as memory or disk
// corruption would) is caught when the replica takes a snapshot: it is not
// shipped, and the replica stops to be re-seeded.
func TestPersistRefusesStateChangedUnderTheReplica(t *testing.T) {
	_, pub := operatorKey(t)
	path := t.TempDir() + "/allowlist.db"
	al, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	f := NewFSM(PreGenesis(testCluster, pub), &al, secrets.NewMemoryStore(8, 4, 64), sandboxledger.New(time.Hour, 8))
	f.core.Policy = f.LocalPolicy()
	fsmWrites(t, f, 1, 0)
	snapshotBytes(t, f) // healthy
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec("UPDATE workload_entry SET entry_json = replace(entry_json, '01\"', '00\"')"); err != nil {
		t.Fatal(err)
	}
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := s.Persist(&memSink{Buffer: &buf}); err == nil {
		t.Fatal("a snapshot of state changed under the replica was persisted")
	}
	if !strings.Contains(f.Stuck(), "no longer matches") {
		t.Fatalf("replica did not stop: %q", f.Stuck())
	}
}

// injectApplied makes r's state machine apply an allowlist write no other
// replica has, at the next index: the effect of hashicorp/raft #695 on the
// replica that applied a write the cluster never committed.
func injectApplied(t *testing.T, r *replica, name string) {
	t.Helper()
	raw, err := json.Marshal(Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpPutWorkload, AtMS: time.Now().UnixMilli(), Name: name, Workload: ptr(mkWorkload(t, 77))}})
	if err != nil {
		t.Fatal(err)
	}
	rf := r.node.r()
	if res, ok := r.node.fsm.Apply(&raft.Log{Index: rf.LastIndex() + 1, Term: rf.CurrentTerm(), Type: raft.LogCommand, Data: raw}).(allowlist.Result); !ok || res.Err != "" {
		t.Fatalf("inject: %#v", res)
	}
}

func holds(r *replica, name string) bool {
	al, _, err := r.al.LoadAll()
	if err != nil {
		return false
	}
	_, ok := al.Workloads[name]
	return ok
}

func followers(c *cluster) []*replica {
	var out []*replica
	for _, r := range c.live() {
		if r.node.r().State() != raft.Leader {
			out = append(out, r)
		}
	}
	return out
}

// A follower that applied an entry the others never had is found at the
// next checkpoint, stops serving and is re-seeded from the leader after its
// restart; the leader and the other follower carry on.
func TestDivergentFollowerIsStoppedAndReseeded(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	fs := followers(c)
	bad, good := fs[0], fs[1]
	injectApplied(t, bad, "X")
	if err := l.al.PutWorkload("after", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	eventually(t, 10*time.Second, "the divergent follower stopped", func() bool { return errors.Is(errFromStuck(bad), ErrDiverged) })
	t.Logf("detected after %s: %s", time.Since(start).Round(time.Millisecond), bad.node.fsm.Stuck())
	if bad.node.Serving() {
		t.Fatal("divergent follower still serves")
	}
	if l.node.fsm.Stuck() != "" || l.node.r().State() != raft.Leader {
		t.Fatalf("one divergent follower unseated the leader: %q", l.node.fsm.Stuck())
	}
	if st := l.node.Status(); !strings.Contains(st.Divergence, bad.node.ID()) {
		t.Fatalf("leader status does not name the divergent replica: %q", st.Divergence)
	}
	eventually(t, 5*time.Second, "the other follower serves", good.node.Serving)
	c.stopReplica(bad)
	again := c.start(bad.name, "m1")
	eventually(t, 20*time.Second, "restarted replica serves", again.node.Serving)
	if holds(again, "X") || !holds(again, "after") {
		t.Fatal("restarted replica does not hold the majority's state")
	}
	if err := l.al.PutWorkload("later", mkWorkload(t, 2)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * testTiming.Checkpoint)
	for _, r := range c.live() {
		if r.node.fsm.Stuck() != "" {
			t.Fatalf("%s stuck after the re-seed: %s", r.name, r.node.fsm.Stuck())
		}
	}
}

func errFromStuck(r *replica) error {
	if s := r.node.fsm.Stuck(); strings.HasPrefix(s, ErrDiverged.Error()) {
		return ErrDiverged
	}
	return nil
}

// A leader that applied an entry no follower has is outvoted by the two
// followers: it stops, hands off leadership, and no backup sealed after the
// checkpoint that found it holds the entry.
func TestDivergentLeaderStepsDown(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	injectApplied(t, l, "X")
	_ = l.al.PutWorkload("after", mkWorkload(t, 1))
	eventually(t, 10*time.Second, "the divergent leader stopped", func() bool { return errors.Is(errFromStuck(l), ErrDiverged) })
	t.Logf("leader stopped: %s", l.node.fsm.Stuck())
	stoppedAt := time.Now()
	var nl *replica
	eventually(t, 10*time.Second, "a new leader", func() bool { nl = c.leader(); return nl != nil && nl != l })
	if holds(nl, "X") {
		t.Fatal("the new leader holds the divergent entry")
	}
	// A new leader serves once it has seen the decree objects (fence.go).
	eventually(t, 5*time.Second, "the new leader unfenced", func() bool { return nl.node.Status().Fenced == nil })
	if err := nl.al.PutWorkload("later", mkWorkload(t, 2)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "a backup from the new leader", func() bool {
		b, ok := c.backups.get()
		return ok && b.Meta.TakenAtMS > stoppedAt.UnixMilli()
	})
	b, _ := c.backups.get()
	body, err := OpenBackup(c.recKey, b)
	if err != nil {
		t.Fatal(err)
	}
	if hasImageWorkload(t, body, "X") {
		t.Fatal("a backup after the leader stopped holds the divergent entry")
	}
	for _, r := range c.live() {
		if r != l && r.node.Serving() && holds(r, "X") {
			t.Fatalf("%s serves the divergent entry", r.name)
		}
	}
}

// hasImageWorkload reports whether the allowlist in snapshot body holds name.
func hasImageWorkload(t *testing.T, body []byte, name string) bool {
	t.Helper()
	sn, err := decodeSnapshot(bytes.NewReader(body), Format, false)
	if err != nil {
		t.Fatal(err)
	}
	al, _, _ := testStores(t)
	if err := al.Restore(sn.Allowlist); err != nil {
		t.Fatal(err)
	}
	doc, _, err := al.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	_, ok := doc.Workloads[name]
	return ok
}

// With one voter cut off, a follower that differs from the leader is one
// against one: no majority says which is wrong. The leader raises the alarm,
// stops no one and seals no backup; once the third voter reports, the
// majority decides.
func TestNoMajorityOnlyAlarms(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	fs := followers(c)
	bad, away := fs[0], fs[1]
	c.partition(away.name, true)
	injectApplied(t, bad, "X")
	if err := l.al.PutWorkload("after", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "alarm raised", func() bool { return strings.HasPrefix(l.node.Status().Divergence, "no majority") })
	calls := c.backups.attempts()
	time.Sleep(20 * testTiming.Backup)
	if bad.node.fsm.Stuck() != "" || l.node.fsm.Stuck() != "" {
		t.Fatalf("a replica was stopped without a majority: leader %q follower %q", l.node.fsm.Stuck(), bad.node.fsm.Stuck())
	}
	if got := c.backups.attempts(); got != calls {
		t.Fatalf("%d backups sealed while the divergence is unresolved", got-calls)
	}
	c.partition(away.name, false)
	eventually(t, 15*time.Second, "the majority decides", func() bool { return errors.Is(errFromStuck(bad), ErrDiverged) })
	eventually(t, 10*time.Second, "alarm cleared", func() bool { return !strings.HasPrefix(l.node.Status().Divergence, "no majority") })
	if l.node.fsm.Stuck() != "" {
		t.Fatalf("leader stopped: %s", l.node.fsm.Stuck())
	}
}
