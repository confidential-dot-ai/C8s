package cdsha

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A replica that meets an entry it cannot read stops serving instead of
// skipping it: Raft would move on, and the replica would serve state the
// rest of the group does not have.
func TestFSMStopsOnEntryItCannotRead(t *testing.T) {
	_, opPub := operatorKey(t)
	for name, e := range map[string]Entry{
		"newer format": {Kind: KindSecret, Format: Format + 1, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}},
		"unknown kind": {Kind: "from-the-future"},
		"newer agreed": {Kind: KindFormat, SetFormat: Format + 1},
		"no payload":   {Kind: KindSecret},
	} {
		t.Run(name, func(t *testing.T) {
			al, sec, led := testStores(t)
			f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
			raw, _ := json.Marshal(e)
			res := f.Apply(&raft.Log{Index: 3, Type: raft.LogCommand, Data: raw})
			if _, ok := res.(error); !ok || f.Stuck() == "" {
				t.Fatalf("applied %v, stuck %q", res, f.Stuck())
			}
			if f.AppliedIndex() != 3 {
				t.Fatal("the index still moves: Raft has moved on")
			}
		})
	}
	// An entry it reads is not a reason to stop, nor is a secret store refusal.
	al, sec, led := testStores(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	raw, _ := json.Marshal(Entry{Kind: KindFormat, SetFormat: Format})
	if res := f.Apply(&raft.Log{Index: 1, Type: raft.LogCommand, Data: raw}); res != nil || f.Stuck() != "" {
		t.Fatalf("current format: %v, stuck %q", res, f.Stuck())
	}
}

// The agreed format only rises, and a snapshot carries it: a replica that
// reads less refuses the snapshot rather than install state it cannot
// follow.
func TestSnapshotInANewerFormatIsRefused(t *testing.T) {
	_, opPub := operatorKey(t)
	al, sec, led := testStores(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	f.readable = Format + 1
	apply := func(i uint64, e Entry) {
		t.Helper()
		raw, _ := json.Marshal(e)
		if res := f.Apply(&raft.Log{Index: i, Type: raft.LogCommand, Data: raw}); res != nil {
			t.Fatalf("entry %d: %v", i, res)
		}
	}
	apply(1, Entry{Kind: KindFormat, SetFormat: Format + 1})
	apply(2, Entry{Kind: KindFormat, SetFormat: Format}) // never lowers
	if got := f.Core().format(); got != Format+1 {
		t.Fatalf("agreed format %d", got)
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
	old := NewFSM(PreGenesis(testCluster, opPub), al2, sec2, led2)
	if err := old.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("older replica installed a newer snapshot: %v", err)
	}
	al3, sec3, led3 := testStores(t)
	same := NewFSM(PreGenesis(testCluster, opPub), al3, sec3, led3)
	same.readable = Format + 1
	if err := same.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err != nil || same.Core().format() != Format+1 {
		t.Fatalf("same release: %v, format %d", err, same.Core().format())
	}
}

// A rollout: old and new replicas share the group in the old format; the
// format rises only once the last old replica is gone, and from then on a
// replica of the old release cannot join.
func TestFormatRisesOnlyWhenEveryMemberReadsIt(t *testing.T) {
	c := newCluster(t, 3)
	next := Format + 1
	c.reads["n0"], c.reads["n1"] = next, next
	c.genesis("n0", "n1", "n2")
	if _, err := c.nodes["n0"].sec.Put(t.Context(), "/before", []byte("v")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * testTiming.Tick)
	for _, r := range c.live() {
		if f := r.node.Core().format(); f != Format {
			t.Fatalf("%s: format %d with an old replica in the group", r.name, f)
		}
	}
	// Roll the old replica to the new release.
	c.stopReplica(c.nodes["n2"])
	c.reads["n2"] = next
	c.start("n2", "m1")
	c.settled(15 * time.Second)
	eventually(t, 10*time.Second, "format raised everywhere", func() bool {
		for _, r := range c.live() {
			if r.node.Core().format() != next {
				return false
			}
		}
		return true
	})
	for _, r := range c.live() {
		if st := r.node.Status(); !st.Serving || st.Stuck != "" {
			t.Fatalf("%s after the raise: %+v", r.name, st)
		}
		eventually(t, 3*time.Second, "secret on "+r.name, func() bool { v, _ := r.sec.Get(t.Context(), "/before"); return string(v) == "v" })
	}
	// A replica of the old release is refused and never serves.
	c.reads["n3"] = Format
	old := c.start("n3", "m1")
	time.Sleep(2 * time.Second)
	if st := old.node.Status(); st.Joined || st.Serving {
		t.Fatalf("old release joined after the raise: %+v", st)
	}
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	if st := l.node.Status(); len(st.Voters)+len(st.NonVoters) != 3 {
		t.Fatalf("membership changed: %+v", st)
	}
}

// An entry that does not decode stops the replica too.
func TestFSMStopsOnUndecodableEntry(t *testing.T) {
	_, opPub := operatorKey(t)
	al, sec, led := testStores(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	if _, ok := f.Apply(&raft.Log{Index: 1, Type: raft.LogCommand, Data: []byte("{")}).(error); !ok || f.Stuck() == "" {
		t.Fatal("undecodable entry did not stop the replica")
	}
	// Non-command entries (configuration, barriers) are not the FSM's.
	g := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	if res := g.Apply(&raft.Log{Index: 2, Type: raft.LogConfiguration}); res != nil || g.Stuck() != "" || g.AppliedIndex() != 2 {
		t.Fatalf("configuration entry: %v %q", res, g.Stuck())
	}
}
