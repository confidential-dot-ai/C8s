package cdsha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A replica refuses a snapshot older than what it applied (Raft would
// install it and roll a serving replica back), and takes the index of a
// newer one it installs.
func TestFSMRefusesOlderSnapshot(t *testing.T) {
	_, opPub := operatorKey(t)
	al, sec, led := testStores(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	put := func(index uint64, v string) {
		t.Helper()
		raw, _ := json.Marshal(Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte(v)}})
		if res := f.Apply(&raft.Log{Index: index, Type: raft.LogCommand, Data: raw}); res != nil {
			if err, ok := res.(error); ok {
				t.Fatal(err)
			}
		}
	}
	snapshotAt := func() []byte {
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
	value := func(fsm *FSM) string {
		v, _ := fsm.secrets.Get(context.Background(), "/p")
		return string(v)
	}
	put(2, "old")
	old := snapshotAt()
	put(5, "new")
	if err := f.Restore(io.NopCloser(bytes.NewReader(old))); !errors.Is(err, ErrStaleSnapshot) {
		t.Fatalf("older snapshot: %v", err)
	}
	if value(f) != "new" || f.AppliedIndex() != 5 {
		t.Fatalf("rolled back to %q at %d", value(f), f.AppliedIndex())
	}
	// A newer snapshot installs and moves the applied index.
	put(9, "newer")
	newer := snapshotAt()
	al2, sec2, led2 := testStores(t)
	g := NewFSM(PreGenesis(testCluster, opPub), al2, sec2, led2)
	if err := g.Restore(io.NopCloser(bytes.NewReader(old))); err != nil || g.AppliedIndex() != 2 {
		t.Fatalf("fresh replica, snapshot at 2: %v, applied %d", err, g.AppliedIndex())
	}
	if err := g.Restore(io.NopCloser(bytes.NewReader(newer))); err != nil || g.AppliedIndex() != 9 || value(g) != "newer" {
		t.Fatalf("newer snapshot: %v, applied %d, value %q", err, g.AppliedIndex(), value(g))
	}
	// The same index again (Raft restarting from its own snapshot) is fine.
	if err := g.Restore(io.NopCloser(bytes.NewReader(newer))); err != nil {
		t.Fatalf("snapshot at the applied index: %v", err)
	}
}
