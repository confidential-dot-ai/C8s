package cdsha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// historySnapshot is a snapshot whose allowlist history holds versions near
// copies of one ~70 KiB document, as a cluster's does, and the size of
// those documents.
func historySnapshot(format uint32, versions int) (snapshot, int) {
	rng := rand.New(rand.NewPCG(3, 4))
	doc := map[string]string{}
	for i := range 900 {
		doc[fmt.Sprintf("w%03d", i)] = fmt.Sprintf("sha256:%064x", rng.Uint64())
	}
	var rows []map[string]any
	size := 0
	for v := range versions {
		doc[fmt.Sprintf("w%03d", v%900)] = fmt.Sprintf("sha256:%064x", rng.Uint64())
		b, _ := json.Marshal(doc)
		size += len(b)
		rows = append(rows, map[string]any{"digest": fmt.Sprintf("d%d", v), "body": b})
	}
	return snapshot{Core: Core{ClusterID: testCluster, Format: format}, Allowlist: allowlist.Snapshot{"journal_object": rows}}, size
}

// Snapshots share the history's repeats (zstd, long window), and a replica
// refuses one in a format it does not read.
func TestSnapshotCompression(t *testing.T) {
	sn, size := historySnapshot(Format, 300)
	var buf bytes.Buffer
	if err := encodeSnapshot(&buf, sn); err != nil {
		t.Fatal(err)
	}
	got, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), Format, false)
	if err != nil || len(got.Allowlist["journal_object"]) != 300 {
		t.Fatalf("round trip: %v (%d rows)", err, len(got.Allowlist["journal_object"]))
	}
	if head, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), Format, true); err != nil || len(head.Allowlist) != 0 || head.Core.ClusterID != testCluster {
		t.Fatalf("header only: %v, %+v", err, head.Core)
	}
	if buf.Len()*50 > size {
		t.Fatalf("snapshot of %d bytes for %d bytes of near copies: repeats not shared", buf.Len(), size)
	}
	for _, format := range []uint32{Format + 1, baseFormat - 1} {
		buf.Reset()
		sn, _ := historySnapshot(format, 2)
		_ = encodeSnapshot(&buf, sn)
		if _, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), Format, false); err == nil {
			t.Fatalf("took a format %d snapshot", format)
		}
	}
	for _, bad := range [][]byte{{0x28, 0xb5, 0x2f, 0xfd, 1, 2, 3}, []byte(`{"core":{}}`)} {
		if _, err := decodeSnapshot(bytes.NewReader(bad), Format, false); err == nil {
			t.Fatalf("garbage %x decoded", bad)
		}
	}
}

// A replica refuses a snapshot older than what it applied (Raft would
// install it and roll a serving replica back), and takes the index of a
// newer one it installs.
func TestFSMRefusesOlderSnapshot(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	put := func(index uint64, v string) {
		t.Helper()
		if res := applyAt(f, index, Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte(v)}}); res != nil {
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
	g := newTestFSM(t, opPub)
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
