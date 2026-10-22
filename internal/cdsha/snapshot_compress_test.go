package cdsha

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// historySnapshot is a snapshot whose allowlist history holds versions near
// copies of one ~70 KiB document, as a cluster's does.
func historySnapshot(t *testing.T, format uint32, versions int) snapshot {
	t.Helper()
	rng := rand.New(rand.NewPCG(3, 4))
	doc := map[string]string{}
	for i := range 900 {
		doc[fmt.Sprintf("w%03d", i)] = fmt.Sprintf("sha256:%064x", rng.Uint64())
	}
	var rows []map[string]any
	for v := range versions {
		doc[fmt.Sprintf("w%03d", v%900)] = fmt.Sprintf("sha256:%064x", rng.Uint64())
		b, _ := json.Marshal(doc)
		rows = append(rows, map[string]any{"digest": fmt.Sprintf("d%d", v), "body": b})
	}
	return snapshot{Core: Core{ClusterID: testCluster, Format: format}, Allowlist: allowlist.Snapshot{"journal_object": rows}}
}

// Format 2 snapshots share the history's repeats (zstd, long window); format
// 1 snapshots stay gzip, which every release reads. Both decode.
func TestSnapshotCompressionByFormat(t *testing.T) {
	sizes := map[uint32]int{}
	for _, format := range []uint32{1, 2} {
		sn := historySnapshot(t, format, 300)
		var buf bytes.Buffer
		if err := encodeSnapshot(&buf, sn); err != nil {
			t.Fatal(err)
		}
		gz := buf.Len() > 1 && buf.Bytes()[0] == 0x1f && buf.Bytes()[1] == 0x8b
		if gz != (format == 1) || (format == 2 && !bytes.HasPrefix(buf.Bytes(), zstdMagic)) {
			t.Fatalf("format %d snapshot: gzip=%v, starts %x", format, gz, buf.Bytes()[:4])
		}
		got, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), Format)
		if err != nil || len(got.Allowlist["journal_object"]) != 300 || got.Core.format() != format {
			t.Fatalf("format %d round trip: %v (%d rows)", format, err, len(got.Allowlist["journal_object"]))
		}
		sizes[format] = buf.Len()
	}
	t.Logf("300 versions of a ~70 KiB document: gzip %d KiB, zstd %d KiB", sizes[1]>>10, sizes[2]>>10)
	if sizes[2]*10 > sizes[1] {
		t.Fatalf("a format 2 snapshot (%d) is not much smaller than gzip (%d): repeats not shared", sizes[2], sizes[1])
	}
	// A replica that reads only format 1 refuses a format 2 snapshot.
	var buf bytes.Buffer
	_ = encodeSnapshot(&buf, historySnapshot(t, 2, 2))
	if _, err := decodeSnapshot(bytes.NewReader(buf.Bytes()), 1); err == nil {
		t.Fatal("a format 1 reader took a format 2 snapshot")
	}
	// Garbage behind either magic is an error, not an empty snapshot.
	for _, bad := range [][]byte{append(append([]byte{}, zstdMagic...), 1, 2, 3), {0x1f, 0x8b, 0}} {
		if _, err := decodeSnapshot(bytes.NewReader(bad), Format); err == nil {
			t.Fatalf("garbage %x decoded", bad)
		}
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("{not json"))
	_ = zw.Close()
	if _, err := decodeSnapshot(bytes.NewReader(gz.Bytes()), Format); err == nil {
		t.Fatal("a gzip snapshot of garbage decoded")
	}
}
