package cdsha

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

func expiryToken(iat int64, id string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		enc(fmt.Appendf(nil, `{"iat":%d,"exp":%d,"jti":%q}`, iat, iat+60, id)) + ".sig"
}

// Spent tokens record their window, and long-expired ones are pruned, only
// from format 3: below it a replica of the previous release shares the
// group, keeps every record, and could not restore the window columns, so
// snapshots leave them out. Either way a snapshot round-trips.
func TestSpentTokenExpiryFollowsFormat(t *testing.T) {
	_, opPub := operatorKey(t)
	al, sec, led := testStores(t)
	f := NewFSM(PreGenesis(testCluster, opPub), al, sec, led)
	idx := uint64(0)
	apply := func(e Entry) any {
		t.Helper()
		idx++
		raw, _ := json.Marshal(e)
		return f.Apply(&raft.Log{Index: idx, Type: raft.LogCommand, Data: raw})
	}
	consume := func(tok string) {
		t.Helper()
		res := apply(Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, Token: tok}})
		if r, ok := res.(allowlist.Result); !ok || r.Err != "" {
			t.Fatalf("consume: %#v", res)
		}
	}
	// roundTrip snapshots f and restores it into a fresh FSM, returning the
	// used_token rows of both.
	roundTrip := func() (src, dst []map[string]any) {
		t.Helper()
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
		if err := g.Restore(io.NopCloser(bytes.NewReader(buf.Bytes()))); err != nil {
			t.Fatal(err)
		}
		a, err := al.Dump()
		if err != nil {
			t.Fatal(err)
		}
		b, err := al2.Dump()
		if err != nil {
			t.Fatal(err)
		}
		return a["used_token"], b["used_token"]
	}
	const t0, hour = int64(1_800_000_000), int64(3600)

	apply(Entry{Kind: KindFormat, SetFormat: 2})
	consume(expiryToken(t0, "a"))
	consume(expiryToken(t0+10*hour, "b"))
	src, dst := roundTrip()
	if len(src) != 2 || !reflect.DeepEqual(src, dst) {
		t.Fatalf("format 2 round trip:\n%v\n%v", src, dst)
	}
	for _, row := range src {
		if row["exp_unix"] != int64(0) || row["iat_unix"] != int64(0) {
			t.Fatalf("format 2 recorded a window: %v", row)
		}
	}
	s, err := f.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if rows := s.(*fsmSnapshot).sn.Allowlist["used_token"]; len(rows) != 2 || len(rows[0]) != 1 || len(rows[1]) != 1 {
		t.Fatalf("format 2 snapshot carries the window columns: %v", rows)
	}

	apply(Entry{Kind: KindFormat, SetFormat: 3})
	consume(expiryToken(t0+20*hour, "c"))
	consume(expiryToken(t0+20*hour+30, "d"))
	src, dst = roundTrip()
	if len(src) != 4 || !reflect.DeepEqual(src, dst) {
		t.Fatalf("format 3 round trip:\n%v\n%v", src, dst)
	}
	consume(expiryToken(t0+30*hour, "e")) // prunes c and d, keeps a and b
	src, dst = roundTrip()
	if len(src) != 3 || !reflect.DeepEqual(src, dst) {
		t.Fatalf("after pruning:\n%v\n%v", src, dst)
	}
	windows := 0
	for _, row := range dst {
		if row["exp_unix"] != int64(0) {
			windows++
			if row["exp_unix"] != t0+30*hour+60 || row["iat_unix"] != t0+30*hour {
				t.Fatalf("row %v", row)
			}
		}
	}
	if windows != 1 {
		t.Fatalf("%d rows with a window", windows)
	}
}
