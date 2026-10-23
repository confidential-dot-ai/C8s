package cdsha

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

func expiryToken(iat int64, id string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		enc(fmt.Appendf(nil, `{"iat":%d,"exp":%d,"jti":%q}`, iat, iat+60, id)) + ".sig"
}

// Spent tokens record their window, long-expired ones are pruned, and the
// windows survive a snapshot round trip.
func TestSpentTokenExpiry(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	idx := uint64(0)
	consume := func(tok string) {
		t.Helper()
		idx++
		res := applyAt(f, idx, Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{Op: allowlist.OpConsumeToken, Token: tok}})
		if r, ok := res.(allowlist.Result); !ok || r.Err != "" {
			t.Fatalf("consume: %#v", res)
		}
	}
	// roundTrip snapshots f and restores it into a fresh FSM, returning the
	// used_token rows of both.
	roundTrip := func() (src, dst []map[string]any) {
		t.Helper()
		g := newTestFSM(t, opPub)
		if err := restoreCopy(t, f, g); err != nil {
			t.Fatal(err)
		}
		return usedTokens(t, f.allowlist), usedTokens(t, g.allowlist)
	}
	const t0, hour = int64(1_800_000_000), int64(3600)

	consume(expiryToken(t0+20*hour, "c"))
	consume(expiryToken(t0+20*hour+30, "d"))
	src, dst := roundTrip()
	if len(src) != 2 || !reflect.DeepEqual(src, dst) {
		t.Fatalf("round trip:\n%v\n%v", src, dst)
	}
	consume(expiryToken(t0+30*hour, "e")) // prunes c and d
	src, dst = roundTrip()
	if len(src) != 1 || !reflect.DeepEqual(src, dst) {
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

// usedTokens reads the used_token rows of a store through its own image.
func usedTokens(t *testing.T, s *allowlist.Store) []map[string]any {
	t.Helper()
	image, err := s.Dump()
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:/used-tokens-"+t.Name()+"?vfs=memdb")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Raw(func(dc any) error { return dc.(interface{ Deserialize([]byte) error }).Deserialize(image) }); err != nil {
		t.Fatal(err)
	}
	rows, err := conn.QueryContext(t.Context(), "SELECT digest, exp_unix, iat_unix FROM used_token ORDER BY digest")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var d string
		var exp, iat int64
		if err := rows.Scan(&d, &exp, &iat); err != nil {
			t.Fatal(err)
		}
		out = append(out, map[string]any{"digest": d, "exp_unix": exp, "iat_unix": iat})
	}
	return out
}
