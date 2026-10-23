package cdsha

import (
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
		a, err := f.allowlist.Dump()
		if err != nil {
			t.Fatal(err)
		}
		b, err := g.allowlist.Dump()
		if err != nil {
			t.Fatal(err)
		}
		return a["used_token"], b["used_token"]
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
