package allowlist

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// tokenAt is an operator token issued at iat (Unix seconds), valid for a
// minute, unique by id. consumeToken never checks its signature.
func tokenAt(iat int64, id string) string {
	return rawToken(fmt.Sprintf(`{"iat":%d,"exp":%d,"jti":%q}`, iat, iat+60, id))
}

func rawToken(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + enc([]byte(payload)) + ".sig"
}

// spent is used_token as digest -> [exp, iat].
func spent(t *testing.T, s *Store) map[string][2]int64 {
	t.Helper()
	rows, err := s.db.Query("SELECT digest, exp_unix, iat_unix FROM used_token")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][2]int64{}
	for rows.Next() {
		var d string
		var exp, iat int64
		if err := rows.Scan(&d, &exp, &iat); err != nil {
			t.Fatal(err)
		}
		out[d] = [2]int64{exp, iat}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func tokenDigest(token string) string {
	return objectDigest([]byte(token[:len(token)-len(".sig")]))
}

const t0 = int64(1_800_000_000)

var margin = int64(spentTokenMargin / time.Second)

// A spent token that has not expired is refused, and its iat and exp are
// recorded.
func TestSpentTokenRecordsItsWindow(t *testing.T) {
	s := openJournaled(t)
	tok := tokenAt(t0, "a")
	if err := s.ConsumeToken(tok); err != nil {
		t.Fatal(err)
	}
	if err := s.ConsumeToken(tok); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("replay = %v", err)
	}
	if got := spent(t, s)[tokenDigest(tok)]; got != [2]int64{t0 + 60, t0} {
		t.Fatalf("recorded %v", got)
	}
}

// A later token prunes the records of tokens that expired more than the
// margin before it was issued, and only those; a pruned token stays spent.
func TestSpentTokensArePruned(t *testing.T) {
	s := openJournaled(t)
	old, edge, recent := tokenAt(t0, "old"), tokenAt(t0+60, "edge"), tokenAt(t0+margin, "recent")
	for _, tok := range []string{old, edge, recent} {
		if err := s.ConsumeToken(tok); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(spent(t, s)); n != 3 {
		t.Fatalf("pruned before any token expired a margin ago: %d rows", n)
	}
	// old expired at t0+60; a token issued at t0+60+margin+1 prunes it, and
	// keeps edge (exp t0+120).
	later := tokenAt(t0+60+margin+1, "later")
	if err := s.ConsumeToken(later); err != nil {
		t.Fatal(err)
	}
	got := spent(t, s)
	if _, ok := got[tokenDigest(old)]; ok || len(got) != 3 {
		t.Fatalf("after the later token: %v", got)
	}
	for _, tok := range []string{old, edge, recent, later} {
		if err := s.ConsumeToken(tok); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("replay = %v", err)
		}
	}
	// A token never spent, but expired a margin before the newest, is
	// refused too, and not recorded: its record could be pruned already.
	if err := s.ConsumeToken(tokenAt(t0-1, "never")); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("expired token = %v", err)
	}
	if n := len(spent(t, s)); n != 3 {
		t.Fatalf("refused token recorded: %d rows", n)
	}
	// A token issued before the newest is still accepted, and does not prune
	// the newest. (No row can hold an exp below the watermark less the
	// margin, so max(watermark, iat) and iat prune alike; see consumeToken.)
	if err := s.ConsumeToken(tokenAt(t0+60+1, "behind")); err != nil {
		t.Fatal(err)
	}
	if _, ok := spent(t, s)[tokenDigest(later)]; !ok {
		t.Fatal("the newest token was pruned")
	}
}

// Records without a window (an earlier release, a group below cdsha.Format
// 2, or a token whose claims do not parse) are kept; such tokens prune
// nothing and do not panic.
func TestSpentTokensWithoutWindowAreKept(t *testing.T) {
	s := openJournaled(t)
	legacy := tokenAt(t0, "legacy")
	if r := s.ApplyWith(Command{Op: OpConsumeToken, Token: legacy}, ApplyOptions{}); r.Err != "" {
		t.Fatal(r.Err)
	}
	old := tokenAt(t0, "old")
	if err := s.ConsumeToken(old); err != nil {
		t.Fatal(err)
	}
	malformed := []string{
		"", "t1", "h.p.s", "a.b.c.d",
		rawToken(`{"iat":1800000000}`),
		rawToken(`{"exp":1800000000}`),
		rawToken(`{"iat":1800000060,"exp":1800000000}`),
		rawToken(`{"iat":1800000000,"exp":1900000000}`),
		rawToken(`{"iat":"x","exp":"y"}`),
		rawToken(`{"iat":-5,"exp":10}`),
		rawToken(`[]`),
		"!!." + base64.RawURLEncoding.EncodeToString([]byte(`{"iat":1,"exp":2}`)) + ".s",
	}
	before := len(spent(t, s))
	for i, tok := range malformed {
		if err := s.ConsumeToken(tok); err != nil {
			t.Fatalf("malformed %d %q: %v", i, tok, err)
		}
	}
	got := spent(t, s)
	if len(got) != before+len(malformed) {
		t.Fatalf("malformed tokens pruned or not recorded: %d rows, want %d", len(got), before+len(malformed))
	}
	for i, tok := range malformed {
		if err := s.ConsumeToken(tok); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("malformed %d replay = %v", i, err)
		}
	}
	if got[tokenDigest(legacy)] != [2]int64{} {
		t.Fatalf("legacy row %v", got[tokenDigest(legacy)])
	}
	if err := s.ConsumeToken(tokenAt(t0+10*margin, "much-later")); err != nil {
		t.Fatal(err)
	}
	got = spent(t, s)
	if _, ok := got[tokenDigest(old)]; ok {
		t.Fatal("old token with a window kept")
	}
	if _, ok := got[tokenDigest(legacy)]; !ok {
		t.Fatal("legacy row pruned")
	}
	if len(got) != before-1+len(malformed)+1 {
		t.Fatalf("rows %d", len(got))
	}
}

// Replicas fed the same commands prune the same records.
func TestSpentTokenPruningIsDeterministic(t *testing.T) {
	st := replicated(t, 3)
	for i := range 40 {
		tok := tokenAt(t0+int64(i)*margin/4, fmt.Sprint(i))
		if err := st[i%3].ConsumeToken(tok); err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
		if i%5 == 0 {
			if err := st[(i+1)%3].ConsumeToken(tok); !errors.Is(err, operatorauth.ErrTokenReused) {
				t.Fatalf("replay %d: %v", i, err)
			}
		}
	}
	ref := spent(t, st[0])
	if len(ref) == 0 || len(ref) > 8 {
		t.Fatalf("%d rows kept", len(ref))
	}
	for _, s := range st[1:] {
		if got := spent(t, s); !reflect.DeepEqual(got, ref) {
			t.Fatalf("replicas differ:\n%v\n%v", got, ref)
		}
	}
}

// Rows with a window round-trip through Dump, the JSON encoding and Restore;
// rows without the columns (a snapshot of an earlier release) restore as 0s
// and are kept; StripTokenExpiry makes such a snapshot.
func TestSpentTokenSnapshotRoundTrip(t *testing.T) {
	src := openJournaled(t)
	toks := []string{tokenAt(t0, "a"), tokenAt(t0+30, "b"), "h.p.legacy"}
	for _, tok := range toks {
		if err := src.ConsumeToken(tok); err != nil {
			t.Fatal(err)
		}
	}
	want := spent(t, src)
	sn, err := src.Dump()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sn)
	if err != nil {
		t.Fatal(err)
	}
	var back Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	dst := openJournaled(t)
	if err := dst.Restore(back); err != nil {
		t.Fatal(err)
	}
	if got := spent(t, dst); !reflect.DeepEqual(got, want) {
		t.Fatalf("restored %v, want %v", got, want)
	}

	back.StripTokenExpiry()
	for _, row := range back["used_token"] {
		if len(row) != 1 {
			t.Fatalf("stripped row %v", row)
		}
	}
	old := openJournaled(t)
	if err := old.Restore(back); err != nil {
		t.Fatal(err)
	}
	got := spent(t, old)
	if len(got) != len(want) {
		t.Fatalf("restored %d rows", len(got))
	}
	for d, w := range got {
		if w != [2]int64{} {
			t.Fatalf("%s restored with %v", d, w)
		}
	}
	for _, tok := range toks {
		if err := old.ConsumeToken(tok); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("replay after restore: %v", err)
		}
	}
	if err := old.ConsumeToken(tokenAt(t0+10*margin, "later")); err != nil {
		t.Fatal(err)
	}
	if n := len(spent(t, old)); n != len(want)+1 {
		t.Fatalf("rows without a window pruned: %d", n)
	}
}

// A database created before the window columns gains them; its records keep
// 0s and its tokens stay spent.
func TestUsedTokenMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE used_token (digest TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	tok := tokenAt(t0, "before")
	if _, err := db.Exec("INSERT INTO used_token (digest) VALUES (?)", tokenDigest(tok)); err != nil {
		t.Fatal(err)
	}
	db.Close()
	for range 2 { // and again, once migrated
		s, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.ConsumeToken(tok); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("token spent before the migration: %v", err)
		}
		if got := spent(t, &s)[tokenDigest(tok)]; got != [2]int64{} {
			t.Fatalf("migrated row %v", got)
		}
		s.Close()
	}
}
