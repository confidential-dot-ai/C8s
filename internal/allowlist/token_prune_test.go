package allowlist

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const t0 = int64(1_800_000_000)

var margin = int64(SpentTokenMargin / time.Second)

// tokenAt is an unsigned operator token issued at iat (Unix seconds), valid
// for a minute, unique by id.
func tokenAt(iat int64, id string) string {
	return rawToken(fmt.Sprintf(`{"iat":%d,"exp":%d,"jti":%q}`, iat, iat+60, id))
}

func rawToken(payload string) string {
	encode := base64.RawURLEncoding.EncodeToString
	return encode([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + encode([]byte(payload)) + ".sig"
}

func tokenDigest(token string) string {
	return objectDigest([]byte(token[:len(token)-len(".sig")]))
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
		var digest string
		var exp, iat int64
		if err := rows.Scan(&digest, &exp, &iat); err != nil {
			t.Fatal(err)
		}
		out[digest] = [2]int64{exp, iat}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// A spent token is refused again, and its own iat and exp are recorded.
func TestSpentTokenRecordsItsWindow(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	token := tokenAt(t0, "a")
	if err := allowlist.ConsumeToken(token); err != nil {
		t.Fatal(err)
	}
	if err := allowlist.ConsumeToken(token); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("replay = %v, want operatorauth.ErrTokenReused", err)
	}
	if got, want := spent(t, store)[tokenDigest(token)], [2]int64{t0 + 60, t0}; got != want {
		t.Fatalf("recorded %v, want %v", got, want)
	}
}

// A later token prunes the records of the tokens that expired more than the
// margin before it was issued, and only those.
func TestSpentTokensArePruned(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	old := tokenAt(t0, "old")
	edge := tokenAt(t0+60, "edge")
	recent := tokenAt(t0+margin, "recent")
	for _, token := range []string{old, edge, recent} {
		if err := allowlist.ConsumeToken(token); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(spent(t, store)); n != 3 {
		t.Fatalf("%d rows kept before any token expired a margin ago, want 3", n)
	}

	// old expired at t0+60, so a token issued at t0+60+margin+1 prunes it and
	// keeps edge, which expired at t0+120.
	later := tokenAt(t0+60+margin+1, "later")
	if err := allowlist.ConsumeToken(later); err != nil {
		t.Fatal(err)
	}
	got := spent(t, store)
	if _, ok := got[tokenDigest(old)]; ok || len(got) != 3 {
		t.Fatalf("after the later token: %v", got)
	}
	for _, token := range []string{old, edge, recent, later} {
		if err := allowlist.ConsumeToken(token); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("replay = %v, want operatorauth.ErrTokenReused", err)
		}
	}

	// A token never spent, but expired a margin before the newest, is refused
	// as well, and not recorded: its record could be pruned already.
	if err := allowlist.ConsumeToken(tokenAt(t0-1, "never")); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("long-expired token = %v, want operatorauth.ErrTokenReused", err)
	}
	if n := len(spent(t, store)); n != 3 {
		t.Fatalf("%d rows after a refused token, want 3", n)
	}

	// A token issued before the newest is still spendable, and does not prune
	// the newest.
	if err := allowlist.ConsumeToken(tokenAt(t0+61, "behind")); err != nil {
		t.Fatal(err)
	}
	if _, ok := spent(t, store)[tokenDigest(later)]; !ok {
		t.Fatal("the newest token was pruned")
	}
}

// A token the store cannot read a validity window from is refused and
// recorded nowhere.
func TestTokenWithoutAWindowIsRefused(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	for _, token := range []string{
		"", "t1", "h.p.s", "a.b.c.d",
		rawToken(`{"iat":1800000000}`),
		rawToken(`{"exp":1800000000}`),
		rawToken(`{"iat":1800000060,"exp":1800000000}`),
		rawToken(`{"iat":1800000000,"exp":1900000000}`),
		rawToken(`{"iat":"x","exp":"y"}`),
		rawToken(`[]`),
	} {
		if err := allowlist.ConsumeToken(token); err == nil {
			t.Errorf("%q: spent", token)
		}
	}
	if n := len(spent(t, store)); n != 0 {
		t.Fatalf("%d records of tokens without a window", n)
	}
}

// Replicas fed the same commands prune the same records.
func TestSpentTokenPruningIsDeterministic(t *testing.T) {
	stores, st := replicated(t, 3)
	for i := range 40 {
		token := tokenAt(t0+int64(i)*margin/4, fmt.Sprint(i))
		if err := st[i%3].ConsumeToken(token); err != nil {
			t.Fatalf("token %d: %v", i, err)
		}
		if i%5 == 0 {
			if err := st[(i+1)%3].ConsumeToken(token); !errors.Is(err, operatorauth.ErrTokenReused) {
				t.Fatalf("replay of token %d at another replica: %v", i, err)
			}
		}
	}
	ref := spent(t, stores[0])
	if len(ref) == 0 || len(ref) > 8 {
		t.Fatalf("%d rows kept of 40 tokens spanning ten margins", len(ref))
	}
	for i, s := range stores[1:] {
		if got := spent(t, s); !reflect.DeepEqual(got, ref) {
			t.Fatalf("replica %d kept other records:\n%v\n%v", i+1, got, ref)
		}
	}
}

// Spent-token records round-trip through a database image.
func TestSpentTokensSurviveASnapshot(t *testing.T) {
	store, allowlist := openJournaledStore(t)
	tokens := []string{tokenAt(t0, "a"), tokenAt(t0+30, "b")}
	for _, token := range tokens {
		if err := allowlist.ConsumeToken(token); err != nil {
			t.Fatal(err)
		}
	}
	want := spent(t, store)
	image, err := store.Dump()
	if err != nil {
		t.Fatal(err)
	}

	fresh, restored := openJournaledStore(t)
	if err := fresh.Restore(image); err != nil {
		t.Fatal(err)
	}
	if got := spent(t, fresh); !reflect.DeepEqual(got, want) {
		t.Fatalf("restored %v, want %v", got, want)
	}
	for _, token := range tokens {
		if err := restored.ConsumeToken(token); !errors.Is(err, operatorauth.ErrTokenReused) {
			t.Fatalf("replay after the restore: %v", err)
		}
	}
}

// A store whose spent tokens have no window is refused at open: CDS must not
// serve reads while every operator write fails.
func TestStoreWithoutTheTokenWindowIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE used_token (digest TEXT PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = OpenStore(path)
	if err == nil || !strings.Contains(err.Error(), "validity window") {
		t.Fatalf("opening a store without the spent-token window = %v", err)
	}
}
