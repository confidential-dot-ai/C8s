package allowlist

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

func faultToken(id string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		enc(fmt.Appendf(nil, `{"iat":1800000000,"exp":1800000060,"jti":%q}`, id)) + ".sig"
}

// A failure of this replica's own database is marked as such; what a
// command produces from its content, at every replica alike, is not.
func TestLocalStoreFaultClassification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	// Content: a constraint the real driver reports, the replicated
	// sentinels, and plain errors.
	if _, err := s.db.Exec(`CREATE TABLE fault_probe (x INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO fault_probe VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	_, constraint := s.db.Exec(`INSERT INTO fault_probe VALUES (1)`)
	if constraint == nil {
		t.Fatal("duplicate primary key accepted")
	}
	for name, err := range map[string]error{
		"constraint":   constraint,
		"invalid":      ErrInvalidWorkload,
		"token reused": operatorauth.ErrTokenReused,
		"plain":        errors.New("put_workload without a workload"),
	} {
		if (Result{}).with(err).LocalStoreFault() {
			t.Errorf("%s: classified as a local store fault: %v", name, err)
		}
	}
	tok := faultToken("a")
	if r := s.Apply(Command{Op: OpConsumeToken, Token: tok}); r.Err != "" {
		t.Fatalf("first consume: %+v", r)
	}
	if r := s.Apply(Command{Op: OpConsumeToken, Token: tok}); r.LocalStoreFault() || !errors.Is(r.Error(), operatorauth.ErrTokenReused) {
		t.Fatalf("replayed token: %+v", r)
	}

	// The store itself: another connection holds the database exclusively.
	lock, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	lock.SetMaxOpenConns(1)
	if _, err := lock.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	r := s.Apply(Command{Op: OpConsumeToken, Token: faultToken("b")})
	if !r.LocalStoreFault() {
		t.Fatalf("write against a locked database: %+v, want a local store fault", r)
	}
	if _, err := lock.Exec(`ROLLBACK`); err != nil {
		t.Fatal(err)
	}

	// And a database this process may only read.
	ro, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ro.Close() })
	if r := (&Store{db: ro, uri: path}).Apply(Command{Op: OpConsumeToken, Token: faultToken("c")}); !r.LocalStoreFault() {
		t.Fatalf("write to a read-only database: %+v, want a local store fault", r)
	}
}
