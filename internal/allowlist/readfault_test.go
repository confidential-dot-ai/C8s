package allowlist_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// A read the replica's own database cannot serve (it is about to stop and
// exit) is a retryable 503, so a client tries another replica; a store that
// fails otherwise is still a server error.
func TestReadOnLocalStoreFaultIsRetryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := allowlist.Handler{Store: &store}

	lock, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	lock.SetMaxOpenConns(1)
	if _, err := lock.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/allowlist", "/allowlist/history"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		switch path {
		case "/allowlist":
			h.HandleList(w, r)
		default:
			h.HandleHistory(w, r)
		}
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s on a locked store: %d %q, want 503", path, w.Code, w.Body)
		}
	}
	if _, err := lock.Exec(`ROLLBACK`); err != nil {
		t.Fatal(err)
	}

	store.Close() // a closed handle: not a fault of the database itself
	w := httptest.NewRecorder()
	h.HandleList(w, httptest.NewRequest(http.MethodGet, "/allowlist", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("GET /allowlist on a closed store: %d, want 500", w.Code)
	}
}
