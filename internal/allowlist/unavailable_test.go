package allowlist_test

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// refusing is a cluster that refuses every command with err.
type refusing struct {
	err error
}

func (c refusing) Commit(allowlist.Command) (allowlist.Result, error) {
	return allowlist.Result{}, c.err
}

// A write the cluster could not commit is a retryable 503, and one it refused
// for its capacity is 507, at the token spend as at the document write.
func TestWritesRefusedByTheClusterAreRetryableOrOutOfSpace(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	document := `{"schema":"c8s.allowlist/v1","workloads":{}}`
	for _, tc := range []struct {
		name     string
		err      error
		want     int
		retrying bool
	}{
		{
			name:     "no quorum",
			err:      fmt.Errorf("%w: %w", allowlist.ErrUnavailable, errors.New("no leader")),
			want:     http.StatusServiceUnavailable,
			retrying: true,
		},
		{
			name: "at capacity",
			err:  fmt.Errorf("%w: %w", allowlist.ErrCapacity, errors.New("75% of the snapshot bound")),
			want: http.StatusInsufficientStorage,
		},
		{
			name: "no room left",
			err:  fmt.Errorf("%w: %w", allowlist.ErrStoreFull, errors.New("database or disk is full")),
			want: http.StatusInsufficientStorage,
		},
	} {
		cluster := store.CommittedBy(refusing{err: tc.err})
		for name, authorize := range map[string]allowlist.WriteAuthorizer{
			"token spend": func(*http.Request, []byte) error { return cluster.ConsumeToken("a.b.sig") },
			"write":       func(*http.Request, []byte) error { return nil },
		} {
			w := httptest.NewRecorder()
			h := allowlist.Handler{
				Allowlist:       cluster,
				WriteAuthorizer: authorize,
			}
			h.HandleReplaceAll(w, httptest.NewRequest(
				http.MethodPut,
				"/allowlist",
				strings.NewReader(document),
			))
			if w.Code != tc.want {
				t.Errorf("%s, %s: %d %q, want %d", tc.name, name, w.Code, w.Body, tc.want)
			}
			if retrying := w.Header().Get("Retry-After") != ""; retrying != tc.retrying {
				t.Errorf("%s, %s: Retry-After %q", tc.name, name, w.Header().Get("Retry-After"))
			}
		}
	}
}

// A read this replica's own database cannot serve is a retryable 503; a store
// that fails otherwise is a server error.
func TestReadsOnALocalStoreFaultAreRetryable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	h := allowlist.Handler{Allowlist: store.Local()}

	lock, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	lock.SetMaxOpenConns(1)
	if _, err := lock.Exec("BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	for path, handler := range map[string]http.HandlerFunc{
		"/allowlist":         h.HandleList,
		"/allowlist/history": h.HandleHistory,
	} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("GET %s on a locked database: %d %q, want 503", path, w.Code, w.Body)
		}
	}
	if _, err := lock.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}

	store.Close() // a closed handle is not a fault of the database itself
	w := httptest.NewRecorder()
	h.HandleList(w, httptest.NewRequest(http.MethodGet, "/allowlist", nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("GET /allowlist on a closed store: %d, want 500", w.Code)
	}
}
