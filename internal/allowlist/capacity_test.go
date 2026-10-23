package allowlist_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// capacityReplicator is an HA cluster whose admission cap refuses the write.
type capacityReplicator struct{}

func (capacityReplicator) Replicate(allowlist.Command) (allowlist.Result, error) {
	return allowlist.Result{}, fmt.Errorf("%w: %w", allowlist.ErrCapacity, errors.New("cds-ha: the replicated state is at its snapshot capacity"))
}

// A write the HA admission cap refuses is 507 with the reason, whether it
// is refused at the token spend or at the write: not 503 (the cluster is
// up and committing) and not 500.
func TestCapacityRefusalIs507(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetReplicator(capacityReplicator{})
	body := `{"label":"ghcr.io/x/web:v1","containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`
	for name, auth := range map[string]allowlist.WriteAuthorizer{
		"token spend": func(r *http.Request, _ []byte) error { return store.ConsumeToken("tok") },
		"write":       func(*http.Request, []byte) error { return nil },
	} {
		app := allowlistTestRouter(allowlist.Handler{Store: &store, WriteAuthorizer: auth}, func() bool { return true })
		w := httptest.NewRecorder()
		app.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/allowlist/workloads/web", strings.NewReader(body)))
		if w.Code != http.StatusInsufficientStorage || !strings.Contains(w.Body.String(), "snapshot capacity") {
			t.Errorf("%s, put: %d %q, want 507 naming the snapshot capacity", name, w.Code, w.Body)
		}
		w = httptest.NewRecorder()
		doc := `{"schema":"c8s.allowlist/v1","workloads":{}}`
		app.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(doc)))
		if w.Code != http.StatusInsufficientStorage {
			t.Errorf("%s, replace: %d %q, want 507", name, w.Code, w.Body)
		}
	}
}

// At the cap, writes that grow the state are refused before their token is
// spent: a spent token is a replicated row, so refusing after it would grow
// the state with every retry (about 110 bytes each, kept an hour). However
// long clients retry, the store does not grow; a DELETE still goes through.
func TestRefusedWritesAtCapacityDoNotGrowTheState(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	body := `{"label":"ghcr.io/x/web:v1","containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`
	spent := 0
	auth := func(*http.Request, []byte) error {
		spent++
		return store.ConsumeToken(fmt.Sprintf("token-%d", spent))
	}
	atCap := false
	h := allowlist.Handler{Store: &store, WriteAuthorizer: auth, Capacity: func() error {
		if atCap {
			return fmt.Errorf("%w: %w", allowlist.ErrCapacity, errors.New("cds-ha: the replicated state is at its snapshot capacity"))
		}
		return nil
	}}
	app := allowlistTestRouter(h, func() bool { return true })
	do := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		app.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}
	if w := do(http.MethodPut, "/allowlist/workloads/web", body); w.Code != http.StatusNoContent {
		t.Fatalf("put under the cap: %d %s", w.Code, w.Body)
	}
	atCap = true
	before, err := store.LiveBytes()
	if err != nil {
		t.Fatal(err)
	}
	history, _ := store.HistoryLen()
	spentBefore := spent
	for i := range 500 {
		path := fmt.Sprintf("/allowlist/workloads/w%d", i)
		if w := do(http.MethodPut, path, body); w.Code != http.StatusInsufficientStorage || !strings.Contains(w.Body.String(), "snapshot capacity") {
			t.Fatalf("put %d at the cap: %d %s, want 507", i, w.Code, w.Body)
		}
	}
	if w := do(http.MethodPut, "/allowlist", `{"schema":"c8s.allowlist/v1","workloads":{}}`); w.Code != http.StatusInsufficientStorage {
		t.Fatalf("replace at the cap: %d %s, want 507", w.Code, w.Body)
	}
	after, _ := store.LiveBytes()
	h2, _ := store.HistoryLen()
	if spent != spentBefore || after != before || h2 != history {
		t.Fatalf("refused writes grew the state: %d tokens spent, store %d -> %d bytes, history %d -> %d", spent-spentBefore, before, after, history, h2)
	}
	// Shrinking writes still work at the cap.
	if w := do(http.MethodDelete, "/allowlist/workloads/web", ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete at the cap: %d %s", w.Code, w.Body)
	}
}
