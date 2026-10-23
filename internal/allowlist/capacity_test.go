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
	return allowlist.Result{}, fmt.Errorf("%w: %w", allowlist.ErrCapacity, errors.New("cds-ha: the replicated state is at its snapshot capacity: ..."))
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
