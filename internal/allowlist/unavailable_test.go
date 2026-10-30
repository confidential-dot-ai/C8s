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

// downReplicator is an HA replica without a leader: nothing commits.
type downReplicator struct{}

func (downReplicator) Replicate(allowlist.Command) (allowlist.Result, error) {
	return allowlist.Result{}, fmt.Errorf("%w: %w", allowlist.ErrUnavailable, errors.New("cds-ha: no leader"))
}

// A write the replicated store cannot commit is 503 and retryable, whether
// it fails at the single-use token spend (before the write) or at the write;
// never 401 (the key is fine) or 500.
func TestWriteUnavailableIs503(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetReplicator(downReplicator{})
	body := `{"label":"ghcr.io/x/web:v1","containers":[{"digest":"` + digestA + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`
	for name, auth := range map[string]allowlist.WriteAuthorizer{
		"token spend": func(r *http.Request, _ []byte) error { return store.ConsumeToken("tok") },
		"write":       func(*http.Request, []byte) error { return nil },
	} {
		app := allowlistTestRouter(allowlist.Handler{Store: &store, WriteAuthorizer: auth}, func() bool { return true })
		for _, method := range []string{http.MethodPut, http.MethodDelete} {
			w := httptest.NewRecorder()
			app.ServeHTTP(w, httptest.NewRequest(method, "/allowlist/workloads/web", strings.NewReader(body)))
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
				t.Errorf("%s, %s: %d %q, want 503 with Retry-After", name, method, w.Code, w.Body)
			}
		}
		w := httptest.NewRecorder()
		doc := `{"schema":"c8s.allowlist/v1","workloads":{}}`
		app.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(doc)))
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s, replace: %d %q, want 503", name, w.Code, w.Body)
		}
	}
}
