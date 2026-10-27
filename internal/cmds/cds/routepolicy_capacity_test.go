package cds

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

// At the HA state's snapshot capacity a route manifest PUT is refused (507)
// before its token is spent.
func TestRoutePutAtCapacityIsRefusedBeforeTheToken(t *testing.T) {
	store := inMemoryStore(t)
	f := newRouteFixture(t, store)
	spent := 0
	h := routeHandler{Store: store, MeshCA: f.meshSource,
		Authorize: func(*http.Request, []byte) error { spent++; return nil },
		Capacity: func() error {
			return fmt.Errorf("%w: %w", allowlist.ErrCapacity, errors.New("cds-ha: the replicated state is at its snapshot capacity"))
		}}
	w := httptest.NewRecorder()
	h.handlePut(w, httptest.NewRequest(http.MethodPut, routes.Path, bytes.NewReader(manifest(t, 1, f.otherPEM))))
	if w.Code != http.StatusInsufficientStorage || !strings.Contains(w.Body.String(), "snapshot capacity") || spent != 0 {
		t.Fatalf("PUT /routes at the cap = %d %q, tokens spent %d; want 507 and none", w.Code, w.Body, spent)
	}
}
