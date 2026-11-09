package cds

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

type fakeRoutes struct {
	manifest []byte
	err      error
}

func (f fakeRoutes) LoadRoutes() (routes.Envelope, error) {
	return routes.Envelope{Manifest: f.manifest}, f.err
}

func patternRoutes(t *testing.T, suffixes ...string) fakeRoutes {
	t.Helper()
	patterns := make([]any, 0, len(suffixes))
	for _, s := range suffixes {
		patterns = append(patterns, map[string]any{"hostSuffix": s, "workload": "opencode", "port": 4096})
	}
	m, err := json.Marshal(map[string]any{
		"schema": routes.Schema, "revision": 1, "notBefore": "2026-09-01T00:00:00Z", "maxAgeSeconds": 86400,
		"hosts": map[string]any{}, "patterns": patterns,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := routes.Parse(m); err != nil {
		t.Fatalf("test manifest: %v", err)
	}
	return fakeRoutes{manifest: m}
}

// A router leaf names *.<hostSuffix> for each stored pattern rule; any other
// leaf, and a router leaf with no stored manifest, names none.
func TestAttest_RouterLeafPatternNames(t *testing.T) {
	store := completeAPIStore(t)
	router := containersView(wlDigestA)
	router[0].Role = workloadclaims.RouterRole
	with := func(r routeStore) func(*AttestHandler) {
		return func(h *AttestHandler) { h.Routes = r; h.RouterCertTTL = 20 * time.Second }
	}
	two := patternRoutes(t, "agents.example", "b.agents.example")

	got := leafFromInventory(t, store, []string{wlDigestA}, router, with(two)).DNSNames
	if want := []string{"*.agents.example", "*.b.agents.example"}; !slices.Equal(got, want) {
		t.Fatalf("router leaf DNS names = %v, want %v", got, want)
	}
	if got := leafFromInventory(t, store, []string{wlDigestA}, containersView(wlDigestA), with(two)).DNSNames; len(got) != 0 {
		t.Fatalf("non-router leaf DNS names = %v, want none", got)
	}
	if got := leafFromInventory(t, store, []string{wlDigestA}, router, with(fakeRoutes{err: allowlist.ErrNoRoutes})).DNSNames; len(got) != 0 {
		t.Fatalf("router leaf without a stored manifest: DNS names = %v, want none", got)
	}
}
