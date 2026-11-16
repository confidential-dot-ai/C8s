package routing

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// getWith sends GET / through the routing listener's handler with the routing
// headers a client may carry, each left out when empty.
func (f *fixture) getWith(connection, expectedRoute, expectedAllowlist string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testHost
	if connection != "" {
		r.Header.Set(ConnectionHeader, connection)
	}
	if expectedRoute != "" {
		r.Header.Set(ExpectRouteHeader, expectedRoute)
	}
	if expectedAllowlist != "" {
		r.Header.Set(ExpectAllowlistHeader, expectedAllowlist)
	}
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	return w
}

// TestTheExpectedRouteIsCheckedFirst: a request expecting a replaced route
// digest is refused with that, not with the unreadable router credential the
// expected allowlist digest would be checked against.
func TestTheExpectedRouteIsCheckedFirst(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	replaced := f.state.Current().Signed.Digest()
	f.apply(t, simpleManifest(2, web.addr()))
	f.publish(t, "garbage")

	w := f.getWith("", hex.EncodeToString(replaced[:]), hex.EncodeToString(testDigest))
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteDigestChanged {
		t.Fatalf("GET / expecting a replaced route under an unreadable credential = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouteDigestChanged)
	}
	if hits := web.hits.Load(); hits != 0 {
		t.Fatalf("backend served %d requests, want 0", hits)
	}
}

// TestAStaleExpectedAllowlistSparesTheBinding: a request whose expected
// allowlist digest is not the router's is refused before its connection's
// binding is held, so the connection keeps serving.
func TestAStaleExpectedAllowlistSparesTheBinding(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	bindings := newFakeBindings(map[string]Binding{"bound": f.bound(t)})
	f.proxy.bindings = bindings

	w := f.getWith("bound", "", hex.EncodeToString(digestOf(0x43)))
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("GET / on a bound connection expecting another allowlist = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouterDigestChanged)
	}
	if len(bindings.held) != 0 || len(bindings.refused) != 0 {
		t.Fatalf("holds = %v, refusals = %v, want the binding untouched", bindings.held, bindings.refused)
	}
	if w := f.getOn("bound"); w.Code != http.StatusOK {
		t.Fatalf("GET / on the same connection without the header = %d %q, want 200", w.Code, w.Body.String())
	}
}

// TestNoExpectedAllowlistReadsNoCredential: a request expecting no allowlist
// digest is routed by its warm pool while the credential is unreadable.
func TestNoExpectedAllowlistReadsNoCredential(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	if w := f.get("/"); w.Code != http.StatusOK {
		t.Fatalf("warmup = %d %q, want 200", w.Code, w.Body.String())
	}
	f.publish(t, "garbage")

	if w := f.get("/"); w.Code != http.StatusOK {
		t.Fatalf("GET / under an unreadable credential = %d %q, want 200", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 2 {
		t.Fatalf("backend served %d requests, want 2", hits)
	}
}
