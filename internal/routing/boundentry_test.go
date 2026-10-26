package routing

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// getOnWith is getOn with the headers in extra.
func (f *fixture) getOnWith(connection string, extra http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testHost
	if connection != "" {
		r.Header.Set(ConnectionHeader, connection)
	}
	for name, values := range extra {
		r.Header[name] = values
	}
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	return w
}

func (f *fixture) getWith(connection string, extra http.Header) int {
	return f.getOnWith(connection, extra).Code
}

// TestE6BoundSessionNeverReachesAnotherEntry: a session bound under a
// document where web is v1 is never forwarded to a backend admitted under a
// redefined web, even when the dial rereads an allowlist the router had not
// polled yet: it is refused with route_entry_changed, so the client attests
// again. An unbound request follows the reread.
func TestE6BoundSessionNeverReachesAnotherEntry(t *testing.T) {
	f := newFixture(t)
	f.entries.refreshGap = 0
	redefined := labelled(map[string]string{"web": "v2", "admin": "v1", "router": "v1"})
	f.allowlists.store(digestOf(0x43), redefined)
	newPod := startBackend(t, "new", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, newPod.addr()))
	bindings := newFakeBindings(map[string]Binding{"1.1": f.bound()})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})
	// The upload lands; the router has not polled it.
	f.allowlists.serve(digestOf(0x43), redefined)

	if w := f.getOn("1.1"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteEntryChanged {
		t.Fatalf("bound GET / to a backend under a redefined entry = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouteEntryChanged)
	}
	if got := bindings.refused["1.1"]; got != types.ErrorCodeRouteEntryChanged {
		t.Fatalf("connection refused with %q, want %q (attest again)", got, types.ErrorCodeRouteEntryChanged)
	}
	sealedHost := []types.HeaderField{{Name: "Host", Value: testHost}}
	_, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}, bindings.entries["1.1"])
	var changed *BindingChangedError
	if !errors.As(err, &changed) || changed.Code != types.ErrorCodeRouteEntryChanged {
		t.Fatalf("tunnelled request bound under web=v1 to the web=v2 backend: Forward() = %v, want a BindingChangedError %q", err, types.ErrorCodeRouteEntryChanged)
	}
	if n := newPod.hits.Load(); n != 0 {
		t.Fatalf("the web=v2 backend served %d bound requests, want 0", n)
	}
	if w := f.getOn(""); w.Code != http.StatusOK {
		t.Fatalf("unbound GET / after the reread = %d %q, want 200", w.Code, w.Body.String())
	}
}

// TestE6BoundSessionNeverReusesAPoolOfAnotherEntry: a session bound under a
// document where web is v2 does not ride a pooled connection to a backend
// admitted under web=v1.
func TestE6BoundSessionNeverReusesAPoolOfAnotherEntry(t *testing.T) {
	f := newFixture(t)
	f.entries.refreshGap = 0
	oldPod := startBackend(t, "old", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, oldPod.addr()))
	if w := f.getOn(""); w.Code != http.StatusOK {
		t.Fatalf("GET / = %d %q, want 200", w.Code, w.Body.String())
	}
	// The upload redefines web; the router renews under it before it polls.
	f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"web": "v2", "admin": "v1", "router": "v1"}))
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	bindings := newFakeBindings(map[string]Binding{"new": f.bound()})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})

	hits := oldPod.hits.Load()
	if w := f.getOn("new"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteEntryChanged {
		t.Fatalf("GET / bound under web=v2 with a pooled connection to web=v1 = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouteEntryChanged)
	}
	if n := oldPod.hits.Load() - hits; n != 0 {
		t.Fatalf("the web=v1 backend served %d requests bound under web=v2, want 0", n)
	}
}

// TestE7RequiredBindingMissing: a request that requires a binding on a
// connection the store holds none for (a cds-attest restart, a dropped
// binding) is refused with binding_missing, not routed unbound; without the
// header it routes unbound, and the header never reaches the backend.
func TestE7RequiredBindingMissing(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	bindings := newFakeBindings(map[string]Binding{"1.1": f.bound()})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})
	require := http.Header{RequireBindingHeader: {"1"}}

	for _, connection := range []string{"1.2", ""} {
		w := f.getOnWith(connection, require)
		if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeBindingMissing {
			t.Fatalf("GET / requiring a binding on connection %q = %d %q, want 503 %q", connection, w.Code, w.Body.String(), types.ErrorCodeBindingMissing)
		}
	}
	if n := web.hits.Load(); n != 0 {
		t.Fatalf("backend served %d requests that required a missing binding, want 0", n)
	}
	if got := f.getWith("1.2", nil); got != http.StatusOK {
		t.Fatalf("GET / on an unbound connection without the header = %d, want 200", got)
	}
	if got := f.getWith("1.1", require); got != http.StatusOK {
		t.Fatalf("GET / requiring the binding it holds = %d, want 200", got)
	}
	if got := web.seen().header.Get(RequireBindingHeader); got != "" {
		t.Fatalf("backend saw %s %q, want it dropped", RequireBindingHeader, got)
	}
}
