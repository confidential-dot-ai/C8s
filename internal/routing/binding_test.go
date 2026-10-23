package routing

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fakeBindings is a binding store that counts touches.
type fakeBindings struct {
	mu      sync.Mutex
	entries map[string]Binding
	touched map[string]int
}

func (b *fakeBindings) Lookup(connection string) (Binding, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bound, ok := b.entries[connection]
	return bound, ok
}

func (b *fakeBindings) Touch(connection string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.touched[connection]++
}

// getOn sends GET / through the routing listener's handler on connection, or
// with no connection header when connection is empty.
func (f *fixture) getOn(connection string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testHost
	if connection != "" {
		r.Header.Set(ConnectionHeader, connection)
	}
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	return w
}

// TestE6ListenerRefusesAChangedBinding: a request on a bound connection is
// refused with the code of whichever digest changed, before any backend is
// selected; an unbound or unknown connection routes by the applied manifest.
func TestE6ListenerRefusesAChangedBinding(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil { // records the router digest
		t.Fatal(err)
	}
	bindings := &fakeBindings{entries: map[string]Binding{"1.1": f.bound()}, touched: map[string]int{}}
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})

	if w := f.getOn("1.1"); w.Code != http.StatusOK {
		t.Fatalf("GET / on a connection bound to the applied manifest = %d %q, want %d", w.Code, w.Body.String(), http.StatusOK)
	}
	if got := web.seen().header.Get(ConnectionHeader); got != "" {
		t.Fatalf("backend saw %s %q, want it dropped", ConnectionHeader, got)
	}

	f.apply(t, simpleManifest(2, web.addr()))
	hits := web.hits.Load()
	w := f.getOn("1.1")
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteDigestChanged {
		t.Fatalf("GET / after another manifest applied = %d %q, want %d %q", w.Code, w.Body.String(), http.StatusServiceUnavailable, types.ErrorCodeRouteDigestChanged)
	}
	if got := web.hits.Load(); got != hits {
		t.Fatalf("backend served %d requests after a refusal, want %d", got, hits)
	}
	for _, connection := range []string{"", "1.2"} {
		if w := f.getOn(connection); w.Code != http.StatusOK {
			t.Fatalf("GET / on connection %q = %d %q, want %d (unbound)", connection, w.Code, w.Body.String(), http.StatusOK)
		}
	}

	bindings.entries["1.1"] = f.bound()
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if w := f.getOn("1.1"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("GET / after the router renewed = %d %q, want %d %q", w.Code, w.Body.String(), http.StatusServiceUnavailable, types.ErrorCodeRouterDigestChanged)
	}
	if bindings.touched["1.1"] == 0 || bindings.touched["1.2"] != 0 {
		t.Fatalf("touches = %v, want only the bound connection touched", bindings.touched)
	}
}

// TestE6EmptyRouterDigestComparesAsAValue: a session bound with no router
// digest is refused once the router has one, and the other way round.
func TestE6EmptyRouterDigestComparesAsAValue(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	unbound := Binding{RouteDigest: f.state.Current().Signed.Digest()}
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if code := f.proxy.changed(unbound, f.state.Current()); code != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("changed(empty router digest) under a stamped router = %q, want %q", code, types.ErrorCodeRouterDigestChanged)
	}
	stamped := f.bound()
	f.renew(t, issueLeaf(t, f.mesh, ""))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if code := f.proxy.changed(stamped, f.state.Current()); code != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("changed(stamped router digest) under an unstamped router = %q, want %q", code, types.ErrorCodeRouterDigestChanged)
	}
	if code := f.proxy.changed(unbound, f.state.Current()); code != "" {
		t.Fatalf("changed(empty router digest) under an unstamped router = %q, want none", code)
	}
}

// TestE6ForwardRefusesAChangedBinding: a tunnelled request bound to another
// manifest is refused with a BindingChangedError and never reaches a backend.
func TestE6ForwardRefusesAChangedBinding(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	bound := f.bound()
	f.apply(t, simpleManifest(2, web.addr()))
	sealedHost := []types.HeaderField{{Name: "Host", Value: testHost}}
	_, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}, bound)
	var changed *BindingChangedError
	if !errors.As(err, &changed) || changed.Code != types.ErrorCodeRouteDigestChanged {
		t.Fatalf("Forward() bound to a replaced manifest = %v, want a BindingChangedError %q", err, types.ErrorCodeRouteDigestChanged)
	}
	if n := web.hits.Load(); n != 0 {
		t.Fatalf("backend served %d requests, want 0", n)
	}
}
