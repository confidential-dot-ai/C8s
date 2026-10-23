package routing

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// fakeBindings is a binding store that counts holds and their releases.
type fakeBindings struct {
	mu       sync.Mutex
	entries  map[string]Binding
	refused  map[string]string
	held     map[string]int
	released map[string]int
}

func newFakeBindings(entries map[string]Binding) *fakeBindings {
	return &fakeBindings{entries: entries, refused: map[string]string{}, held: map[string]int{}, released: map[string]int{}}
}

func (b *fakeBindings) Hold(connection string) (Binding, string, uint64, func(), bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	bound, ok := b.entries[connection]
	if !ok {
		return Binding{}, "", 0, nil, false
	}
	b.held[connection]++
	return bound, b.refused[connection], 1, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		b.released[connection]++
	}, true
}

func (b *fakeBindings) Refuse(connection string, _ uint64, code string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refused[connection] == "" {
		b.refused[connection] = code
	}
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
// refused once another manifest is applied, before any backend is selected;
// an unbound or unknown connection routes by the applied manifest.
func TestE6ListenerRefusesAChangedBinding(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	bindings := newFakeBindings(map[string]Binding{"1.1": f.bound()})
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

	// The binding stays refused once its digests hold again (E6).
	bindings.entries["1.1"] = f.bound()
	if w := f.getOn("1.1"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteDigestChanged {
		t.Fatalf("GET / on a refused connection whose digests hold again = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouteDigestChanged)
	}
	if bindings.held["1.1"] == 0 || bindings.held["1.2"] != 0 || bindings.released["1.1"] != bindings.held["1.1"] {
		t.Fatalf("holds = %v, releases = %v, want only the bound connection held, each hold released", bindings.held, bindings.released)
	}
}

// TestE6AllowlistWriteKeepsTheSession: a session survives an allowlist write
// and a router renewal that leave the entries its routes name unchanged, and
// is refused with route_entry_changed once one of them is redefined or
// removed, or its bound document cannot be fetched.
func TestE6AllowlistWriteKeepsTheSession(t *testing.T) {
	tests := []struct {
		name  string
		write func(*fixture)
		want  string
	}{
		{"unrelated entry added", func(f *fixture) {
			f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"web": "v1", "admin": "v1", "router": "v1", "new": "v1"}))
		}, ""},
		{"route's entry redefined", func(f *fixture) {
			f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"web": "v2", "admin": "v1", "router": "v1"}))
		}, types.ErrorCodeRouteEntryChanged},
		{"route's entry removed", func(f *fixture) {
			f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"admin": "v1", "router": "v1"}))
		}, types.ErrorCodeRouteEntryChanged},
		{"bound document unavailable", func(f *fixture) {
			f.allowlists.serve(digestOf(0x43), testAllowlist())
			f.allowlists.fail = errors.New("CDS unreachable")
		}, types.ErrorCodeRouteEntryChanged},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			// The router's leaf is stamped under a document the router never
			// read as current, so the check fetches it.
			bound := digestOf(0x41)
			f.allowlists.store(bound, testAllowlist())
			f.renew(t, issueStampedLeaf(t, f.mesh, "router", bound))
			web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
			f.apply(t, simpleManifest(1, web.addr()))
			bindings := newFakeBindings(map[string]Binding{"1.1": f.bound()})
			f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})

			tc.write(f)
			f.refresh(t)
			// The router renews under the new allowlist; the session's
			// binding does not follow it.
			f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
			w := f.getOn("1.1")
			if tc.want == "" {
				if w.Code != http.StatusOK {
					t.Fatalf("GET / = %d %q, want 200", w.Code, w.Body.String())
				}
				return
			}
			if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != tc.want {
				t.Fatalf("GET / = %d %q, want 503 %q", w.Code, w.Body.String(), tc.want)
			}
			sealedHost := []types.HeaderField{{Name: "Host", Value: testHost}}
			_, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}, bindings.entries["1.1"])
			var changed *BindingChangedError
			if !errors.As(err, &changed) || changed.Code != tc.want {
				t.Fatalf("Forward() = %v, want a BindingChangedError %q", err, tc.want)
			}
		})
	}
}

// TestE6UnstampedBindingHoldsTheManifestAlone: a session bound with no router
// digest is checked against the route digest only.
func TestE6UnstampedBindingHoldsTheManifestAlone(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	unbound := Binding{RouteDigest: f.state.Current().Signed.Digest()}
	f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"web": "v2"}))
	f.refresh(t)
	route := f.state.Current().Manifest.Hosts[testHost].Routes[0]
	if code := f.proxy.entryChanged(context.Background(), unbound, route); code != "" {
		t.Fatalf("entryChanged(no router digest) after the route's entry changed = %q, want none", code)
	}
}

// TestE6EntryCheckIsPerRoute: removing the entry one route names refuses a
// bound request to that route only.
func TestE6EntryCheckIsPerRoute(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	admin := startBackend(t, "admin", issueLeaf(t, f.mesh, "admin"))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/", "prefix", web.addr(), "web"),
		workloadRoute("/admin", "prefix", admin.addr(), "admin"),
	}}})
	bindings := newFakeBindings(map[string]Binding{"1.1": f.bound(), "1.2": f.bound()})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})
	f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"web": "v1", "router": "v1"}))
	f.refresh(t)

	get := func(connection, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = testHost
		r.Header.Set(ConnectionHeader, connection)
		w := httptest.NewRecorder()
		f.proxy.ServeHTTP(w, r)
		return w
	}
	if w := get("1.1", "/"); w.Code != http.StatusOK {
		t.Fatalf("bound GET / after admin was removed = %d %q, want 200", w.Code, w.Body.String())
	}
	if w := get("1.2", "/admin"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteEntryChanged {
		t.Fatalf("bound GET /admin after admin was removed = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouteEntryChanged)
	}
	if n := admin.hits.Load(); n != 0 {
		t.Fatalf("admin served %d requests, want 0", n)
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
