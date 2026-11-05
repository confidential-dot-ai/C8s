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

// fakeBindings is a binding store that counts holds and their releases and
// records each connection's first refusal.
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

func (b *fakeBindings) Hold(connection string) *HeldBinding {
	b.mu.Lock()
	defer b.mu.Unlock()
	bound, ok := b.entries[connection]
	if !ok {
		return nil
	}
	b.held[connection]++
	return &HeldBinding{
		Binding:     bound,
		RefusedWith: b.refused[connection],
		Refuse: func(code string) {
			b.mu.Lock()
			defer b.mu.Unlock()
			if b.refused[connection] == "" {
				b.refused[connection] = code
			}
		},
		Release: func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.released[connection]++
		},
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

// TestListenerRefusesAChangedBinding: a request on a bound connection is
// refused with the code of whichever digest changed, before any backend is
// selected; an unbound or unknown connection routes by the applied manifest.
func TestListenerRefusesAChangedBinding(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil { // records the router digest
		t.Fatal(err)
	}
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

	// The binding stays refused once its digests hold again.
	bindings.entries["1.1"] = f.bound()
	if w := f.getOn("1.1"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouteDigestChanged {
		t.Fatalf("GET / on a refused connection whose digests hold again = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouteDigestChanged)
	}
	delete(bindings.refused, "1.1")
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if w := f.getOn("1.1"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("GET / after the router renewed = %d %q, want %d %q", w.Code, w.Body.String(), http.StatusServiceUnavailable, types.ErrorCodeRouterDigestChanged)
	}
	if bindings.held["1.1"] == 0 || bindings.held["1.2"] != 0 || bindings.released["1.1"] != bindings.held["1.1"] {
		t.Fatalf("holds = %v, releases = %v, want only the bound connection held, each hold released", bindings.held, bindings.released)
	}
}

// TestEmptyRouterDigestComparesAsAValue: a session bound with no router
// digest is refused once the router has one, and the other way round.
func TestEmptyRouterDigestComparesAsAValue(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	unbound := Binding{RouteDigest: f.state.Current().Signed.Digest()}
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if code := f.proxy.changedSince(unbound, f.state.Current()); code != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("changedSince(empty router digest) under a stamped router = %q, want %q", code, types.ErrorCodeRouterDigestChanged)
	}
	stamped := f.bound()
	f.renew(t, issueLeaf(t, f.mesh, ""))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if code := f.proxy.changedSince(stamped, f.state.Current()); code != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("changedSince(stamped router digest) under an unstamped router = %q, want %q", code, types.ErrorCodeRouterDigestChanged)
	}
	if code := f.proxy.changedSince(unbound, f.state.Current()); code != "" {
		t.Fatalf("changedSince(empty router digest) under an unstamped router = %q, want none", code)
	}
}

// TestForwardRefusesAChangedBinding: a tunnelled request bound to another
// manifest is refused with a BindingChangedError and never reaches a backend.
func TestForwardRefusesAChangedBinding(t *testing.T) {
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

// TestRenewalBeforeThePollRefusesABoundDial: a router leaf renewed after
// the binding check and before the poll fails the dial of a request bound to
// the previous digest, and retires the pools, rather than serve it by a
// backend accepted under the renewed one.
func TestRenewalBeforeThePollRefusesABoundDial(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	bindings := newFakeBindings(map[string]Binding{"1.1": f.bound()})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	f.transports.For(backend) // built under the bound digest

	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	if w := f.getOn("1.1"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("GET / bound to the digest before a renewal no poll saw = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouterDigestChanged)
	}
	if got := bindings.refused["1.1"]; got != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("connection refused with %q after the refused dial, want %q", got, types.ErrorCodeRouterDigestChanged)
	}
	if n := web.hits.Load(); n != 0 {
		t.Fatalf("backend under the renewed digest served %d requests, want 0", n)
	}
	if got := f.transports.RouterDigest(); got != string(digestOf(0x43)) {
		t.Fatalf("RouterDigest() after the refused dial = %x, want the renewed %x", got, digestOf(0x43))
	}
	if w := f.get("/"); w.Code != http.StatusOK {
		t.Fatalf("unbound GET / after the pools retired = %d %q, want 200", w.Code, w.Body.String())
	}
}

// TestRenewalBeforeThePollRefusesAnUnboundDial: the unbound request whose
// dial retires the pools gets a retryable 503, not a backend 502, and the
// next one is served.
func TestRenewalBeforeThePollRefusesAnUnboundDial(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	f.transports.For(backend)

	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	if w := f.get("/"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("unbound GET / on a pool built before a renewal no poll saw = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouterDigestChanged)
	}
	if w := f.get("/"); w.Code != http.StatusOK {
		t.Fatalf("unbound GET / after the pools retired = %d %q, want 200", w.Code, w.Body.String())
	}
}

// TestTransportUnderAnotherDigest: a bound request never takes a workload
// transport whose pool was accepted under another router digest.
func TestTransportUnderAnotherDigest(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	route := f.state.Current().Manifest.Hosts[testHost].Routes[0]
	bound := f.bound()
	if _, ok := f.proxy.transport(route, &HeldBinding{Binding: bound}); !ok {
		t.Fatal("transport(bound to the tracked digest) refused, want it")
	}
	bound.RouterDigest = string(digestOf(0x44))
	if _, ok := f.proxy.transport(route, &HeldBinding{Binding: bound}); ok {
		t.Fatal("transport(bound to another digest) taken, want it refused")
	}
	if _, ok := f.proxy.transport(route, nil); !ok {
		t.Fatal("transport(unbound) refused, want it")
	}
}

// TestListenerRefusesAPoolUnderAnotherDigest: a bound request whose workload
// pool was built under another router digest, as a poll between its binding
// check and its pool lookup leaves it, is refused and so is its connection.
func TestListenerRefusesAPoolUnderAnotherDigest(t *testing.T) {
	f := newFixture(t)
	f.apply(t, simpleManifest(1, "127.0.0.1:1"))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	bindings := newFakeBindings(map[string]Binding{"1.1": f.bound()})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	f.transports.For(backend)
	key := backendKey(backend)
	f.transports.mu.Lock()
	pool := f.transports.cache[key]
	pool.routerDigest = string(digestOf(0x44))
	f.transports.cache[key] = pool
	f.transports.mu.Unlock()

	if w := f.getOn("1.1"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("GET / on a pool under another digest = %d %q, want 503 %q", w.Code, w.Body.String(), types.ErrorCodeRouterDigestChanged)
	}
	if got := bindings.refused["1.1"]; got != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("connection refused with %q, want %q", got, types.ErrorCodeRouterDigestChanged)
	}
}

// TestUnreadableCredentialKeepsTheRouterDigest: a failed credential read
// is no renewal, so a bound connection is not refused for it, and a request a
// client drives through syncRouterDigest retires no pool while it fails.
func TestUnreadableCredentialKeepsTheRouterDigest(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	bindings := newFakeBindings(map[string]Binding{"1.1": f.bound()})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Bindings: bindings})
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	before := f.transports.For(backend)

	f.publish(t, "garbage")
	if err := f.transports.syncRouterDigest(); err == nil {
		t.Fatal("syncRouterDigest() with an unreadable bundle = nil, want an error")
	}
	if f.transports.For(backend) != before {
		t.Fatal("syncRouterDigest() with an unreadable bundle retired a pool, want none retired")
	}
	if err := f.transports.dropMeshPools(); err == nil {
		t.Fatal("dropMeshPools() with an unreadable bundle = nil, want an error")
	}
	if w := f.getOn("1.1"); w.Code != http.StatusBadGateway {
		t.Fatalf("GET / while the credential is unreadable = %d %q, want 502 (the dial fails, the binding holds)", w.Code, w.Body.String())
	}
	f.publish(t, caPEM(f.mesh))
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
	if w := f.getOn("1.1"); w.Code != http.StatusOK {
		t.Fatalf("GET / once the credential reads again = %d %q, want 200", w.Code, w.Body.String())
	}
	if len(bindings.refused) != 0 {
		t.Fatalf("refusals = %v, want none", bindings.refused)
	}
}

// TestFirstReadFailureTracksNoDigest: a first poll that cannot read the
// credential tracks no router digest, so the stamped leaf published after it
// is no renewal.
func TestFirstReadFailureTracksNoDigest(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	f.publish(t, "garbage")
	if err := f.transports.dropMeshPools(); err == nil {
		t.Fatal("dropMeshPools() with an unreadable bundle = nil, want an error")
	}
	f.publish(t, caPEM(f.mesh))
	if w := f.getOn(""); w.Code != http.StatusOK {
		t.Fatalf("GET / once a stamped leaf is published = %d %q, want 200", w.Code, w.Body.String())
	}
}

// A handshake before any credential read makes the router read it, even for
// an unstamped leaf, whose empty digest an unread router also reports.
func TestSyncRouterDigestReadsAnUnreadCredential(t *testing.T) {
	f := newFixture(t)
	if _, known := f.transports.knownRouterDigest(); known {
		t.Fatal("knownRouterDigest() before any read = known, want unknown")
	}
	if _, err := f.proxy.SyncRouterDigest(""); err != nil {
		t.Fatalf("SyncRouterDigest(\"\") = %v, want nil", err)
	}
	if _, known := f.transports.knownRouterDigest(); !known {
		t.Fatal("knownRouterDigest() after SyncRouterDigest = unknown, want the credential read")
	}
}
