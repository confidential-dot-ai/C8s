package routing

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/getcert"
)

// poll reads the published credential the way the route poller does.
func (f *fixture) poll(t testing.TB) {
	t.Helper()
	if err := f.transports.dropMeshPools(); err != nil {
		t.Fatal(err)
	}
}

// renewRouter renews the router's leaf under digest and polls, the way the
// route poller picks up a renewal.
func (f *fixture) renewRouter(t testing.TB, digest []byte) {
	t.Helper()
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digest))
	f.poll(t)
}

// TestLaggingBackendServedWithinTheBound: a router that renewed under a new
// allowlist digest keeps serving a backend whose own renewal has not landed
// yet, until the bound on that renewal passes.
func TestLaggingBackendServedWithinTheBound(t *testing.T) {
	tests := []struct {
		name     string
		advance  time.Duration
		want     int
		wantBody string
	}{
		{name: "inside the bound", advance: getcert.PolicyRenewLag - time.Nanosecond, want: http.StatusOK, wantBody: "web"},
		{name: "at the bound", advance: getcert.PolicyRenewLag, want: http.StatusBadGateway, wantBody: backendDigestMismatch},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			web := startBackend(t, "web", issueLeaf(t, f.mesh, "web")) // stamped testDigest
			f.apply(t, simpleManifest(uint64(i+1), web.addr()))
			f.poll(t)
			if got := f.get("/").Code; got != http.StatusOK {
				t.Fatalf("GET / before the allowlist write = %d, want 200", got)
			}
			connection := web.seen().remoteAddr

			f.renewRouter(t, digestOf(0x43))
			f.clock.Advance(tc.advance)

			w := f.get("/")
			if w.Code != tc.want || !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("GET / %v after the router renewed = %d %q, want %d %q", tc.advance, w.Code, w.Body.String(), tc.want, tc.wantBody)
			}
			if tc.want != http.StatusOK {
				return
			}
			if got := web.seen().remoteAddr; got == connection {
				t.Fatalf("backend connection = %q, want the pool retired and redialled", got)
			}
		})
	}
}

// TestLeadingBackendRefusedUntilTheRouterRenews: the bound covers a backend
// behind the router, not one ahead of it, so a backend that renewed first is
// refused until the router's own renewal lands.
func TestLeadingBackendRefusedUntilTheRouterRenews(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, web.addr()))
	f.poll(t)

	w := f.get("/")
	if w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), backendDigestMismatch) {
		t.Fatalf("GET / to a backend ahead of the router = %d %q, want 502 %q", w.Code, w.Body.String(), backendDigestMismatch)
	}
	if n := web.hits.Load(); n != 0 {
		t.Fatalf("backend ahead of the router served %d requests, want 0", n)
	}

	f.renewRouter(t, digestOf(0x43))
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / once the router renewed = %d, want 200", got)
	}
}

// TestOnlyTheDigestTheRouterHeldLastIsServed: one digest is covered, the one
// the router replaced; a second renewal drops the first and no digest the
// router never held is served.
func TestOnlyTheDigestTheRouterHeldLastIsServed(t *testing.T) {
	f := newFixture(t)
	first := startBackend(t, "web", issueLeaf(t, f.mesh, "web")) // stamped testDigest
	second := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	stranger := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x45)))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/first", "prefix", first.addr(), "web"),
		workloadRoute("/second", "prefix", second.addr(), "web"),
		workloadRoute("/stranger", "prefix", stranger.addr(), "web"),
	}}})
	f.poll(t)

	f.renewRouter(t, digestOf(0x43))
	f.renewRouter(t, digestOf(0x44))

	for path, want := range map[string]int{
		"/first":    http.StatusBadGateway,
		"/second":   http.StatusOK,
		"/stranger": http.StatusBadGateway,
	} {
		if got := f.get(path).Code; got != want {
			t.Fatalf("GET %s after two renewals = %d, want %d", path, got, want)
		}
	}
}

// TestLaggingDigestRequiresTheRoutesWorkloadName: the bound covers the
// allowlist digest alone; the workload name the manifest names is still
// required of the backend.
func TestLaggingDigestRequiresTheRoutesWorkloadName(t *testing.T) {
	f := newFixture(t)
	other := startBackend(t, "other", issueLeaf(t, f.mesh, "other")) // stamped testDigest
	f.apply(t, simpleManifest(1, other.addr()))
	f.poll(t)

	f.renewRouter(t, digestOf(0x43))

	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / to a lagging backend naming another workload = %d, want 502", got)
	}
	if n := other.hits.Load(); n != 0 {
		t.Fatalf("backend naming another workload served %d requests, want 0", n)
	}
}

// TestDamagedRouterStampLeavesNoLaggingDigest: the value tracked for a leaf
// whose stamp does not parse names no allowlist, so the digest replacing it
// covers no backend.
func TestDamagedRouterStampLeavesNoLaggingDigest(t *testing.T) {
	f := newFixture(t)
	f.poll(t)
	f.renew(t, damagedStampLeaf(t))
	f.poll(t)

	f.renewRouter(t, digestOf(0x43))

	if got := f.transports.acceptedPrevious(); got != "" {
		t.Fatalf("acceptedPrevious() after a damaged stamp = %q, want none", got)
	}
}
