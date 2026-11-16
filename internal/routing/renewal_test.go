package routing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func (f *fixture) getExpecting(digest []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testHost
	r.Header.Set(ExpectAllowlistHeader, hex.EncodeToString(digest))
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	return w
}

func TestHeaderRefusesRenewalBetweenAdmissionAndDial(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, web.addr()))
	bindings := newFakeBindings(map[string]Binding{"bound": f.bound(t)})
	f.proxy.bindings = bindings
	before, err := f.identity.Credential()
	if err != nil {
		t.Fatal(err)
	}
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	after, err := f.identity.Credential()
	if err != nil {
		t.Fatal(err)
	}
	var reads atomic.Int32
	f.transports.cfg.MeshIdentity = func() (MeshCredential, error) {
		if reads.Add(1) == 1 {
			return before, nil
		}
		return after, nil
	}
	w := f.getExpecting(testDigest)
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("header request after renewal = %d %q, want 503 router_digest_changed", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 0 {
		t.Fatalf("backend requests = %d, want 0", hits)
	}
	if len(bindings.held) != 0 || len(bindings.released) != 0 || len(bindings.refused) != 0 {
		t.Fatalf("header request touched bindings: %+v", bindings)
	}
}

func TestHeaderRefusesAPoolUnderAnotherDigest(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	bound := f.bound(t)
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	if _, ok := f.transports.ForRouterDigest(backend, bound.RouterDigest); !ok {
		t.Fatal("pool refused the current digest")
	}
	key := poolKey{backend: backendKey(backend), pinned: true}
	f.transports.mu.Lock()
	pool := f.transports.cache[key]
	pool.routerDigest = string(digestOf(0x43))
	f.transports.cache[key] = pool
	f.transports.mu.Unlock()
	w := f.getExpecting(testDigest)
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("header request through another digest's pool = %d %q, want 503 router_digest_changed", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 0 {
		t.Fatalf("backend requests = %d, want 0", hits)
	}
}

func TestBindingAndHeaderMustPinTheSameDigest(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, web.addr()))
	bound := f.bound(t)
	bound.RouterDigest = string(digestOf(0x43))
	bindings := newFakeBindings(map[string]Binding{"bound": bound})
	f.proxy.bindings = bindings
	before, err := f.identity.Credential()
	if err != nil {
		t.Fatal(err)
	}
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	var reads atomic.Int32
	f.transports.cfg.MeshIdentity = func() (MeshCredential, error) {
		if reads.Add(1) == 1 {
			return before, nil
		}
		return f.identity.Credential()
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testHost
	r.Header.Set(ConnectionHeader, "bound")
	r.Header.Set(ExpectAllowlistHeader, hex.EncodeToString(testDigest))
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("request with different header and binding digests = %d %q, want 503 router_digest_changed", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 0 || bindings.refused["bound"] != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("backend requests = %d, refusal = %q; want 0, router_digest_changed", hits, bindings.refused["bound"])
	}
}

func TestUnpinnedRequestsSurviveRepeatedRenewals(t *testing.T) {
	for _, tc := range []struct {
		name      string
		closeIdle bool
	}{
		{name: "warm connections"},
		{name: "new connections", closeIdle: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
			f.apply(t, simpleManifest(1, web.addr()))
			backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
			doc := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{"web": entryOf(t, 1)}}
			history := &fakeHistory{
				calls: map[[sha256.Size]byte]int{},
				docs:  map[[sha256.Size]byte]*allowlist.Allowlist{[sha256.Size]byte(testDigest): doc},
			}
			for generation := byte(0x43); generation < 0x4b; generation++ {
				history.docs[[sha256.Size]byte(digestOf(generation))] = doc
			}
			f.transports.entries = &entryDocs{src: history}
			if err := f.transports.syncRouterDigest(); err != nil {
				t.Fatal(err)
			}
			if w := f.get("/"); w.Code != http.StatusOK {
				t.Fatalf("warmup = %d %q, want 200", w.Code, w.Body.String())
			}
			wantHits := int64(1)
			for generation := byte(0x43); generation < 0x4b; generation++ {
				if tc.closeIdle {
					f.transports.For(backend).CloseIdleConnections()
				}
				f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(generation)))
				for _, requests := range []int{4, 1} {
					start := make(chan struct{})
					responses := make(chan *httptest.ResponseRecorder, requests)
					for range requests {
						go func() {
							<-start
							responses <- f.get("/")
						}()
					}
					close(start)
					for range requests {
						w := <-responses
						if w.Code != http.StatusOK {
							t.Errorf("unpinned request under %x = %d %q, want 200", generation, w.Code, w.Body.String())
						}
					}
					wantHits += int64(requests)
				}
			}
			if hits := web.hits.Load(); hits != wantHits {
				t.Fatalf("backend requests = %d, want %d", hits, wantHits)
			}
		})
	}
}

func TestRenewalKeepsPinnedAndUnpinnedConnectionsSeparate(t *testing.T) {
	f := newFixture(t)
	renewedDigest := digestOf(0x43)
	web := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", renewedDigest))
	f.apply(t, simpleManifest(1, web.addr()))
	bindings := newFakeBindings(map[string]Binding{"bound": f.bound(t)})
	f.proxy.bindings = bindings
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	old := f.transports.For(backend)
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", renewedDigest))
	if w := f.get("/"); w.Code != http.StatusOK {
		t.Fatalf("unpinned request after renewal = %d %q, want 200", w.Code, w.Body.String())
	}
	retiredConnection := web.seen().remoteAddr
	unpinned := f.transports.For(backend)
	if unpinned == old {
		t.Fatal("renewal left the old pool selectable")
	}
	if w := f.get("/"); w.Code != http.StatusOK {
		t.Fatalf("unpinned request on the fresh pool = %d %q, want 200", w.Code, w.Body.String())
	}
	unpinnedConnection := web.seen().remoteAddr
	if unpinnedConnection == retiredConnection {
		t.Fatal("fresh pool reused a retired pool's connection")
	}
	w := f.getOn("bound")
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != types.ErrorCodeRouterDigestChanged {
		t.Fatalf("old binding after renewal = %d %q, want 503 router_digest_changed", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 2 {
		t.Fatalf("backend requests after binding refusal = %d, want 2", hits)
	}
	if w := f.getExpecting(renewedDigest); w.Code != http.StatusOK {
		t.Fatalf("header request under the renewed digest = %d %q, want 200", w.Code, w.Body.String())
	}
	pinned, ok := f.transports.ForRouterDigest(backend, string(renewedDigest))
	if !ok || pinned == unpinned || web.seen().remoteAddr == unpinnedConnection {
		t.Fatal("header request did not use a separate pinned pool and connection")
	}
	stamp, err := armtls.MatchedWorkloadFromCert(web.seen().clientCert)
	if err != nil || stamp == nil || !bytes.Equal(stamp.AllowlistDigest, renewedDigest) {
		t.Fatalf("pinned connection stamp = %+v, %v, want digest %x", stamp, err, renewedDigest)
	}
	pinnedConnection := web.seen().remoteAddr
	if w := f.getExpecting(renewedDigest); w.Code != http.StatusOK || web.seen().remoteAddr != pinnedConnection {
		t.Fatalf("second header request = %d %q, want 200 on the pinned connection", w.Code, w.Body.String())
	}
	bindings.entries["renewed"] = f.bound(t)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testHost
	r.Header.Set(ConnectionHeader, "renewed")
	r.Header.Set(ExpectAllowlistHeader, hex.EncodeToString(renewedDigest))
	w = httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK || web.seen().remoteAddr != pinnedConnection {
		t.Fatalf("matching header and binding = %d %q, want 200 on the pinned connection", w.Code, w.Body.String())
	}
}

func TestUnpinnedRenewalChecksTheBackendEntry(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	f.transports.entries = &entryDocs{src: &fakeHistory{
		calls: map[[sha256.Size]byte]int{},
		docs: map[[sha256.Size]byte]*allowlist.Allowlist{
			[sha256.Size]byte(testDigest):     {Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{"web": entryOf(t, 1)}},
			[sha256.Size]byte(digestOf(0x43)): {Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{"web": entryOf(t, 2)}},
		},
	}}
	if err := f.transports.syncRouterDigest(); err != nil {
		t.Fatal(err)
	}
	f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
	w := f.get("/")
	if w.Code != http.StatusBadGateway || strings.TrimSpace(w.Body.String()) != backendDigestMismatch {
		t.Fatalf("unpinned request to a redefined backend = %d %q, want 502 backend_digest_mismatch", w.Code, w.Body.String())
	}
	if hits := web.hits.Load(); hits != 0 {
		t.Fatalf("backend requests = %d, want 0", hits)
	}
}

func TestAddressBackendSharesOnePoolForEveryPin(t *testing.T) {
	f := newFixture(t)
	ca := newCA(t, "address backend")
	web := startBackend(t, "web", issueLeaf(t, ca, "", "backend.example"), webPKI)
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		addressRoute("/", "prefix", web.addr(), "backend.example", caPEM(ca)),
	}}})
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	unpinned := f.transports.For(backend)
	for _, digest := range []string{"", string(testDigest), string(digestOf(0x43))} {
		pinned, ok := f.transports.ForRouterDigest(backend, digest)
		if !ok || pinned != unpinned {
			t.Fatalf("address backend pool for digest %x differs from its unpinned pool", digest)
		}
	}
	if len(f.transports.cache) != 1 {
		t.Fatalf("address backend pools = %d, want 1", len(f.transports.cache))
	}
}

func TestPinnedPoolChecksItsTagBeforeTheFirstCredentialRead(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	backend := f.state.Current().Manifest.Hosts[testHost].Routes[0].Backend
	pool, ok := f.transports.ForRouterDigest(backend, "")
	if !ok {
		t.Fatal("pool refused the tracked empty digest")
	}
	request := httptest.NewRequest(http.MethodGet, "https://"+web.addr(), nil)
	response, err := pool.RoundTrip(request)
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, errRouterRenewed) || web.hits.Load() != 0 {
		t.Fatalf("empty pin under a stamped leaf: err = %v, backend requests = %d; want renewal refusal and 0", err, web.hits.Load())
	}
}

func TestWorkloadPoolRetirementCoversBothPools(t *testing.T) {
	for _, event := range []string{"expiry", "mesh CA", "router digest", "manifest removal", "read failure", "damaged stamp"} {
		t.Run(event, func(t *testing.T) {
			f := newFixture(t)
			web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
			f.apply(t, simpleManifest(1, web.addr()))
			bound := f.bound(t)
			if w := f.get("/"); w.Code != http.StatusOK {
				t.Fatalf("unpinned warmup = %d %q", w.Code, w.Body.String())
			}
			if w := f.getExpecting(testDigest); w.Code != http.StatusOK {
				t.Fatalf("pinned warmup = %d %q", w.Code, w.Body.String())
			}
			connection := web.seen().remoteAddr
			manifest := f.state.Current().Manifest
			backend := manifest.Hosts[testHost].Routes[0].Backend
			unpinned := f.transports.For(backend)
			pinned, _ := f.transports.ForRouterDigest(backend, bound.RouterDigest)
			f.transports.Retain(manifest)
			kept, ok := f.transports.ForRouterDigest(backend, bound.RouterDigest)
			if !ok || kept != pinned || f.transports.For(backend) != unpinned {
				t.Fatal("Retain removed a pool named by the manifest")
			}
			switch event {
			case "expiry":
				f.transports.mu.Lock()
				f.transports.leafExpiry = time.Now().Add(-time.Second)
				f.transports.mu.Unlock()
			case "mesh CA":
				f.mesh = newCA(t, "renewed mesh")
				f.renew(t, issueLeaf(t, f.mesh, "router"))
			case "router digest":
				f.renew(t, issueStampedLeaf(t, f.mesh, "router", digestOf(0x43)))
			case "manifest removal":
				f.transports.Retain(&routes.Manifest{})
			case "read failure":
				f.publish(t, "garbage")
				if w := f.getExpecting(testDigest); w.Code != http.StatusBadGateway {
					t.Fatalf("header request with unreadable credentials = %d %q, want 502", w.Code, w.Body.String())
				}
				kept, ok := f.transports.ForRouterDigest(backend, bound.RouterDigest)
				if !ok || kept != pinned || f.transports.For(backend) != unpinned {
					t.Fatal("failed request read retired a pool")
				}
			case "damaged stamp":
				f.renew(t, damagedStampLeaf(t))
			}
			if err := f.transports.dropMeshPools(); (err != nil) != (event == "read failure") {
				t.Fatalf("dropMeshPools() after %s = %v", event, err)
			}
			fresh, ok := f.transports.ForRouterDigest(backend, f.transports.RouterDigest())
			if !ok || fresh == pinned || f.transports.For(backend) == unpinned {
				t.Fatal("retirement kept a workload pool")
			}
			if event == "expiry" {
				if w := f.getExpecting(testDigest); w.Code != http.StatusOK || web.seen().remoteAddr == connection {
					t.Fatalf("request after expiry = %d %q, want 200 on a fresh connection", w.Code, w.Body.String())
				}
			}
		})
	}
}
