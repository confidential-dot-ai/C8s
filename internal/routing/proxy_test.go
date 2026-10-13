package routing

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestB1WorkloadBackend(t *testing.T) {
	f := newFixture(t)
	other := newCA(t, "other")
	tests := []struct {
		name string
		leaf tls.Certificate
		want int
	}{
		{"B1 matching name", issueLeaf(t, f.mesh, "web"), http.StatusOK},
		{"B1 other name", issueLeaf(t, f.mesh, "admin"), http.StatusBadGateway},
		{"B1 no name", issueLeaf(t, f.mesh, "", "web.default.svc"), http.StatusBadGateway},
		{"B1 chain to another CA", issueLeaf(t, other, "web"), http.StatusBadGateway},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := startBackend(t, "web", tc.leaf)
			f.apply(t, simpleManifest(uint64(i+1), b.addr()))
			if got := f.get("/").Code; got != tc.want {
				t.Fatalf("GET / = %d, want %d", got, tc.want)
			}
			if tc.want != http.StatusOK && b.hits.Load() != 0 {
				t.Fatalf("backend saw %d requests after a failed verification, want 0", b.hits.Load())
			}
		})
	}
}

func TestB1RequiresTLS13(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"), func(c *tls.Config) { c.MaxVersion = tls.VersionTLS12 })
	f.apply(t, simpleManifest(1, web.addr()))
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / to a TLS 1.2 workload backend = %d, want %d", got, http.StatusBadGateway)
	}
	if got := web.hits.Load(); got != 0 {
		t.Fatalf("TLS 1.2 workload backend served %d requests, want 0", got)
	}
}

func TestB1PicksUpRotatedMeshCA(t *testing.T) {
	f := newFixture(t)
	rotated := newCA(t, "mesh-2")
	caFile := writeFile(t, "ca.pem", []byte(caPEM(f.mesh)))
	f.transports = NewTransports(TransportConfig{
		MeshCAs:           CAFile(caFile),
		ClientCertificate: f.transports.cfg.ClientCertificate,
	})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports})
	b := startBackend(t, "web", issueLeaf(t, rotated, "web"))
	f.apply(t, simpleManifest(1, b.addr()))
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / before the bundle holds the new CA = %d, want %d", got, http.StatusBadGateway)
	}
	if err := os.WriteFile(caFile, []byte(caPEM(f.mesh, rotated)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / after the bundle rotation = %d, want %d", got, http.StatusOK)
	}
}

func TestB3AddressBackend(t *testing.T) {
	f := newFixture(t)
	external := newCA(t, "external")
	b := startBackend(t, "admin", issueLeaf(t, external, "", "admin.ops.svc"))
	tests := []struct {
		name       string
		serverName string
		ca         string
		want       int
	}{
		{"B3 right CA and name", "admin.ops.svc", caPEM(external), http.StatusOK},
		{"B3 wrong name", "other.ops.svc", caPEM(external), http.StatusBadGateway},
		{"B3 wrong CA", "admin.ops.svc", caPEM(newCA(t, "unrelated")), http.StatusBadGateway},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.apply(t, manifestSpec{revision: uint64(i + 1), hosts: map[string][]route{
				testHost: {addressRoute("/", "prefix", b.addr(), tc.serverName, tc.ca)},
			}})
			if got := f.get("/").Code; got != tc.want {
				t.Fatalf("GET / = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestB4PresentsMeshLeaf(t *testing.T) {
	f := newFixture(t)
	external := newCA(t, "external")
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	admin := startBackend(t, "admin", issueLeaf(t, external, "", "admin.ops.svc"))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/", "prefix", web.addr(), "web"),
		addressRoute("/admin", "prefix", admin.addr(), "admin.ops.svc", caPEM(external)),
	}}})
	for _, tc := range []struct {
		path string
		b    *testBackend
	}{{"/", web}, {"/admin", admin}} {
		if got := f.get(tc.path).Code; got != http.StatusOK {
			t.Fatalf("GET %s = %d, want %d", tc.path, got, http.StatusOK)
		}
		got := tc.b.seen().clientCert
		if got == nil || !got.Equal(f.routerLeaf.Leaf) {
			t.Fatalf("%s backend client certificate = %v, want the router's mesh leaf (B4)", tc.b.name, got)
		}
	}
}

func TestB5NoFallback(t *testing.T) {
	f := newFixture(t)
	good := startBackend(t, "good", issueLeaf(t, f.mesh, "web"))
	bad := startBackend(t, "bad", issueLeaf(t, f.mesh, "impostor"))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/", "prefix", good.addr(), "web"),
		workloadRoute("/api", "prefix", bad.addr(), "web"),
	}}})
	if got := f.get("/api/x").Code; got != http.StatusBadGateway {
		t.Fatalf("GET /api/x = %d, want %d", got, http.StatusBadGateway)
	}
	if n := good.hits.Load(); n != 0 {
		t.Fatalf("other route's backend saw %d requests, want 0 (B5)", n)
	}
}

func TestB6M4M5Paths(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	admin := startBackend(t, "admin", issueLeaf(t, f.mesh, "admin"))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/app", "prefix", web.addr(), "web"),
		workloadRoute("/admin", "prefix", admin.addr(), "admin"),
	}}})
	tests := []struct {
		name    string
		target  string
		want    int
		backend *testBackend
		wantURI string
	}{
		{"B6 dot segments normalized", "/app/x/../y?q=1&b=%2F", http.StatusOK, web, "/app/y?q=1&b=%2F"},
		{"B6 unreserved escape decoded", "/%61pp/a%2Cb", http.StatusOK, web, "/app/a%2Cb"},
		{"M4 encoded slash then dot segments", "/x|%2F..%2Fadmin", http.StatusNotFound, nil, ""},
		{"M4 encoded slash", "/app%2F..%2Fadmin", http.StatusNotFound, nil, ""},
		{"M5 no route", "/other", http.StatusNotFound, nil, ""},
		{"M6 reserved path", "/allowlist", http.StatusNotFound, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hits := admin.hits.Load()
			if got := f.get(tc.target).Code; got != tc.want {
				t.Fatalf("GET %s = %d, want %d", tc.target, got, tc.want)
			}
			if tc.backend == nil {
				if admin.hits.Load() != hits {
					t.Fatalf("GET %s reached the admin backend", tc.target)
				}
				return
			}
			if got := tc.backend.seen().requestURI; got != tc.wantURI {
				t.Fatalf("GET %s forwarded as %q, want %q", tc.target, got, tc.wantURI)
			}
		})
	}
}

func TestM1HostSelection(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	for _, tc := range []struct {
		host string
		want int
	}{{"APP.example:443", http.StatusOK}, {"other.example", http.StatusNotFound}} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		f.proxy.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("GET / with Host %q = %d, want %d", tc.host, w.Code, tc.want)
		}
	}
	if got := web.seen().host; got != "APP.example:443" {
		t.Fatalf("backend Host = %q, want the request host", got)
	}
}

func TestA7M1TunnelHost(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	admin := startBackend(t, "admin", issueLeaf(t, f.mesh, "admin"))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{
		testHost:        {workloadRoute("/", "prefix", web.addr(), "web")},
		"admin.example": {workloadRoute("/", "prefix", admin.addr(), "admin")},
	}})
	host := func(v string) []types.HeaderField { return []types.HeaderField{{Name: "Host", Value: v}} }
	tests := []struct {
		name      string
		outerHost string
		headers   []types.HeaderField
		wantCode  int
		wantBody  string
	}{
		{"M1 outer host cannot redirect", "admin.example", host(testHost), http.StatusOK, "web"},
		{"M1 no sealed Host", "admin.example", nil, http.StatusBadRequest, ""},
		{"M1 sealed host unknown", testHost, host("other.example"), http.StatusNotFound, ""},
		{"M1 two sealed Hosts", testHost, append(host(testHost), host("admin.example")...), http.StatusBadRequest, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := f.proxy.Forward(outerRequest(tc.outerHost), types.TunnelRequest{Method: "GET", Path: "/x?q=1", Headers: tc.headers})
			if err != nil {
				t.Fatalf("Forward() = %v, want nil", err)
			}
			if resp.Status != tc.wantCode {
				t.Fatalf("Forward() status = %d, want %d", resp.Status, tc.wantCode)
			}
			if tc.wantBody != "" && string(resp.Body) != tc.wantBody {
				t.Fatalf("Forward() body = %q, want %q", resp.Body, tc.wantBody)
			}
		})
	}
	if n := admin.hits.Load(); n != 0 {
		t.Fatalf("admin backend served %d tunnel requests, want 0: the outer host must not route (M1)", n)
	}
	if got := web.seen().requestURI; got != "/x?q=1" {
		t.Fatalf("tunnel request forwarded as %q, want %q (B6)", got, "/x?q=1")
	}
}

func TestA7TunnelPaths(t *testing.T) {
	f := newFixture(t)
	sealedHost := []types.HeaderField{{Name: "Host", Value: testHost}}
	if resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}); err != nil || resp.Status != http.StatusServiceUnavailable {
		t.Fatalf("Forward() before the first apply = %d, %v, want %d, nil (A2)", resp.Status, err, http.StatusServiceUnavailable)
	}
	bad := startBackend(t, "bad", issueLeaf(t, f.mesh, "impostor"))
	f.apply(t, simpleManifest(1, bad.addr()))
	if _, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}); err == nil {
		t.Fatal("Forward() to a backend failing B1 = nil error, want one (B5)")
	}
	resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/x|%2F..%2Fadmin", Headers: sealedHost})
	if err != nil || resp.Status != http.StatusNotFound {
		t.Fatalf("Forward(/x|%%2F..%%2Fadmin) = %d, %v, want %d, nil (M4)", resp.Status, err, http.StatusNotFound)
	}
}

// TestA5SwapUnderLoad swaps manifests while requests and handshakes run. Run
// with -race: every request must land on a backend some applied manifest named
// for it, and every handshake must see a whole manifest.
func TestA5SwapUnderLoad(t *testing.T) {
	f := newFixture(t)
	backends := []*testBackend{
		startBackend(t, "even", issueLeaf(t, f.mesh, "web")),
		startBackend(t, "odd", issueLeaf(t, f.mesh, "web")),
	}
	manifest := func(rev uint64) manifestSpec { return simpleManifest(rev, backends[rev%2].addr()) }
	f.apply(t, manifest(1))
	srv := httptest.NewServer(f.proxy)
	t.Cleanup(srv.Close)

	var stop atomic.Bool
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
				req.Host = testHost
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errs <- err
					return
				}
				body := make([]byte, 8)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()
				if got := string(body[:n]); resp.StatusCode != http.StatusOK || (got != "even" && got != "odd") {
					errs <- fmt.Errorf("GET / = %d %q, want 200 from a named backend", resp.StatusCode, got)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for !stop.Load() {
				a, err := f.state.Session()
				if err != nil {
					errs <- fmt.Errorf("Session() = %v, want nil", err)
					return
				}
				rev := a.Manifest.Revision
				r, _, ok := a.Table.Select(&http.Request{Host: testHost, RequestURI: "/"})
				if !ok || r.Backend.Address != backends[rev%2].addr() {
					errs <- fmt.Errorf("revision %d table routes to %q, want %q", rev, r.Backend.Address, backends[rev%2].addr())
					return
				}
			}
		}()
	}
	for rev := uint64(2); rev <= 40; rev++ {
		f.apply(t, manifest(rev))
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// outerRequest is the tunnel POST as nginx hands it to cds-attest.
func outerRequest(host string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/.well-known/c8s/tunnel", nil)
	r.Host = host
	r.Header.Set("X-Real-IP", "203.0.113.7")
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	r.Header.Set("X-Forwarded-Proto", "https")
	return r
}

func TestA7TunnelSealedHeaders(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	forward := func(headers ...types.HeaderField) types.TunnelResponse {
		t.Helper()
		resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Method: "GET", Path: "/", Headers: headers})
		if err != nil {
			t.Fatalf("Forward() = %v, want nil", err)
		}
		return resp
	}

	resp := forward(
		types.HeaderField{Name: "Host", Value: testHost},
		types.HeaderField{Name: "X-Real-IP", Value: "1.2.3.4"},
		types.HeaderField{Name: "X-Forwarded-For", Value: "1.2.3.4"},
		types.HeaderField{Name: "Forwarded", Value: "for=1.2.3.4"},
		types.HeaderField{Name: "X-C8s-Exporter", Value: "exporter"},
		types.HeaderField{Name: "Connection", Value: "X-C8s-Exporter"},
	)
	if resp.Status != http.StatusOK {
		t.Fatalf("Forward() status = %d, want %d", resp.Status, http.StatusOK)
	}
	h := web.seen().header
	for name, want := range map[string]string{
		"X-Real-Ip":         "203.0.113.7",
		"X-Forwarded-For":   "203.0.113.7",
		"X-Forwarded-Proto": "https",
		"Forwarded":         "",
		"X-C8s-Exporter":    "exporter",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("backend %s = %q, want %q", name, got, want)
		}
	}

	hits := web.hits.Load()
	if resp := forward(types.HeaderField{Name: "Host", Value: testHost}, types.HeaderField{Name: "Upgrade", Value: "websocket"}, types.HeaderField{Name: "Connection", Value: "Upgrade"}); resp.Status != http.StatusBadRequest {
		t.Fatalf("Forward(sealed Upgrade) status = %d, want %d", resp.Status, http.StatusBadRequest)
	}
	if web.hits.Load() != hits {
		t.Fatal("Forward(sealed Upgrade) reached the backend")
	}
}

func TestAcquireBoundsTunnelSlots(t *testing.T) {
	p := NewProxy(ProxyConfig{TunnelSlots: 1})
	release, ok := p.Acquire("a")
	if !ok {
		t.Fatal("Acquire() on a free proxy = false, want true")
	}
	if _, ok := p.Acquire("b"); ok {
		t.Fatal("Acquire() with every slot taken = true, want false")
	}
	release()
	if _, ok := p.Acquire("b"); !ok {
		t.Fatal("Acquire() after release = false, want true")
	}
}

// One client holds at most its share of the slots, so the others still get in.
func TestAcquireBoundsOneClientsShare(t *testing.T) {
	p := NewProxy(ProxyConfig{TunnelSlots: 8})
	var releases []func()
	for range 2 {
		release, ok := p.Acquire("greedy")
		if !ok {
			t.Fatal("Acquire(greedy) within its share = false, want true")
		}
		releases = append(releases, release)
	}
	if _, ok := p.Acquire("greedy"); ok {
		t.Fatal("Acquire(greedy) over its share = true, want false")
	}
	if _, ok := p.Acquire("other"); !ok {
		t.Fatal("Acquire(other) with free slots = false, want true")
	}
	releases[0]()
	if _, ok := p.Acquire("greedy"); !ok {
		t.Fatal("Acquire(greedy) after a release = false, want true")
	}
}

// TestListenerDropsClientExporter: only the tunnel sets X-C8s-Exporter, which
// TestA7TunnelSealedHeaders shows it forwarding.
func TestListenerDropsClientExporter(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = testHost
	r.Header.Set("X-C8s-Exporter", "forged")
	w := httptest.NewRecorder()
	f.proxy.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want %d", w.Code, http.StatusOK)
	}
	if got := web.seen().header.Values("X-C8s-Exporter"); len(got) != 0 {
		t.Fatalf("backend X-C8s-Exporter = %q, want none", got)
	}
}
