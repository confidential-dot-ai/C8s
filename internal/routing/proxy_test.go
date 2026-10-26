package routing

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
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
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"), func(c *tls.Config) {
		c.MinVersion = tls.VersionTLS12
		c.MaxVersion = tls.VersionTLS12
	})
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
	b := startBackend(t, "web", issueLeaf(t, rotated, "web"))
	f.apply(t, simpleManifest(1, b.addr()))
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / before the bundle holds the new CA = %d, want %d", got, http.StatusBadGateway)
	}
	// The reader paths of a generation the pointer does not name anchor
	// nothing: the rotation counts once it is published.
	if err := os.WriteFile(filepath.Join(f.volume, "ca.crt"), []byte(caPEM(rotated)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := f.get("/").Code; got != http.StatusBadGateway {
		t.Fatalf("GET / with the new CA on the reader path alone = %d, want %d", got, http.StatusBadGateway)
	}
	if n := b.hits.Load(); n != 0 {
		t.Fatalf("backend saw %d requests before the rotation was published, want 0", n)
	}
	// get-cert publishes the one mesh CA of the generation it adopted, so a
	// rotation replaces the bundle rather than adding to it.
	f.publish(t, caPEM(rotated))
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / after the bundle rotation = %d, want %d", got, http.StatusOK)
	}
}

func TestB3AddressBackend(t *testing.T) {
	f := newFixture(t)
	external := newCA(t, "external")
	b := startBackend(t, "admin", issueLeaf(t, external, "", "admin.ops.svc"), webPKI)
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
	admin := startBackend(t, "admin", issueLeaf(t, external, "", "admin.ops.svc"), webPKI)
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
			resp, err := f.proxy.Forward(outerRequest(tc.outerHost), types.TunnelRequest{Method: "GET", Path: "/x?q=1", Headers: tc.headers}, f.bound())
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
	if resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}, f.bound()); err != nil || resp.Status != http.StatusServiceUnavailable {
		t.Fatalf("Forward() before the first apply = %d, %v, want %d, nil (A2)", resp.Status, err, http.StatusServiceUnavailable)
	}
	bad := startBackend(t, "bad", issueLeaf(t, f.mesh, "impostor"))
	f.apply(t, simpleManifest(1, bad.addr()))
	if _, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}, f.bound()); err == nil {
		t.Fatal("Forward() to a backend failing B1 = nil error, want one (B5)")
	}
	resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/x|%2F..%2Fadmin", Headers: sealedHost}, f.bound())
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
		resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Method: "GET", Path: "/", Headers: headers}, f.bound())
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

// TestAcquireAdmitsManyRequests: the default budget admits hundreds of
// tunnelled requests from many clients at once, refuses the one it cannot
// cover, and takes it once another releases.
func TestAcquireAdmitsManyRequests(t *testing.T) {
	const record = 1 << 10
	p := NewProxy(ProxyConfig{})
	want := DefaultTunnelBudget / TunnelReservation(record)
	if want < 250 {
		t.Fatalf("default budget admits %d requests, want at least 250", want)
	}
	var releases []func()
	for i := range want {
		release, ok := p.Acquire(fmt.Sprint("client-", i%64), record)
		if !ok {
			t.Fatalf("Acquire(%d) number %d within the budget = false, want true", record, i+1)
		}
		releases = append(releases, release)
	}
	if _, ok := p.Acquire("late", record); ok {
		t.Fatalf("Acquire(%d) past the budget = true, want false", record)
	}
	releases[0]()
	if _, ok := p.Acquire("late", record); !ok {
		t.Fatalf("Acquire(%d) after a release = false, want true", record)
	}
}

// TestAcquireChargesCopies ties the reservation to the copies a request
// holds: three of its record and four of the largest response.
func TestAcquireChargesCopies(t *testing.T) {
	if got, want := TunnelReservation(MaxTunnelRecordBytes), int64(3*MaxTunnelRecordBytes+4*MaxTunnelResponseBytes); got != want {
		t.Fatalf("TunnelReservation(%d) = %d, want %d", MaxTunnelRecordBytes, got, want)
	}
	p := NewProxy(ProxyConfig{TunnelBudget: TunnelReservation(512) + TunnelReservation(0)})
	release, ok := p.Acquire("a", 512)
	if !ok {
		t.Fatal("Acquire(512) on a free proxy = false, want true")
	}
	if _, ok := p.Acquire("b", 1024); ok {
		t.Fatal("Acquire(1024) over the remaining budget = true, want false")
	}
	if _, ok := p.Acquire("b", 0); !ok {
		t.Fatal("Acquire(0) within the remaining budget = false, want true")
	}
	release()
}

// TestAcquireBoundsOneClientsShare: one client holds at most a quarter of
// the budget, so the others still get in.
func TestAcquireBoundsOneClientsShare(t *testing.T) {
	p := NewProxy(ProxyConfig{TunnelBudget: 8 * TunnelReservation(MaxTunnelRecordBytes)})
	var releases []func()
	for range 2 {
		release, ok := p.Acquire("greedy", MaxTunnelRecordBytes)
		if !ok {
			t.Fatal("Acquire(greedy) within its share = false, want true")
		}
		releases = append(releases, release)
	}
	if _, ok := p.Acquire("greedy", MaxTunnelRecordBytes); ok {
		t.Fatal("Acquire(greedy) over its share = true, want false")
	}
	if _, ok := p.Acquire("other", MaxTunnelRecordBytes); !ok {
		t.Fatal("Acquire(other) with budget left = false, want true")
	}
	releases[0]()
	if _, ok := p.Acquire("greedy", MaxTunnelRecordBytes); !ok {
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

// slowReader hands out at most 32 KiB per Read, after a pause.
type slowReader struct{ r io.Reader }

func (s slowReader) Read(p []byte) (int, error) {
	time.Sleep(4 * time.Millisecond)
	return s.r.Read(p[:min(len(p), 32<<10)])
}

// TestListenerTimeoutIsIdle: the routing listener's timeout spares a client
// that reads slower than the whole response could cross within it, and cuts
// off one that stops reading.
func TestListenerTimeoutIsIdle(t *testing.T) {
	const timeout = time.Second
	f := newFixture(t)
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Timeout: timeout})
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	ts := httptest.NewServer(f.proxy)
	t.Cleanup(ts.Close)

	t.Run("slow client", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/big", nil)
		req.Host = testHost
		start := time.Now()
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		n, err := io.Copy(io.Discard, slowReader{resp.Body})
		if err != nil || n != bigBytes {
			t.Fatalf("slow read of /big = %d bytes, %v, want %d bytes", n, err, bigBytes)
		}
		if elapsed := time.Since(start); elapsed < 2*timeout {
			t.Fatalf("slow read took %v, want over %v for the test to mean anything", elapsed, 2*timeout)
		}
		if err := <-web.bigDone; err != nil {
			t.Fatalf("backend write to a slow client = %v, want nil", err)
		}
	})
	t.Run("stalled client", func(t *testing.T) {
		conn, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET /endless HTTP/1.1\r\nHost: %s\r\n\r\n", testHost)
		select {
		case <-web.bigDone:
		case <-time.After(10 * timeout):
			t.Fatal("a client reading nothing still holds the request")
		}
	})
}

// TestListenerUpgradeIsIdle: an upgraded connection carrying traffic outlives
// the timeout, and one that goes quiet is closed after it.
func TestListenerUpgradeIsIdle(t *testing.T) {
	const timeout = 500 * time.Millisecond
	f := newFixture(t)
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports, Timeout: timeout})
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, web.addr()))
	ts := httptest.NewServer(f.proxy)
	t.Cleanup(ts.Close)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET /echo HTTP/1.1\r\nHost: %s\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n", testHost)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade GET /echo = %v, %v, want 101", resp, err)
	}
	start := time.Now()
	var quiet time.Time
	for i := 0; time.Since(start) < 4*timeout; i++ {
		time.Sleep(timeout / 5)
		// The proxy's last activity is its echo, after this write.
		quiet = time.Now()
		fmt.Fprintf(conn, "ping %d\n", i)
		if line, err := br.ReadString('\n'); err != nil || line != fmt.Sprintf("ping %d\n", i) {
			t.Fatalf("echo %d after %v = %q, %v, want it echoed", i, time.Since(start), line, err)
		}
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * timeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("read on a quiet upgraded connection = %v, want EOF", err)
	}
	if elapsed := time.Since(quiet); elapsed < timeout {
		t.Fatalf("quiet upgraded connection closed after %v, want at least %v", elapsed, timeout)
	}
}

// TestB8WorkloadBackendEntry: a workload backend stamped under another
// allowlist passes while its entry is unchanged in the current one, and is
// refused with backend_entry_changed when the entry was redefined or the
// stamped document cannot be fetched.
func TestB8WorkloadBackendEntry(t *testing.T) {
	f := newFixture(t)
	f.allowlists.store(digestOf(0x43), testAllowlist())
	f.allowlists.store(digestOf(0x44), labelled(map[string]string{"web": "v0"}))
	tests := []struct {
		name     string
		digest   []byte
		want     int
		wantBody string
	}{
		{"B8 current digest", testDigest, http.StatusOK, ""},
		{"B8 older digest, entry unchanged", digestOf(0x43), http.StatusOK, ""},
		{"B8 older digest, entry redefined", digestOf(0x44), http.StatusBadGateway, backendEntryChanged},
		{"B8 digest not in the history", digestOf(0x45), http.StatusBadGateway, backendEntryChanged},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", tc.digest))
			f.apply(t, simpleManifest(uint64(i+1), b.addr()))
			w := f.get("/")
			if w.Code != tc.want || !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("GET / = %d %q, want %d %q", w.Code, w.Body.String(), tc.want, tc.wantBody)
			}
			if tc.want == http.StatusOK {
				return
			}
			var logs bytes.Buffer
			f.proxy.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			sealedHost := []types.HeaderField{{Name: "Host", Value: testHost}}
			resp, err := f.proxy.Forward(outerRequest(testHost), types.TunnelRequest{Path: "/", Headers: sealedHost}, f.bound())
			if err != nil || resp.Status != tc.want || !strings.Contains(string(resp.Body), tc.wantBody) {
				t.Fatalf("Forward(/) = %d %q, %v, want %d %q, nil", resp.Status, resp.Body, err, tc.want, tc.wantBody)
			}
			// The listener and the tunnel log a refusal at Info: it is
			// expected for a backend not yet renewed after an allowlist write.
			if !strings.Contains(logs.String(), "backend request refused") || strings.Contains(logs.String(), "level=WARN") {
				t.Fatalf("tunnelled B8 refusal logged %q, want a backend request refused line at Info", logs.String())
			}
			if n := b.hits.Load(); n != 0 {
				t.Fatalf("backend saw %d requests after a refusal, want 0", n)
			}
		})
	}
}

// TestB8EntryRemoved: a backend whose entry the current allowlist no longer
// holds is refused, under its stamped digest or the current one.
func TestB8EntryRemoved(t *testing.T) {
	f := newFixture(t)
	b := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	f.apply(t, simpleManifest(1, b.addr()))
	f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"admin": "v1"}))
	f.refresh(t)
	if w := f.get("/"); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), backendEntryChanged) {
		t.Fatalf("GET / to a removed entry = %d %q, want 502 %q", w.Code, w.Body.String(), backendEntryChanged)
	}
	if n := b.hits.Load(); n != 0 {
		t.Fatalf("backend of a removed entry served %d requests, want 0", n)
	}
}

// TestB8NoCurrentAllowlist: until the router has read an allowlist, it
// refuses every workload backend and still serves address backends; a dial
// once the CDS answers reads it.
func TestB8NoCurrentAllowlist(t *testing.T) {
	f := newFixture(t)
	f.allowlists.down = errors.New("CDS unreachable")
	f.entries = NewEntries(f.allowlists)
	f.transports = NewTransports(TransportConfig{MeshIdentity: f.identity.Credential, Entries: f.entries})
	f.proxy = NewProxy(ProxyConfig{State: f.state, Transports: f.transports})
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	external := newCA(t, "external")
	admin := startBackend(t, "admin", issueLeaf(t, external, "", "admin.ops.svc"), webPKI)
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/", "prefix", web.addr(), "web"),
		addressRoute("/admin", "prefix", admin.addr(), "admin.ops.svc", caPEM(external)),
	}}})
	if w := f.get("/"); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), backendEntryChanged) {
		t.Fatalf("GET / before any allowlist read = %d %q, want 502 %q", w.Code, w.Body.String(), backendEntryChanged)
	}
	if got := f.get("/admin").Code; got != http.StatusOK {
		t.Fatalf("GET /admin before any allowlist read = %d, want %d", got, http.StatusOK)
	}
	f.allowlists.mu.Lock()
	f.allowlists.down = nil
	f.allowlists.mu.Unlock()
	f.entries.refreshGap = 0
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / once the CDS answers = %d, want %d", got, http.StatusOK)
	}
}

// TestB8RouterStampIsNotCompared: the router's own leaf, unstamped or
// stamped under any digest, does not decide the backend check; B1 still
// requires the route's workload name.
func TestB8RouterStampIsNotCompared(t *testing.T) {
	f := newFixture(t)
	b := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	unnamed := startBackend(t, "web", issueLeaf(t, f.mesh, "", "web.default.svc"))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/", "prefix", b.addr(), "web"),
		workloadRoute("/unnamed", "prefix", unnamed.addr(), "web"),
	}}})
	for _, leaf := range []tls.Certificate{issueLeaf(t, f.mesh, ""), issueStampedLeaf(t, f.mesh, "router", digestOf(0x43))} {
		f.renew(t, leaf)
		if err := f.transports.dropMeshPools(); err != nil {
			t.Fatal(err)
		}
		if got := f.get("/").Code; got != http.StatusOK {
			t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
		}
		if got := f.get("/unnamed").Code; got != http.StatusBadGateway {
			t.Fatalf("GET /unnamed = %d, want %d (B1 requires a name)", got, http.StatusBadGateway)
		}
	}
}

// TestB8RouterBehindTheCDS: a backend stamped under an allowlist newer than
// the one the router last read is accepted once a reread finds its entry, and
// a backend that keeps failing rereads at most once per gap.
func TestB8RouterBehindTheCDS(t *testing.T) {
	f := newFixture(t)
	f.entries.refreshGap = 0
	f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"web": "v1", "admin": "v1", "router": "v1", "new": "v1"}))
	b := startBackend(t, "new", issueStampedLeaf(t, f.mesh, "new", digestOf(0x43)))
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {workloadRoute("/", "prefix", b.addr(), "new")}}})
	if w := f.get("/"); w.Code != http.StatusOK {
		t.Fatalf("GET / to a backend stamped under an allowlist the router had not read = %d %q, want 200", w.Code, w.Body.String())
	}

	f.entries.refreshGap = time.Hour
	stale := startBackend(t, "new", issueStampedLeaf(t, f.mesh, "new", digestOf(0x45)))
	f.apply(t, manifestSpec{revision: 2, hosts: map[string][]route{testHost: {workloadRoute("/", "prefix", stale.addr(), "new")}}})
	reads := f.allowlists.read()
	for range 3 {
		if got := f.get("/").Code; got != http.StatusBadGateway {
			t.Fatalf("GET / to a backend under an unknown allowlist = %d, want %d", got, http.StatusBadGateway)
		}
	}
	if n := f.allowlists.read() - reads; n != 0 {
		t.Fatalf("failed checks reread the allowlist %d times within the gap, want 0", n)
	}
}

// TestB8HistoryCache: a stamped document is fetched once however many
// connections present it, and the bounded cache refetches one it evicted.
func TestB8HistoryCache(t *testing.T) {
	f := newFixture(t)
	f.allowlists.store(digestOf(0x43), testAllowlist())
	b := startBackend(t, "web", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, simpleManifest(1, b.addr()))
	for range 3 {
		if got := f.get("/").Code; got != http.StatusOK {
			t.Fatalf("GET / = %d, want %d", got, http.StatusOK)
		}
		f.transports.Retain(&routes.Manifest{}) // a fresh connection each time
	}
	if n := f.allowlists.fetched(); n != 1 {
		t.Fatalf("history fetches = %d, want 1", n)
	}

	ctx := context.Background()
	for i := range historyCacheSize {
		digest := digestOf(byte(0x50 + i))
		f.allowlists.store(digest, testAllowlist())
		if err := f.entries.Check(ctx, string(digest), "web"); err != nil {
			t.Fatal(err)
		}
	}
	fetched := f.allowlists.fetched()
	if err := f.entries.Check(ctx, string(digestOf(0x50)), "web"); err != nil {
		t.Fatal(err)
	}
	if n := f.allowlists.fetched(); n != fetched {
		t.Fatalf("a cached document was fetched again (%d fetches, want %d)", n, fetched)
	}
	if err := f.entries.Check(ctx, string(digestOf(0x43)), "web"); err != nil {
		t.Fatal(err)
	}
	if n := f.allowlists.fetched(); n != fetched+1 {
		t.Fatalf("an evicted document took %d fetches, want 1", n-fetched)
	}

	f.allowlists.fail = errors.New("CDS unreachable")
	if err := f.entries.Check(ctx, string(digestOf(0x46)), "web"); !errors.Is(err, errEntryChanged) {
		t.Fatalf("Check() with the history unreachable = %v, want %v", err, errEntryChanged)
	}
}

// TestB10ChangedEntryRetiresPools: an allowlist write retires, at the next
// poll, the pools of the workloads whose entry it redefined or removed, and
// keeps the others and the address backends'.
func TestB10ChangedEntryRetiresPools(t *testing.T) {
	f := newFixture(t)
	web := startBackend(t, "web", issueLeaf(t, f.mesh, "web"))
	admin := startBackend(t, "admin", issueLeaf(t, f.mesh, "admin"))
	external := newCA(t, "external")
	ext := startBackend(t, "ext", issueLeaf(t, external, "", "ext.ops.svc"), webPKI)
	f.apply(t, manifestSpec{revision: 1, hosts: map[string][]route{testHost: {
		workloadRoute("/", "prefix", web.addr(), "web"),
		workloadRoute("/admin", "prefix", admin.addr(), "admin"),
		addressRoute("/ext", "prefix", ext.addr(), "ext.ops.svc", caPEM(external)),
	}}})
	for _, path := range []string{"/", "/admin", "/ext"} {
		if got := f.get(path).Code; got != http.StatusOK {
			t.Fatalf("GET %s = %d, want %d", path, got, http.StatusOK)
		}
	}
	backends := f.state.Current().Manifest.Hosts[testHost].Routes
	before := map[string]*http.Transport{}
	for _, r := range backends {
		before[r.Path] = f.transports.For(r.Backend, nil)
	}

	f.allowlists.serve(digestOf(0x43), labelled(map[string]string{"web": "v2", "admin": "v1", "router": "v1"}))
	f.refresh(t)
	for _, r := range backends {
		if kept := f.transports.For(r.Backend, nil) == before[r.Path]; kept != (r.Path != "/") {
			t.Fatalf("transport of %s kept = %v after only web was redefined", r.Path, kept)
		}
	}
	if w := f.get("/"); w.Code != http.StatusBadGateway || !strings.Contains(w.Body.String(), backendEntryChanged) {
		t.Fatalf("GET / after web was redefined = %d %q, want 502 %q", w.Code, w.Body.String(), backendEntryChanged)
	}
	if got := f.get("/admin").Code; got != http.StatusOK {
		t.Fatalf("GET /admin after an unrelated write = %d, want %d", got, http.StatusOK)
	}

	renewed := startBackend(t, "renewed", issueStampedLeaf(t, f.mesh, "web", digestOf(0x43)))
	f.apply(t, manifestSpec{revision: 2, hosts: map[string][]route{testHost: {
		workloadRoute("/", "prefix", renewed.addr(), "web"),
	}}})
	if got := f.get("/").Code; got != http.StatusOK {
		t.Fatalf("GET / to a backend renewed under the new allowlist = %d, want %d", got, http.StatusOK)
	}
}
