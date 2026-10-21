package cdsattest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/routing"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// routedServer is a cds-attest server whose tunnel routes by a manifest,
// with a workload backend "web" holding a named leaf from the mesh CA. Its
// /big answers with bigResponseBytes.
type routedServer struct {
	ts       *httptest.Server
	state    *routing.State
	clock    *testClock
	signer   *operatorauth.Signer
	keys     []*ecdsa.PublicKey
	backend  string
	lastHost chan string
}

const bigResponseBytes = 24 << 20

func newRoutedServer(t *testing.T, opts ...func(*routing.ProxyConfig, *Config)) *routedServer {
	t.Helper()
	identity := writeTestMeshIdentity(t)
	// The engine's own mesh CA: the test identity's CA key is not kept.
	ca, err := issuer.NewCA("mesh", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certutil.EncodeCertPEM(ca.Cert.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	routerLeaf := namedLeaf(t, ca, "router")
	rs := &routedServer{clock: &testClock{now: time.Now()}, lastHost: make(chan string, 16)}

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big" {
			_, _ = w.Write(make([]byte, bigResponseBytes))
			return
		}
		rs.lastHost <- r.Host
		_, _ = io.WriteString(w, "web saw "+r.RequestURI)
	}))
	// A member backend serves the mesh profile: its endpoint holds its leaf,
	// answers the mesh protocol and carries plain HTTP inside it.
	testutil.ServeMeshBackend(backend, namedLeaf(t, ca, "web"))
	backend.StartTLS()
	t.Cleanup(backend.Close)
	rs.backend = strings.TrimPrefix(backend.URL, "https://")

	opKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(opKey)
	if err != nil {
		t.Fatal(err)
	}
	if rs.signer, err = operatorauth.NewSignerFromKeyPEM(keyPEM); err != nil {
		t.Fatal(err)
	}
	rs.keys = []*ecdsa.PublicKey{&opKey.PublicKey}

	meshCAs := routing.CAFile(caFile)
	clientCert := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &routerLeaf, nil }
	rs.state = routing.NewState(routing.StateConfig{Reserved: defaultReservedPaths, MeshCAs: meshCAs, Now: rs.clock.Now})
	proxyCfg := routing.ProxyConfig{
		State:      rs.state,
		Transports: routing.NewTransports(routing.TransportConfig{MeshCAs: meshCAs, ClientCertificate: clientCert}),
	}
	certPath, _ := writeTestServingLeaf(t)
	srvCfg := Config{
		Logger:               slog.New(slog.DiscardHandler),
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		ServingCertFile:      certPath,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
	}
	for _, opt := range opts {
		opt(&proxyCfg, &srvCfg)
	}
	srvCfg.Routes = routing.NewProxy(proxyCfg)
	rs.ts = httptest.NewServer(NewServer(srvCfg).Handler())
	t.Cleanup(rs.ts.Close)
	return rs
}

// testSandboxID is the workload instance a member leaf names.
const testSandboxID = "8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f6c2b1a0e8d9f"

func namedLeaf(t *testing.T, ca *issuer.CA, workload string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: workload}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := ca.SignCSR(issuer.SignCSRParams{CSR: csr, TTL: 30 * time.Minute, SandboxID: testSandboxID, MatchedWorkload: &armtls.MatchedWorkload{
		Name: workload, AllowlistVersion: "1", AllowlistDigest: bytes.Repeat([]byte{0x42}, 32),
	}})
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

// apply signs a manifest routing app.example to the web backend.
func (rs *routedServer) apply(t *testing.T, revision uint64, maxAge time.Duration) {
	t.Helper()
	manifest, err := json.Marshal(map[string]any{
		"schema":        routes.Schema,
		"revision":      revision,
		"notBefore":     "2020-01-01T00:00:00Z",
		"maxAgeSeconds": int(maxAge / time.Second),
		"hosts": map[string]any{"app.example": map[string]any{"routes": []any{
			map[string]any{"path": "/", "match": "prefix", "backend": map[string]string{"address": rs.backend, "workload": "web"}},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := rs.signer.Authorization(http.MethodPut, routes.Path, manifest)
	if err != nil {
		t.Fatal(err)
	}
	env := routes.Envelope{Manifest: manifest, Token: strings.TrimPrefix(auth, "Bearer ")}
	if _, err := rs.state.Accept(env, rs.keys); err != nil {
		t.Fatalf("Accept(revision %d) = %v, want nil", revision, err)
	}
}

// handshakeCodes returns the error code each attested handshake answers with,
// or "" for success.
func (rs *routedServer) handshakeCodes(t *testing.T) (pq, lb string) {
	t.Helper()
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(types.AttestPQRequest{Nonce: b64url(make([]byte, 32)), XWingEK: b64url(ck.EncapsulationKey())})
	pqResp := postAttestPQ(t, rs.ts.URL, body)
	lbResp, err := http.Get(rs.ts.URL + "/.well-known/c8s/attest-lb?nonce=" + b64url(make([]byte, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return errorCode(t, pqResp), errorCode(t, lbResp)
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return ""
	}
	var e types.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("status %d with undecodable body: %v", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d (%s), want 200 or 503", resp.StatusCode, e.Error)
	}
	return e.Error
}

func TestA2F2HandshakeGates(t *testing.T) {
	rs := newRoutedServer(t)
	if pq, lb := rs.handshakeCodes(t); pq != types.ErrorCodeRoutesUnavailable || lb != types.ErrorCodeRoutesUnavailable {
		t.Fatalf("handshakes before the first apply = %q, %q, want %q (A2)", pq, lb, types.ErrorCodeRoutesUnavailable)
	}
	rs.apply(t, 1, time.Minute)
	if pq, lb := rs.handshakeCodes(t); pq != "" || lb != "" {
		t.Fatalf("handshakes after apply = %q, %q, want success", pq, lb)
	}
	rs.clock.Advance(time.Minute)
	if pq, lb := rs.handshakeCodes(t); pq != types.ErrorCodeRoutesStale || lb != types.ErrorCodeRoutesStale {
		t.Fatalf("handshakes when stale = %q, %q, want %q (F2)", pq, lb, types.ErrorCodeRoutesStale)
	}
	rs.apply(t, 1, time.Minute) // F3
	if pq, lb := rs.handshakeCodes(t); pq != "" || lb != "" {
		t.Fatalf("handshakes after a refresh = %q, %q, want success (F3)", pq, lb)
	}
}

func TestA7M1TunnelRoutesByManifest(t *testing.T) {
	rs := newRoutedServer(t)
	rs.apply(t, 1, time.Hour)
	channel, sessionID := establishSession(t, rs.ts.URL, make([]byte, 32))

	resp := tunnel(t, rs.ts.URL, channel, sessionID, types.TunnelRequest{
		Method:  "GET",
		Path:    "/v1/../models?x=1",
		Headers: []types.HeaderField{{Name: "Host", Value: "app.example"}},
	})
	if resp.Status != http.StatusOK || string(resp.Body) != "web saw /models?x=1" {
		t.Fatalf("tunnel GET = %d %q, want 200 %q (A7, B6)", resp.Status, resp.Body, "web saw /models?x=1")
	}
	if got := <-rs.lastHost; got != "app.example" {
		t.Fatalf("backend Host = %q, want the sealed Host (M1)", got)
	}

	resp = tunnel(t, rs.ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/"})
	if resp.Status != http.StatusBadRequest {
		t.Fatalf("tunnel GET without a sealed Host = %d, want 400 (M1)", resp.Status)
	}
}

// TestTunnelStalledClientFreesBudget: a client that stalls its upload or its
// download holds its tunnel budget only until it has made no progress for the
// I/O timeout, though it stays connected.
func TestTunnelStalledClientFreesBudget(t *testing.T) {
	host := types.HeaderField{Name: "Host", Value: "app.example"}
	tests := []struct {
		name string
		// stall sends a tunnel request on conn and stops reading or writing.
		stall func(t *testing.T, conn net.Conn, sessionID string, recBody []byte)
	}{
		{"upload", func(t *testing.T, conn net.Conn, sessionID string, recBody []byte) {
			fmt.Fprintf(conn, "POST /.well-known/c8s/tunnel HTTP/1.1\r\nHost: router\r\nX-C8s-Session: %s\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\n\r\n%s",
				sessionID, len(recBody)+1, recBody)
			// Let it take the budget before the probes race it there.
			time.Sleep(200 * time.Millisecond)
		}},
		{"download", func(t *testing.T, conn net.Conn, sessionID string, recBody []byte) {
			fmt.Fprintf(conn, "POST /.well-known/c8s/tunnel HTTP/1.1\r\nHost: router\r\nX-C8s-Session: %s\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\n\r\n%s",
				sessionID, len(recBody), recBody)
			// The status line arrives once the handler is writing the sealed
			// body, which outgrows the socket buffers while this client reads
			// no further.
			if status, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.Contains(status, " 200 ") {
				t.Fatalf("stalled tunnel response = %q, %v, want 200", status, err)
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rs := newRoutedServer(t, func(p *routing.ProxyConfig, s *Config) {
				p.TunnelBudget = oneRequestBudget
				s.TunnelIOTimeout = 2 * time.Second
			})
			rs.apply(t, 1, time.Hour)
			channel, sessionID := establishSession(t, rs.ts.URL, make([]byte, 32))
			plain, _ := cbor.Marshal(types.TunnelRequest{Method: "GET", Path: "/big", Headers: []types.HeaderField{host}})
			rec, err := channel.SealRequest(plain)
			if err != nil {
				t.Fatal(err)
			}
			recBody, _ := cbor.Marshal(rec)
			conn, err := net.Dial("tcp", rs.ts.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			tc.stall(t, conn, sessionID, recBody)
			start := time.Now()

			get := func() (int, string) {
				resp := postSealedTunnel(t, rs.ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/", Headers: []types.HeaderField{host}})
				defer resp.Body.Close()
				var refusal types.ErrorResponse
				_ = json.NewDecoder(resp.Body).Decode(&refusal)
				return resp.StatusCode, refusal.Error
			}
			// The stalled upload takes the budget once its headers are parsed.
			for {
				code, errCode := get()
				if code == http.StatusServiceUnavailable && errCode == types.ErrorCodeTunnelBusy {
					break
				}
				if time.Since(start) > time.Second/2 {
					t.Fatalf("tunnel while a stalled request holds the budget = %d %q, want %d %q", code, errCode, http.StatusServiceUnavailable, types.ErrorCodeTunnelBusy)
				}
				time.Sleep(10 * time.Millisecond)
			}
			for {
				if code, _ := get(); code == http.StatusOK {
					break
				}
				if time.Since(start) > 10*time.Second {
					t.Fatal("tunnel budget never freed while the stalled client stayed connected")
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// slowReader hands out at most 32 KiB per Read, after a pause.
type slowReader struct{ r io.Reader }

func (s slowReader) Read(p []byte) (int, error) {
	time.Sleep(4 * time.Millisecond)
	return s.r.Read(p[:min(len(p), 32<<10)])
}

// TestTunnelSlowClientGetsWholeResponse: a client that reads a sealed
// response slower than it could cross within the I/O timeout, but never
// stops, receives it whole.
func TestTunnelSlowClientGetsWholeResponse(t *testing.T) {
	const timeout = time.Second
	rs := newRoutedServer(t, func(_ *routing.ProxyConfig, s *Config) { s.TunnelIOTimeout = timeout })
	rs.apply(t, 1, time.Hour)
	channel, sessionID := establishSession(t, rs.ts.URL, make([]byte, 32))
	plain, _ := cbor.Marshal(types.TunnelRequest{Method: "GET", Path: "/big", Headers: []types.HeaderField{{Name: "Host", Value: "app.example"}}})
	rec, err := channel.SealRequest(plain)
	if err != nil {
		t.Fatal(err)
	}
	recBody, _ := cbor.Marshal(rec)
	req, _ := http.NewRequest(http.MethodPost, rs.ts.URL+"/.well-known/c8s/tunnel", bytes.NewReader(recBody))
	req.Header.Set("X-C8s-Session", sessionID)
	req.Header.Set("Content-Type", "application/cbor")
	start := time.Now()
	httpResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer httpResp.Body.Close()
	sealed, err := io.ReadAll(slowReader{httpResp.Body})
	if err != nil {
		t.Fatalf("slow read of the sealed response after %d bytes: %v", len(sealed), err)
	}
	if elapsed := time.Since(start); elapsed < 2*timeout {
		t.Fatalf("slow read took %v, want over %v for the test to mean anything", elapsed, 2*timeout)
	}
	var out overenc.Record
	if err := cbor.Unmarshal(sealed, &out); err != nil {
		t.Fatal(err)
	}
	respCBOR, err := channel.OpenResponse(out, rec.Seq)
	if err != nil {
		t.Fatal(err)
	}
	var resp types.TunnelResponse
	if err := cbor.Unmarshal(respCBOR, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != http.StatusOK || len(resp.Body) != bigResponseBytes {
		t.Fatalf("slowly read tunnel GET /big = %d with %d bytes, want 200 with %d", resp.Status, len(resp.Body), bigResponseBytes)
	}
}

// oneRequestBudget admits one tunnelled request at a time.
const oneRequestBudget = 3*tunnelBodyLimit + 4*routing.MaxTunnelResponseBytes

// TestTunnelBudgetNeedsSession: a request naming no live session, or
// declaring an oversized record, is refused before it reads the body, so a
// slow sender holds no budget while a session's request gets through.
func TestTunnelBudgetNeedsSession(t *testing.T) {
	rs := newRoutedServer(t, func(p *routing.ProxyConfig, _ *Config) { p.TunnelBudget = oneRequestBudget })
	rs.apply(t, 1, time.Hour)
	channel, sessionID := establishSession(t, rs.ts.URL, make([]byte, 32))
	tests := []struct {
		name, session string
		length        int
		want          string
	}{
		{"no session", "", 1024, " 401 "},
		{"unknown session", "forged", 1024, " 401 "},
		{"oversized record", sessionID, tunnelBodyLimit + 1, " 413 "},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", rs.ts.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			// Headers and one byte of the body, then nothing.
			fmt.Fprintf(conn, "POST /.well-known/c8s/tunnel HTTP/1.1\r\nHost: router\r\nX-C8s-Session: %s\r\nContent-Type: application/cbor\r\nContent-Length: %d\r\n\r\nx",
				tc.session, tc.length)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if status, err := bufio.NewReader(conn).ReadString('\n'); err != nil || !strings.Contains(status, tc.want) {
				t.Fatalf("stalled tunnel upload = %q, %v, want%s", status, err, tc.want)
			}
			// The previous subtest's request releases its budget after its
			// response is on the wire; the stalled upload stays open throughout.
			deadline := time.Now().Add(2 * time.Second)
			for {
				resp := postSealedTunnel(t, rs.ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/", Headers: []types.HeaderField{{Name: "Host", Value: "app.example"}}})
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					break
				}
				if resp.StatusCode != http.StatusServiceUnavailable || time.Now().After(deadline) {
					t.Fatalf("tunnel beside a stalled refused upload = %d, want %d", resp.StatusCode, http.StatusOK)
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

func TestAttestEndpointsDisabled(t *testing.T) {
	srv := NewServer(Config{Routes: testRoutes(t), DisableAttestEndpoints: true})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	for _, path := range []string{"/.well-known/c8s/attest-lb", "/.well-known/c8s/tunnel"} {
		resp, err := http.Post(ts.URL+path, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("POST %s with attest endpoints off = %d, want 404 or 405", path, resp.StatusCode)
		}
	}
	resp, err := http.Get(ts.URL + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /readyz with attest endpoints off = %d, want 200", resp.StatusCode)
	}
}

func TestCheckRoutingFlags(t *testing.T) {
	mesh := config{meshIdentityCertFile: "c", meshIdentityKeyFile: "k", meshIdentityCAFile: "ca", attestationAPIURL: "http://127.0.0.1:9"}
	routed := func(edit func(*config)) config {
		c := mesh
		c.routing = routingConfig{cdsURL: "https://cds:8443", pollInterval: time.Second, backendTimeout: time.Hour, host: "127.0.0.1"}
		if edit != nil {
			edit(&c)
		}
		return c
	}
	tests := []struct {
		name    string
		cfg     config
		wantSub string
	}{
		{"routed", routed(nil), ""},
		{"no cds", routed(func(c *config) { c.routing.cdsURL = "" }), "--cds-url is required"},
		{"tunnel budget under one request", routed(func(c *config) { c.routing.tunnelBudget = quantityFlag{bytes: oneRequestBudget - 1, set: true} }), "--tunnel-budget"},
		{"cds without attestation api", routed(func(c *config) { c.attestationAPIURL = "" }), "--attestation-api-url"},
		{"cds without mesh identity", routed(func(c *config) { c.meshIdentityKeyFile = "" }), "--mesh-identity"},
		{"non-loopback routing host", routed(func(c *config) { c.routing.port = 8802; c.routing.host = "0.0.0.0" }), "loopback"},
		{"non-loopback routing host without port", routed(func(c *config) { c.routing.host = "0.0.0.0" }), "loopback"},
		{"zero poll interval", routed(func(c *config) { c.routing.pollInterval = 0 }), "--routes-poll-interval"},
		{"zero backend timeout", routed(func(c *config) { c.routing.backendTimeout = 0 }), "--backend-timeout"},
		{"negative backend timeout", routed(func(c *config) { c.routing.backendTimeout = -time.Second }), "--backend-timeout"},
		{"attest off without routing port", routed(func(c *config) { c.attestOff = true }), "--routing-port"},
		{"publish routes", routed(func(c *config) { c.routing.publish = true }), ""},
		{"publish routes without cds", routed(func(c *config) { c.routing.publish = true; c.routing.cdsURL = "" }), "--publish-routes requires --cds-url"},
		{"publish routes with attest off", routed(func(c *config) { c.routing.publish = true; c.attestOff = true; c.routing.port = 8802 }), "--publish-routes requires --attest-endpoints=true"},
		{"measured policies", routed(func(c *config) { c.measuredPolicies = "/run/nri/measured-policies" }), ""},
		{"measured policies with attest off", routed(func(c *config) {
			c.measuredPolicies = "/run/nri/measured-policies"
			c.attestOff = true
			c.routing.port = 8802
		}), "--measured-policies-file requires --attest-endpoints=true"},
		{"default reserved paths", routed(func(c *config) { c.routing.reservedPaths = defaultReservedPaths }), ""},
		{"reserved path /a//b", routed(func(c *config) { c.routing.reservedPaths = []string{"/ok", "/a//b"} }), "--reserved-paths"},
		{"reserved path /Foo%7e", routed(func(c *config) { c.routing.reservedPaths = []string{"/ok", "/Foo%7e"} }), "--reserved-paths"},
		{"reserved path empty", routed(func(c *config) { c.routing.reservedPaths = []string{"/ok", ""} }), "--reserved-paths"},
		{"reserved path /a/../b", routed(func(c *config) { c.routing.reservedPaths = []string{"/ok", "/a/../b"} }), "--reserved-paths"},
		{"reserved path x", routed(func(c *config) { c.routing.reservedPaths = []string{"/ok", "x"} }), "--reserved-paths"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkRoutingFlags(tc.cfg)
			if tc.wantSub == "" {
				if err != nil {
					t.Fatalf("checkRoutingFlags() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("checkRoutingFlags() = %v, want an error containing %q", err, tc.wantSub)
			}
		})
	}
}

func TestW6OperatorKeySource(t *testing.T) {
	cds, err := routing.NewCDSClient("https://cds:8443", http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	write := func(name string, b []byte) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	present := write("operator-pubkey", keyPEM)
	other := write("keys.pem", keyPEM)
	empty := write("operator-pubkey", []byte("no keys"))
	missing := filepath.Join(t.TempDir(), "operator-pubkey")
	logger := slog.New(slog.DiscardHandler)
	tests := []struct {
		name    string
		cfg     routingConfig
		pinned  bool
		want    routing.KeySource
		wantErr bool
	}{
		{"W6 launch configuration", routingConfig{launchKeysFile: present}, true, routing.KeyFile(present), false},
		{"W6 launch configuration over a configured file", routingConfig{launchKeysFile: present, operatorKeysFile: other}, true, routing.KeyFile(present), false},
		{"W6 configured file", routingConfig{launchKeysFile: missing, operatorKeysFile: other}, true, routing.KeyFile(other), false},
		{"W6 configured file absent", routingConfig{launchKeysFile: missing, operatorKeysFile: missing}, true, nil, true},
		{"W6 CDS", routingConfig{launchKeysFile: missing}, true, cds, false},
		{"unpinned CDS with launch keys", routingConfig{launchKeysFile: present}, false, routing.KeyFile(present), false},
		{"unpinned CDS with a configured file", routingConfig{launchKeysFile: missing, operatorKeysFile: other}, false, routing.KeyFile(other), false},
		{"W6 launch configuration without keys", routingConfig{launchKeysFile: empty}, true, nil, true},
		{"W6 configured file without keys", routingConfig{launchKeysFile: missing, operatorKeysFile: empty}, true, nil, true},
		{"unpinned CDS supplying keys", routingConfig{launchKeysFile: missing}, false, nil, true},
		{"unpinned CDS supplying keys, dev opt-in", routingConfig{launchKeysFile: missing, allowUnpinnedCDS: true}, false, cds, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := operatorKeySource(tc.cfg, tc.pinned, cds, logger)
			if (err != nil) != tc.wantErr {
				t.Fatalf("operatorKeySource() error = %v, want error %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("operatorKeySource() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRoutingFlagDefaults(t *testing.T) {
	flags := NewCmd().Flags()
	for _, tc := range []struct{ flag, want string }{
		{"routes-poll-interval", "30s"},
		{"routing-port", "0"},
		{"routing-host", "127.0.0.1"},
		{"backend-timeout", "1h0m0s"},
		{"attest-endpoints", "true"},
		{"operator-keys-file", ""},
		{"allow-unpinned-cds", "false"},
	} {
		f := flags.Lookup(tc.flag)
		if f == nil {
			t.Fatalf("missing --%s flag", tc.flag)
		}
		if f.DefValue != tc.want {
			t.Fatalf("default --%s = %q, want %q", tc.flag, f.DefValue, tc.want)
		}
	}
	if flags.Lookup("image-policy-file") == nil {
		t.Fatal("missing --image-policy-file flag")
	}
}

// TestRunRoutingListenerBeforeFirstApply runs cds-attest with routing on and
// the attestation endpoints off, against a CDS that cannot be reached: the
// routing listener answers 503 (A2) while readiness stays 200.
func TestRunRoutingListenerBeforeFirstApply(t *testing.T) {
	port, routingPort := freePort(t), freePort(t)
	cfg := routedRunConfig(t, port)
	cfg.routing.port = routingPort
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	get := func(port int, path string) int {
		deadline := time.Now().Add(5 * time.Second)
		for {
			resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + path)
			if err == nil {
				resp.Body.Close()
				return resp.StatusCode
			}
			select {
			case err := <-done:
				t.Fatalf("run() exited early: %v", err)
			case <-time.After(20 * time.Millisecond):
			}
			if time.Now().After(deadline) {
				t.Fatalf("GET :%d%s never answered: %v", port, path, err)
			}
		}
	}
	if got := get(routingPort, "/"); got != http.StatusServiceUnavailable {
		t.Fatalf("routing listener GET / before the first apply = %d, want %d (A2)", got, http.StatusServiceUnavailable)
	}
	if got := get(port, "/readyz"); got != http.StatusOK {
		t.Fatalf("GET /readyz before the first apply = %d, want %d (A2 leaves readiness alone)", got, http.StatusOK)
	}
	if got := get(port, "/.well-known/c8s/attest-lb"); got != http.StatusNotFound {
		t.Fatalf("GET attest-lb with --attest-endpoints=false = %d, want %d", got, http.StatusNotFound)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() after cancel = %v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run() did not stop after cancel")
	}
}

// The router serves cluster workloads only, so a manifest naming an address
// backend is refused when it is fetched, before anything applies it.
func TestClusterWorkloadRoutesRefusesAnAddressBackend(t *testing.T) {
	manifest := func(backend map[string]string) []byte {
		t.Helper()
		b, err := json.Marshal(map[string]any{
			"schema": routes.Schema, "revision": 1, "notBefore": "2020-01-01T00:00:00Z", "maxAgeSeconds": 3600,
			"hosts": map[string]any{"app.example": map[string]any{"routes": []any{
				map[string]any{"path": "/", "match": "prefix", "backend": backend},
			}}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	workload := clusterWorkloadRoutes{routes: fetchedRoutes{env: routes.Envelope{
		Manifest: manifest(map[string]string{"address": "web.adopted.svc:8080", "workload": "web"}),
	}}}
	if _, err := workload.Routes(t.Context()); err != nil {
		t.Fatalf("Routes() with a workload backend = %v, want nil", err)
	}
	external := clusterWorkloadRoutes{routes: fetchedRoutes{env: routes.Envelope{
		Manifest: manifest(map[string]string{"address": "admin.ops.example:443", "serverName": "admin.ops.example", "ca": testAnchorPEM(t)}),
	}}}
	_, err := external.Routes(t.Context())
	if err == nil {
		t.Fatal("Routes() with an address backend = nil, want a refusal")
	}
	if !strings.Contains(err.Error(), "the router serves cluster workloads only") {
		t.Fatalf("Routes() = %v, want the cluster-workloads refusal", err)
	}
}

// fetchedRoutes serves one envelope, standing in for the verified CDS.
type fetchedRoutes struct {
	env routes.Envelope
}

func (f fetchedRoutes) Routes(context.Context) (routes.Envelope, error) {
	return f.env, nil
}

// testAnchorPEM is a certificate an address backend's ca member can hold.
func testAnchorPEM(t *testing.T) string {
	t.Helper()
	ca, err := issuer.NewCA("external", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return string(certutil.EncodeCertPEM(ca.Cert.Raw))
}

// The hop to a member backend takes its trust root from the credential
// generation on this pod's own volume, at the compiled path. A CA an
// argument names is the control plane's choice, so it anchors nothing: a
// backend keyed to it is refused.
func TestMemberBackendRefusesACAAnArgumentNames(t *testing.T) {
	ca, err := issuer.NewCA("control plane", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	named := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(named, certutil.EncodeCertPEM(ca.Cert.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	// The argument's CA is not among the mesh CAs the member dial trusts.
	cas, _ := memberMeshCAs()()
	for _, trusted := range cas {
		if trusted.Equal(ca.Cert) {
			t.Fatalf("the member dial trusts the CA %q names", named)
		}
	}

	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reached")
	}))
	leaf := namedLeaf(t, ca, "web")
	testutil.ServeMeshBackend(backend, leaf)
	backend.StartTLS()
	t.Cleanup(backend.Close)

	transports := routing.NewTransports(routing.TransportConfig{
		MeshCAs:           memberMeshCAs(),
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &leaf, nil },
	})
	address := strings.TrimPrefix(backend.URL, "https://")
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transports.For(routes.Backend{Address: address, Workload: "web"}).RoundTrip(request)
	if err == nil {
		response.Body.Close()
		t.Fatal("a backend keyed by the CA an argument names answered the router")
	}
}

// The verifier this router weighs CDS evidence with is the node's, and never
// a plaintext endpoint this pod named: its connections into the cluster are
// uncaptured, so such an endpoint could be a member pod. The node's own
// address is compared as an address, after the expansion, so a host that
// merely carries it is another host.
func TestCheckVerifierEndpoint(t *testing.T) {
	const node = "172.18.0.7"
	nodeIPPath := filepath.Join(t.TempDir(), "node-ip")
	if err := os.WriteFile(nodeIPPath, []byte(node+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		endpoint string
		wantErr  bool
	}{
		"the node's socket":                     {"unix:///run/c8s/workload-claims/attestation-api.sock", false},
		"the node's address":                    {"http://" + node + ":8400", false},
		"the node's address, no port":           {"http://" + node, false},
		"this pod's loopback":                   {"http://127.0.0.1:8400", false},
		"this pod's loopback in brackets":       {"http://[::1]:8400", false},
		"an https endpoint":                     {"https://verifier.example:8400", false},
		"the node's address as userinfo":        {"http://" + node + "@evil.example:8400", true},
		"the node's address as a suffix domain": {"http://" + node + ".evil.example:8400", true},
		"another address":                       {"http://10.43.0.9:8400", true},
		"a name, never resolved":                {"http://localhost:8400", true},
		"a name of this node":                   {"http://node.cluster.local:8400", true},
		"an IPv6 address of another host":       {"http://[fd00::9]:8400", true},
		"a path on the node":                    {"http://" + node + ":8400/evidence", true},
		"another scheme":                        {"ftp://" + node + ":8400", true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkVerifierEndpoint(tc.endpoint, nodeIPPath)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkVerifierEndpoint(%q) = %v, wantErr %v", tc.endpoint, err, tc.wantErr)
			}
		})
	}

	// Without the enforcer's file there is no node address to admit, so a
	// plaintext endpoint beyond this pod is refused whatever it names.
	if err := checkVerifierEndpoint("http://"+node+":8400", filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("a plaintext verifier was admitted with no published node address")
	}
}
