package cds

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func testMeshCA(t *testing.T) *issuer.MeshCA {
	t.Helper()
	mesh, err := issuer.NewMeshCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("mesh ca: %v", err)
	}
	return mesh
}

func newStubRouter(t *testing.T) http.Handler {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("allowlist: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	mesh, err := issuer.NewMeshCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler: AttestHandler{
			Challenges: &cs,
			CertTTL:    time.Hour,
		},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		MeshCA:           mesh,
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}
	return newRouter(deps)
}

func TestRouter_RateLimitsAttestationEndpoints(t *testing.T) {
	store, _ := allowlist.OpenInMemory()
	t.Cleanup(func() { _ = store.Close() })
	mesh, _ := issuer.NewMeshCA("test ca", time.Hour)
	cs := attestation.NewChallengeStore(time.Minute)
	// Burst of 1, so the second request from the same source IP is rejected.
	rl, err := issuer.NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatalf("rate limiter: %v", err)
	}
	deps := dependencies{
		AttestHandler: AttestHandler{
			Challenges: &cs,
			CertTTL:    time.Hour,
		},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		MeshCA:           mesh,
		RateLimiter:      rl,
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}
	r := newRouter(deps)

	do := func() int {
		req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader([]byte(`{}`)))
		req.RemoteAddr = "10.0.0.1:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if got := do(); got == http.StatusTooManyRequests {
		t.Fatalf("first request rate-limited unexpectedly: %d", got)
	}
	if got := do(); got != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", got)
	}
}

// TestRouter_RateLimitsAllowlistWrites pins that allowlist mutations sit behind
// the same per-IP limiter as the attestation endpoints: token verification
// costs ECDSA verifies before any authentication.
func TestRouter_RateLimitsAllowlistWrites(t *testing.T) {
	store, _ := allowlist.OpenInMemory()
	t.Cleanup(func() { _ = store.Close() })
	mesh, _ := issuer.NewMeshCA("test ca", time.Hour)
	rl, err := issuer.NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatalf("rate limiter: %v", err)
	}
	deps := dependencies{
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		MeshCA:           mesh,
		RateLimiter:      rl,
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}
	r := newRouter(deps)

	do := func() int {
		req := httptest.NewRequest(http.MethodPut, "/allowlist", bytes.NewReader([]byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`)))
		req.RemoteAddr = "10.0.0.2:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if got := do(); got == http.StatusTooManyRequests {
		t.Fatalf("first request rate-limited unexpectedly: %d", got)
	}
	if got := do(); got != http.StatusTooManyRequests {
		t.Fatalf("second request: got %d, want 429", got)
	}
}

// TestRouter_RateLimitsAuthenticate pins the challenge endpoint behind the
// per-source limiter: minting a challenge costs a stored nonce, and no caller
// is authenticated at that point. Its budget is its own, so spending it leaves
// the /attest that redeems the challenge servable.
func TestRouter_RateLimitsAuthenticate(t *testing.T) {
	store, _ := allowlist.OpenInMemory()
	t.Cleanup(func() { _ = store.Close() })
	mesh, _ := issuer.NewMeshCA("test ca", time.Hour)
	cs := attestation.NewChallengeStore(time.Minute)
	// Burst of 1 with a refill too slow to reach, so the assertion is on the
	// budget rather than on how fast the test runs. The challenge route has a
	// limiter of its own, as it does in the shipped wiring.
	rl, err := issuer.NewIPRateLimiter(rate.Limit(0.001), 1, 100)
	if err != nil {
		t.Fatalf("rate limiter: %v", err)
	}
	// A single-entry map, so a second source evicts the first — and the
	// routes on the other limiter must not notice.
	challengeRL, err := issuer.NewIPRateLimiter(rate.Limit(0.001), 1, 1)
	if err != nil {
		t.Fatalf("challenge rate limiter: %v", err)
	}
	deps := dependencies{
		AttestHandler: AttestHandler{
			Challenges: &cs,
			CertTTL:    time.Hour,
		},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		MeshCA:           mesh,
		RateLimiter:      rl,
		ChallengeLimiter: challengeRL,
		MaxRequestSize:   65536,
	}
	r := newRouter(deps)

	post := func(path, addr string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{}`)))
		req.RemoteAddr = addr
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	first := post("/authenticate", "10.0.0.3:1234")
	if first.Code != http.StatusOK {
		t.Fatalf("first /authenticate: got %d, want 200", first.Code)
	}
	var issued types.ChallengeResponse
	if err := json.Unmarshal(first.Body.Bytes(), &issued); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if raw, err := base64.StdEncoding.DecodeString(issued.Challenge); err != nil || len(raw) != 32 {
		t.Fatalf("challenge %q decodes to %d bytes (err %v), want 32", issued.Challenge, len(raw), err)
	}
	if got := post("/authenticate", "10.0.0.3:1234").Code; got != http.StatusTooManyRequests {
		t.Fatalf("second /authenticate from the same source: got %d, want 429", got)
	}
	// The same source's attestation budget is untouched by that flood: a
	// challenge is only worth anything to a caller that can still redeem it.
	if got := post("/attest", "10.0.0.3:1234").Code; got == http.StatusTooManyRequests {
		t.Fatal("/attest was spent by the same source's challenge requests")
	}
	// A second source takes the first source's challenge bucket. What must
	// not follow is the first source getting a fresh attestation bucket: the
	// two maps are separate, so its spent /attest budget is still spent.
	if got := post("/authenticate", "10.0.0.4:1234").Code; got != http.StatusOK {
		t.Fatalf("/authenticate from a second source: got %d, want 200", got)
	}
	if got := post("/attest", "10.0.0.3:1234").Code; got != http.StatusTooManyRequests {
		t.Fatalf("/attest after the challenge refusal: got %d, want the source's spent budget", got)
	}
}

func newTestRateLimiter(t *testing.T) *issuer.IPRateLimiter {
	t.Helper()
	rl, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 1000)
	if err != nil {
		t.Fatalf("rate limiter: %v", err)
	}
	return rl
}

func TestRouter_RoutesMountedWithExpectedMethods(t *testing.T) {
	cases := []struct {
		method, path string
		wantStatus   int
	}{
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodGet, "/.well-known/jwks.json", http.StatusNotFound},
		{http.MethodGet, "/metrics", http.StatusOK},
		{http.MethodGet, "/ca", http.StatusOK},
		{http.MethodGet, "/allowlist", http.StatusOK},
		{http.MethodGet, "/does-not-exist", http.StatusNotFound},
		{http.MethodPost, "/sign-csr", http.StatusNotFound},
		{http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
	}

	r := newStubRouter(t)
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d; body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestRouter_AttestKeyRemoved(t *testing.T) {
	// The retired key-only flow must no longer expose an issuance route.
	r := newStubRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/attest-key", bytes.NewReader([]byte(`{}`)))
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("/attest-key: got %d, want 404", w.Code)
	}
}

func TestRouter_AttestRejectsOversizedBody(t *testing.T) {
	store, _ := allowlist.OpenInMemory()
	t.Cleanup(func() { _ = store.Close() })
	mesh, _ := issuer.NewMeshCA("test ca", time.Hour)
	cs := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler: AttestHandler{
			Challenges: &cs,
			CertTTL:    time.Hour,
		},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: func(*http.Request, []byte) error { return nil }},
		ReadyFn:          func() bool { return true },
		MeshCA:           mesh,
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   16,
	}
	r := newRouter(deps)

	body := make([]byte, 1024)
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Fatalf("oversized body should be rejected; got %d", w.Code)
	}
}

func TestRouter_CAEndpointReturnsLoadedCert(t *testing.T) {
	r := newStubRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/ca", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("content-type: got %q", ct)
	}
	if _, err := certutil.ParseCertificatePEM(w.Body.Bytes()); err != nil {
		t.Errorf("body is not a parseable cert: %v", err)
	}
}

// TestRouter_OperatorKeysEndpoint: /operator-keys serves the pinned key PEM
// when configured and 404s when allowlist writes are disabled — so `c8s verify`
// can distinguish "no keys pinned" from a broken endpoint.
func TestRouter_OperatorKeysEndpoint(t *testing.T) {
	// Not configured (newStubRouter sets no OperatorKeysPEM) → 404.
	r := newStubRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/operator-keys", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unset: status got %d, want 404", w.Code)
	}

	// Configured → 200 with the PEM served verbatim.
	pemBundle := []byte("-----BEGIN PUBLIC KEY-----\nZHVtbXk=\n-----END PUBLIC KEY-----\n")
	h := handleOperatorKeys(pemBundle)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/operator-keys", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("set: status got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
		t.Errorf("content-type: got %q", ct)
	}
	if w.Body.String() != string(pemBundle) {
		t.Errorf("body: got %q, want the configured PEM", w.Body.String())
	}
}

func TestNewHTTPServerSetsTimeouts(t *testing.T) {
	defaultSrv := newHTTPServer(":0", http.NewServeMux(), config{})
	if defaultSrv.ReadTimeout != defaultHTTPReadTimeout {
		t.Errorf("default ReadTimeout = %v, want %v", defaultSrv.ReadTimeout, defaultHTTPReadTimeout)
	}
	if defaultSrv.ReadHeaderTimeout != defaultHTTPReadHeaderTimeout {
		t.Errorf("default ReadHeaderTimeout = %v, want %v", defaultSrv.ReadHeaderTimeout, defaultHTTPReadHeaderTimeout)
	}
	if defaultSrv.WriteTimeout != defaultHTTPWriteTimeout {
		t.Errorf("default WriteTimeout = %v, want %v", defaultSrv.WriteTimeout, defaultHTTPWriteTimeout)
	}
	if defaultSrv.IdleTimeout != defaultHTTPIdleTimeout {
		t.Errorf("default IdleTimeout = %v, want %v", defaultSrv.IdleTimeout, defaultHTTPIdleTimeout)
	}
	if defaultSrv.MaxHeaderBytes != defaultHTTPMaxHeaderBytes {
		t.Errorf("default MaxHeaderBytes = %d, want %d", defaultSrv.MaxHeaderBytes, defaultHTTPMaxHeaderBytes)
	}

	cfg := config{
		readTimeout:       time.Second,
		readHeaderTimeout: 2 * time.Second,
		writeTimeout:      3 * time.Second,
		idleTimeout:       4 * time.Second,
		maxHeaderBytes:    4096,
	}
	srv := newHTTPServer(":0", http.NewServeMux(), cfg)

	if srv.ReadTimeout != cfg.readTimeout {
		t.Errorf("ReadTimeout = %v, want %v", srv.ReadTimeout, cfg.readTimeout)
	}
	if srv.ReadHeaderTimeout != cfg.readHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, cfg.readHeaderTimeout)
	}
	if srv.WriteTimeout != cfg.writeTimeout {
		t.Errorf("WriteTimeout = %v, want %v", srv.WriteTimeout, cfg.writeTimeout)
	}
	if srv.IdleTimeout != cfg.idleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, cfg.idleTimeout)
	}
	if srv.MaxHeaderBytes != cfg.maxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, cfg.maxHeaderBytes)
	}
}

func TestValidateConfigRejectsUnsafeValues(t *testing.T) {
	valid := config{
		maxHeaderBytes:             1,
		namedCertTTL:               issuer.MaxNamedLeafTTL,
		maxRequestSize:             1,
		secretsMaxPaths:            1024,
		secretsMaxPathsPerWorkload: 64,
		secretsMaxValueBytes:       4096,
		sandboxLedgerMax:           10000,
		readinessInterval:          time.Second,
		minCAValidity:              time.Hour,
		caCertValidity:             365 * 24 * time.Hour,
	}
	if err := validateConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		edit func(*config)
	}{
		{name: "negative read timeout", edit: func(c *config) { c.readTimeout = -time.Second }},
		{name: "negative read header timeout", edit: func(c *config) { c.readHeaderTimeout = -time.Second }},
		{name: "negative write timeout", edit: func(c *config) { c.writeTimeout = -time.Second }},
		{name: "negative idle timeout", edit: func(c *config) { c.idleTimeout = -time.Second }},
		{name: "negative max header bytes", edit: func(c *config) { c.maxHeaderBytes = -1 }},
		{name: "zero named cert ttl", edit: func(c *config) { c.namedCertTTL = 0 }},
		{name: "negative named cert ttl", edit: func(c *config) { c.namedCertTTL = -time.Hour }},
		{name: "named cert ttl above the ceiling", edit: func(c *config) { c.namedCertTTL = issuer.MaxNamedLeafTTL + time.Hour }},
		{name: "zero max request size", edit: func(c *config) { c.maxRequestSize = 0 }},
		{name: "negative max request size", edit: func(c *config) { c.maxRequestSize = -1 }},
		{name: "zero readiness interval", edit: func(c *config) { c.readinessInterval = 0 }},
		{name: "negative readiness interval", edit: func(c *config) { c.readinessInterval = -time.Second }},
		{
			name: "zero min ca validity",
			edit: func(c *config) { c.minCAValidity = 0 },
		},
		{
			name: "negative min ca validity",
			edit: func(c *config) { c.minCAValidity = -time.Hour },
		},
		// Renewal starts at half the CA certificate's lifetime, so this pair
		// would let the certificate fall under --min-ca-validity before
		// renewal had a tick to replace it.
		{
			name: "ca validity too short for the renewal window",
			edit: func(c *config) { c.caCertValidity = 2 * (time.Hour + caRenewalCheckInterval) },
		},
		{
			name: "ca validity below min ca validity",
			edit: func(c *config) { c.caCertValidity = 30 * time.Minute },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.edit(&cfg)
			if err := validateConfig(cfg); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestCAValidityHolds(t *testing.T) {
	now := time.Now()
	fresh := &x509.Certificate{NotAfter: now.Add(48 * time.Hour)}
	expiring := &x509.Certificate{NotAfter: now.Add(30 * time.Minute)}
	expired := &x509.Certificate{NotAfter: now.Add(-time.Hour)}

	for _, tc := range []struct {
		name      string
		cert      *x509.Certificate
		minWindow time.Duration
		want      bool
	}{
		{"validity beyond the window", fresh, time.Hour, true},
		{"validity inside the window", expiring, time.Hour, false},
		{"already expired", expired, time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := caValidityHolds(tc.cert, tc.minWindow, now); got != tc.want {
				t.Errorf("caValidityHolds() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReadinessFn(t *testing.T) {
	mesh, err := issuer.NewMeshCA("test ca", 48*time.Hour)
	if err != nil {
		t.Fatalf("mesh ca: %v", err)
	}

	for _, tc := range []struct {
		name string
		svc  func() bool
		want bool
	}{
		{"attestation-api healthy and CA current", func() bool {
			return true
		}, true},
		{"attestation-api down", func() bool {
			return false
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := readinessFn(tc.svc, mesh, time.Hour)(); got != tc.want {
				t.Errorf("readinessFn() = %v, want %v", got, tc.want)
			}
		})
	}

	expiring, err := issuer.NewMeshCA("test ca", time.Minute)
	if err != nil {
		t.Fatalf("mesh ca: %v", err)
	}
	if readinessFn(func() bool {
		return true
	}, expiring, time.Hour)() {
		t.Error("readiness held with a CA certificate inside the renewal window")
	}
}

func TestParseReferenceDigests(t *testing.T) {
	cases := []struct {
		name    string
		input   []string
		wantLen int
	}{
		{"empty", nil, 0},
		{"whitespace only", []string{"  ", ""}, 0},
		{"normalises case and trim", []string{"DEAD", " beef ", "dead"}, 2},
		{"three distinct", []string{"a", "b", "c"}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseReferenceDigests(tc.input)
			if len(got) != tc.wantLen {
				t.Errorf("len: got %d, want %d (map=%v)", len(got), tc.wantLen, got)
			}
		})
	}
}

func TestNewRouter_PanicsOnZeroMaxRequestSize(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for zero MaxRequestSize")
		}
	}()
	newRouter(dependencies{RateLimiter: newTestRateLimiter(t), ChallengeLimiter: newTestRateLimiter(t), MaxRequestSize: 0})
}

func TestNewRouter_PanicsOnNilRateLimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil RateLimiter")
		}
	}()
	newRouter(dependencies{RateLimiter: nil, MaxRequestSize: 1})
}

// The challenge route meters in a map of its own, so a wiring that forgets it
// must not fall back to sharing another route's.
func TestNewRouter_PanicsOnNilChallengeLimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for nil ChallengeLimiter")
		}
	}()
	newRouter(dependencies{RateLimiter: newTestRateLimiter(t), ChallengeLimiter: nil, MaxRequestSize: 1})
}

// Sharing one limiter between the two routes is the regression the challenge
// map exists to prevent, and it is a wiring mistake no route-level test would
// notice, so the router refuses to be built that way.
func TestNewRouter_PanicsOnASharedChallengeLimiter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for a ChallengeLimiter shared with the attestation limiter")
		}
	}()
	shared := newTestRateLimiter(t)
	newRouter(dependencies{RateLimiter: shared, ChallengeLimiter: shared, MaxRequestSize: 1})
}

// /measurements must report what this CDS enforces, and must report an empty
// set rather than hiding it: "admits any measurement" is the finding a
// verifier most needs.
func TestHandleMeasurements(t *testing.T) {
	set, err := refvalues.Parse([]byte(
		`{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"a","measurement":"` +
			strings.Repeat("ab", 48) + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := refvalues.Render(set)
	if err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handleMeasurements(doc)(w, httptest.NewRequest(http.MethodGet, "/measurements", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	served, err := refvalues.ParseRendered(w.Body.Bytes())
	if err != nil {
		t.Fatalf("served body does not parse: %v", err)
	}
	if len(served.Images) != 1 || served.Family != teetypes.FamilySNP {
		t.Errorf("served set = %+v, want the one pinned image", served)
	}

	empty, err := refvalues.Render(refvalues.ReferenceValues{Family: teetypes.FamilySNP})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handleMeasurements(empty)(w, httptest.NewRequest(http.MethodGet, "/measurements", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("empty set status = %d, want 200 (not a 404)", w.Code)
	}
	servedEmpty, err := refvalues.ParseRendered(w.Body.Bytes())
	if err != nil {
		t.Fatalf("empty served body does not parse: %v", err)
	}
	if len(servedEmpty.Images) != 0 {
		t.Errorf("empty set served %d entries", len(servedEmpty.Images))
	}
}
