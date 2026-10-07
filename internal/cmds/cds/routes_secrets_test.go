package cds

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func secretsRouter(t *testing.T, enabled bool) http.Handler {
	t.Helper()
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	secretsCS := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler:    AttestHandler{Challenges: &cs},
		ReadyFn:          func() bool { return true },
		RateLimiter:      limiter,
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}
	if enabled {
		// A bare handler: routing is what is under test, so every request that
		// reaches it is refused for want of a client certificate.
		deps.SecretsHandler = &secrets.Handler{}
		deps.SecretsChallenges = &secretsCS
		deps.SecretsOperator = &secrets.OperatorHandler{Store: secrets.NewMemoryStore(8, 7, 64)}
		deps.SecretsExplain = &secrets.ExplainHandler{}
	}
	return newRouter(deps)
}

func get(t *testing.T, h http.Handler, method, path string) int {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w.Code
}

// The challenge route is "/secrets" exactly and the secret route is everything
// below it, so neither shadows the other and no store path is unreachable.
func TestRouter_SecretsChallengeDoesNotShadowSecretPaths(t *testing.T) {
	r := secretsRouter(t, true)

	if code := get(t, r, http.MethodPost, "/secrets"); code != http.StatusOK {
		t.Fatalf("POST /secrets = %d, want 200 (a challenge)", code)
	}
	// A secret literally named /challenge must still route to the handler, not
	// to the challenge endpoint.
	for _, p := range []string{"/secrets/challenge", "/secrets/api/db", "/secrets/a/b/c"} {
		if code := get(t, r, http.MethodGet, p); code == http.StatusNotFound {
			t.Fatalf("GET %s = 404: the route did not reach the secrets handler", p)
		}
	}
}

// With --secrets off, nothing under /secrets is served at all.
func TestRouter_SecretsUnroutedWhenDisabled(t *testing.T) {
	r := secretsRouter(t, false)
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/secrets"},
		{http.MethodGet, "/secrets/api/db"},
		{http.MethodPost, "/secrets/api/db"},
		{http.MethodPut, "/secrets/api/db"},
		{http.MethodGet, "/secrets-explain/" + strings.Repeat("a", 64)},
	} {
		if code := get(t, r, tc.method, tc.path); code != http.StatusNotFound {
			t.Fatalf("%s %s = %d with secrets disabled, want 404", tc.method, tc.path, code)
		}
	}
}

// The issuance and secrets challenge pools are distinct, so a nonce minted for
// one endpoint is not redeemable at the other.
func TestRouter_SecretsChallengePoolIsSeparate(t *testing.T) {
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	secretsCS := attestation.NewChallengeStore(time.Minute)
	deps := dependencies{
		AttestHandler:     AttestHandler{Challenges: &cs},
		ReadyFn:           func() bool { return true },
		RateLimiter:       limiter,
		ChallengeLimiter:  newTestRateLimiter(t),
		MaxRequestSize:    65536,
		SecretsHandler:    &secrets.Handler{},
		SecretsChallenges: &secretsCS,
		SecretsOperator:   &secrets.OperatorHandler{Store: secrets.NewMemoryStore(8, 7, 64)},
		SecretsExplain:    &secrets.ExplainHandler{},
	}
	_ = newRouter(deps)

	issued := cs.Create()
	if secretsCS.Consume(issued[:]) {
		t.Fatal("an issuance challenge was redeemable against the secrets pool")
	}
	secretsIssued := secretsCS.Create()
	if cs.Consume(secretsIssued[:]) {
		t.Fatal("a secrets challenge was redeemable against the issuance pool")
	}
}

// PUT is the operator's door onto the same paths, so it is authorized by the
// pinned operator key rather than by a mesh leaf and sandbox token. With no
// authorizer wired, it refuses.
func TestRouter_SecretsPutIsOperatorAuthorized(t *testing.T) {
	r := secretsRouter(t, true)
	if code := get(t, r, http.MethodPut, "/secrets/api/db"); code != http.StatusUnauthorized {
		t.Fatalf("PUT /secrets/api/db = %d, want 401", code)
	}
}

// The operator body cap is the allowlist one, not MaxRequestSize: a secret
// value is base64 inside JSON and would not fit the attestation-sized bound.
func TestRouter_SecretsPutUsesTheAllowlistWriteCap(t *testing.T) {
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1000), 1000, 100)
	if err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	secretsCS := attestation.NewChallengeStore(time.Minute)
	var seen int
	deps := dependencies{
		AttestHandler:     AttestHandler{Challenges: &cs},
		ReadyFn:           func() bool { return true },
		RateLimiter:       limiter,
		ChallengeLimiter:  newTestRateLimiter(t),
		MaxRequestSize:    8,
		SecretsHandler:    &secrets.Handler{},
		SecretsChallenges: &secretsCS,
		SecretsExplain:    &secrets.ExplainHandler{},
		SecretsOperator: &secrets.OperatorHandler{
			Store:        secrets.NewMemoryStore(8, 7, 4096),
			MaxBodyBytes: allowlistWriteBodyCap,
			Authorize:    func(_ *http.Request, body []byte) error { seen = len(body); return nil },
		},
	}
	r := newRouter(deps)

	value := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 512))
	body := `{"value":"` + value + `"}`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/secrets/api/db", strings.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", w.Code, w.Body)
	}
	if seen != len(body) {
		t.Fatalf("authorizer saw %d bytes, want the whole %d-byte body", seen, len(body))
	}
}

// The diagnostic is a sibling of /secrets, not a path beneath it. chi prefers a
// literal segment over a wildcard, so had it been mounted at
// /secrets/explain/... every secret stored under /explain/ would have become
// unreachable — a store path silently shadowed by a route.
func TestRouter_ExplainDoesNotShadowSecretPaths(t *testing.T) {
	r := secretsRouter(t, true)

	sandbox := strings.Repeat("a", 64)
	if code := get(t, r, http.MethodGet, "/secrets-explain/"+sandbox); code != http.StatusUnauthorized {
		t.Fatalf("GET /secrets-explain = %d, want 401 (operator-authorized)", code)
	}
	// A secret literally under /explain still reaches the release handler,
	// which refuses it for want of a client certificate rather than 404ing.
	for _, p := range []string{"/secrets/explain", "/secrets/explain/" + sandbox, "/secrets/explain/db"} {
		if code := get(t, r, http.MethodGet, p); code == http.StatusNotFound {
			t.Fatalf("GET %s = 404: the explain route shadowed a store path", p)
		}
	}
}

// leafWithSandbox mints a client certificate carrying a sandbox ID, as CDS
// stamps one, so a request can arrive with an identity the router can key on.
func leafWithSandbox(t *testing.T, sandboxID string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ext, err := armtls.MarshalSandboxIDExtension(sandboxID)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The workload secret routes must bound one sandbox, not one address. Every pod
// on a node reaches CDS from the same address through the NodePort and the mesh
// proxy, so an address bucket lets one pod wedge its co-tenants' fetchers.
func TestRouter_SecretRoutesRateLimitPerSandbox(t *testing.T) {
	// Burst of one, so the second request against a given bucket is refused.
	limiter, err := issuer.NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	secretsCS := attestation.NewChallengeStore(time.Minute)
	r := newRouter(dependencies{
		AttestHandler:     AttestHandler{Challenges: &cs},
		ReadyFn:           func() bool { return true },
		RateLimiter:       limiter,
		ChallengeLimiter:  newTestRateLimiter(t),
		MaxRequestSize:    65536,
		SecretsHandler:    &secrets.Handler{},
		SecretsChallenges: &secretsCS,
		SecretsOperator:   &secrets.OperatorHandler{Store: secrets.NewMemoryStore(8, 7, 64)},
		SecretsExplain:    &secrets.ExplainHandler{},
	})

	send := func(leaf *x509.Certificate) int {
		req := httptest.NewRequest(http.MethodGet, "/secrets/api/db", nil)
		req.RemoteAddr = "10.0.0.7:34567" // the node address every pod shares
		if leaf != nil {
			req.TLS = &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{leaf},
				VerifiedChains:   [][]*x509.Certificate{{leaf}},
			}
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}

	victim := leafWithSandbox(t, strings.Repeat("a", 64))
	hostile := leafWithSandbox(t, strings.Repeat("b", 64))

	// The hostile pod spends its own burst and is refused for more.
	if code := send(hostile); code == http.StatusTooManyRequests {
		t.Fatal("the first request was rate limited")
	}
	if code := send(hostile); code != http.StatusTooManyRequests {
		t.Fatalf("a sandbox past its burst = %d, want 429", code)
	}
	// The co-tenant on the same address still gets through.
	if code := send(victim); code == http.StatusTooManyRequests {
		t.Fatal("one pod exhausted a co-tenant's bucket: the limiter is keyed on the address")
	}
}
