package secrets

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// failingStore stands in for a backend that is reachable but not working, so
// the handler's 500 paths are exercised separately from its 403/404 ones.
type failingStore struct{ err error }

func (f failingStore) Get(context.Context, string) ([]byte, error) { return nil, f.err }
func (f failingStore) PutIfAbsent(context.Context, string, []byte, Holder) ([]byte, Held, error) {
	return nil, Held{}, f.err
}
func (f failingStore) Put(context.Context, string, []byte) (Held, error) {
	return Held{}, f.err
}
func (f failingStore) TopHolders(int) []HolderPaths { return nil }

// A store failure is not a policy denial: the caller is told the secret is
// unavailable, and the reason stays in the CDS log.
func TestStoreFailureIsFiveHundred(t *testing.T) {
	for _, tc := range []struct{ name, method string }{
		{"read", http.MethodGet},
		{"create", http.MethodPost},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			hn.h.Store = failingStore{err: fmt.Errorf("backend down")}
			if w := do(hn.h, hn.request(t, tc.method, "/api/db")); w.Code != http.StatusInternalServerError {
				t.Fatalf("%s = %d, want 500", tc.method, w.Code)
			}
		})
	}
}

// Reading a granted path that holds nothing is a plain 404 — the same answer an
// ungranted path gets, so the two are indistinguishable from outside.
func TestReadMissingSecretIsNotFound(t *testing.T) {
	hn := newHarness(t)
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/never-created")); w.Code != http.StatusNotFound {
		t.Fatalf("missing secret = %d, want 404", w.Code)
	}
}

func TestChallengeHeaderRejections(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"missing", func(r *http.Request) { r.Header.Del("X-C8s-Challenge") }},
		{"not base64", func(r *http.Request) { r.Header.Set("X-C8s-Challenge", "!!!not base64!!!") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			r := hn.request(t, http.MethodGet, "/api/db")
			tc.mutate(r)
			if w := do(hn.h, r); w.Code != http.StatusBadRequest {
				t.Fatalf("%s challenge = %d, want 400", tc.name, w.Code)
			}
		})
	}
}

func TestNoChallengeStoreRefuses(t *testing.T) {
	hn := newHarness(t)
	hn.h.Challenges = nil
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusBadRequest {
		t.Fatalf("unconfigured challenge store = %d, want 400", w.Code)
	}
}

func TestTokenHeaderRejections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"missing", ""},
		{"wrong scheme", "Bearer " + base64.StdEncoding.EncodeToString([]byte(`{"token":"","signature":""}`))},
		{"not base64", AuthScheme + "!!!"},
		{"not json", AuthScheme + base64.StdEncoding.EncodeToString([]byte("not json"))},
		{"unknown field", AuthScheme + base64.StdEncoding.EncodeToString([]byte(`{"token":"AA==","signature":"AA==","extra":1}`))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			r := hn.request(t, http.MethodGet, "/api/db")
			if tc.value == "" {
				r.Header.Del("Authorization")
			} else {
				r.Header.Set("Authorization", tc.value)
			}
			if w := do(hn.h, r); w.Code != http.StatusForbidden {
				t.Fatalf("%s token = %d, want 403", tc.name, w.Code)
			}
		})
	}
}

// Each of these leaves the handler unable to reach or bound an inventory, so it
// must refuse rather than dial anything.
func TestInventoryMisconfigurationRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Handler)
	}{
		{"no inventory client", func(h *Handler) { h.Inventory = nil }},
		{"no bindings", func(h *Handler) { h.Bindings = nil }},
		{"no cidrs", func(h *Handler) { h.InventoryHosts = nil }},
		{"bound host outside cidrs", func(h *Handler) { h.Bindings = fakeBindings{host: "203.0.113.5"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			tc.mutate(&hn.h)
			if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
				t.Fatalf("%s = %d, want 403", tc.name, w.Code)
			}
		})
	}
}

// An unreachable inventory is fail-closed: CDS cannot establish what the
// sandbox runs, so it releases nothing.
func TestInventoryFetchFailureRefuses(t *testing.T) {
	hn := newHarness(t)
	hn.inv.err = fmt.Errorf("dial timeout")
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("unreachable inventory = %d, want 403", w.Code)
	}
}

// A sandbox whose only containers are C8s's own has nothing to match an entry
// against, so it is refused rather than matched vacuously.
func TestOnlyInjectedContainersRefuses(t *testing.T) {
	hn := newHarness(t)
	hn.inv.containers = []workloadclaims.SandboxContainer{
		{Digest: testInjected, Argv: []string{"get-cert", "--san=x"}, Role: roleCredentials},
	}
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("injected-only sandbox = %d, want 403", w.Code)
	}
}

// A reported container with no digest cannot be matched, so the whole answer is
// refused rather than partly trusted.
func TestContainerWithoutDigestRefuses(t *testing.T) {
	hn := newHarness(t)
	hn.inv.containers = []workloadclaims.SandboxContainer{
		{Digest: testAppImg, Argv: []string{"/serve"}},
		{Digest: "", Argv: []string{"/other"}},
	}
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("digest-less container = %d, want 403", w.Code)
	}
}

// A container the node binds no role to stays in the candidate set and makes
// the pod foreign, here with no argv at all to read.
func TestArgvLessContainerIsNotDropped(t *testing.T) {
	hn := newHarness(t)
	hn.inv.containers = append(hn.inv.containers,
		workloadclaims.SandboxContainer{Digest: testInjected})
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("argv-less injected image = %d, want 403", w.Code)
	}
}

// An allowlist that cannot be loaded is an internal failure, not a denial.
type failingPolicy struct{}

func (failingPolicy) Allowlist() (*pkgallowlist.Allowlist, error) {
	return nil, fmt.Errorf("allowlist unavailable")
}

func TestPolicyFailureRefuses(t *testing.T) {
	hn := newHarness(t)
	hn.h.Policy = failingPolicy{}
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("unloadable allowlist = %d, want 403", w.Code)
	}
}

// A request outside the route prefix cannot name a store path.
func TestRequestPathOutsidePrefix(t *testing.T) {
	hn := newHarness(t)
	r := hn.request(t, http.MethodGet, "/api/db")
	r.URL.Path = "/elsewhere/api/db"
	r.URL.RawPath = ""
	if w := do(hn.h, r); w.Code != http.StatusBadRequest {
		t.Fatalf("path outside /secrets = %d, want 400", w.Code)
	}
}

func TestDenialError(t *testing.T) {
	if got := deny("sandbox %s is unbound", "abc").Error(); got != "sandbox abc is unbound" {
		t.Fatalf("Error() = %q", got)
	}
}

// A handler with no logger configured still serves; it falls back to the
// default rather than panicking on a denial path.
func TestHandlerWithoutLogger(t *testing.T) {
	hn := newHarness(t)
	hn.h.Logger = nil
	if w := do(hn.h, hn.request(t, http.MethodGet, "/other/db")); w.Code != http.StatusNotFound {
		t.Fatalf("logger-less handler = %d, want 404", w.Code)
	}
}

// --- rate-limit keying ---

// The key is the sandbox, not the address: pods share a node's address through
// the NodePort and the mesh proxy, so an address bucket is a shared one.
func TestRateKeyUsesTheVerifiedSandbox(t *testing.T) {
	leaf, _ := leafFor(t, testSandbox)
	r := httptest.NewRequest(http.MethodGet, "/secrets/api/db", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	if got := RateKey(r); got != "sandbox:"+testSandbox {
		t.Fatalf("RateKey = %q, want the sandbox bucket", got)
	}
}

// A certificate crypto/tls has not chained to the mesh CA carries a sandbox ID
// its holder chose. Keying on it would let anyone able to mint a self-signed
// leaf name a victim's bucket and exhaust it — the denial this keying exists to
// prevent, handed to an unauthenticated caller.
func TestRateKeyIgnoresAnUnverifiedCertificate(t *testing.T) {
	leaf, _ := leafFor(t, testSandbox)
	r := httptest.NewRequest(http.MethodGet, "/secrets/api/db", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	if got := RateKey(r); got != "" {
		t.Fatalf("RateKey = %q, want the address fallback for an unverified chain", got)
	}
}

func TestRateKeyFallsBackWithoutASandbox(t *testing.T) {
	for _, tc := range []struct {
		name string
		tls  *tls.ConnectionState
	}{
		{"no TLS", nil},
		{"no certificate", &tls.ConnectionState{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/secrets/api/db", nil)
			r.TLS = tc.tls
			if got := RateKey(r); got != "" {
				t.Fatalf("RateKey = %q, want the address fallback", got)
			}
		})
	}

	// A verified leaf carrying no sandbox extension is the same case.
	bare, _ := leafFor(t, "")
	r := httptest.NewRequest(http.MethodGet, "/secrets/api/db", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{bare},
		VerifiedChains:   [][]*x509.Certificate{{bare}},
	}
	if got := RateKey(r); got != "" {
		t.Fatalf("RateKey = %q, want the address fallback with no sandbox ID", got)
	}
}
