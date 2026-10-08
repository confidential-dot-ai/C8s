package cds

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/attestation"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// operatorRouter serves a journaled store whose allowlist writes take an
// operator token through authorize, as run wires them.
func operatorRouter(t *testing.T, authorize allowlist.WriteAuthorizer) (http.Handler, *allowlist.Store) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	if err := store.StartJournal("sha256:auth", 0); err != nil {
		t.Fatal(err)
	}
	cs := attestation.NewChallengeStore(time.Minute)
	return newRouter(dependencies{
		AttestHandler:    AttestHandler{Challenges: &cs},
		AllowlistHandler: allowlist.Handler{Store: &store, WriteAuthorizer: authorize},
		ReadyFn:          func() bool { return true },
		RateLimiter:      newTestRateLimiter(t),
		ChallengeLimiter: newTestRateLimiter(t),
		MaxRequestSize:   65536,
	}), &store
}

func operatorSigner(t *testing.T) (*operatorauth.Signer, operatorauth.Verifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := operatorauth.NewSignerFromKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	return signer, operatorauth.Verifier{Keys: []*ecdsa.PublicKey{&key.PublicKey}, ClockSkew: time.Minute}
}

func canonicalPolicy(t *testing.T) []byte {
	t.Helper()
	doc, err := pkgallowlist.ParseJSON([]byte(`{"schema":"` + pkgallowlist.Schema + `","workloads":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A write token authorizes one write: CDS publishes it as the policy's
// signature at once, and a replay of it is refused.
func TestOperatorTokenIsSingleUse(t *testing.T) {
	signer, verifier := operatorSigner(t)
	var store *allowlist.Store
	r, store := operatorRouter(t, func(req *http.Request, body []byte) error {
		return singleUse(verifier.Authorize, store, time.Minute)(req, body)
	})
	body := canonicalPolicy(t)
	auth, err := signer.Authorization(http.MethodPut, "/allowlist", body)
	if err != nil {
		t.Fatal(err)
	}
	put := func() int {
		req := httptest.NewRequest(http.MethodPut, "/allowlist", strings.NewReader(string(body)))
		req.Header.Set("Authorization", auth)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	if code := put(); code != http.StatusNoContent {
		t.Fatalf("first PUT /allowlist = %d, want 204", code)
	}
	sum := sha256.Sum256(body)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, fmt.Sprintf("%s/objects/sha256/%x/signature", wellKnown, sum), nil))
	if w.Code != http.StatusOK || "Bearer "+w.Body.String() != auth {
		t.Fatalf("GET signature = %d %q, want 200 with the write token", w.Code, w.Body)
	}
	if code := put(); code != http.StatusUnauthorized {
		t.Fatalf("replayed PUT /allowlist = %d, want 401", code)
	}
	for path, want := range map[string]int{
		wellKnown + "/objects/sha256/" + strings.Repeat("0", 64) + "/signature":         http.StatusNotFound,
		wellKnown + "/objects/sha256/" + hex.EncodeToString([]byte("x")) + "/signature": http.StatusBadRequest,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != want {
			t.Errorf("GET %s = %d, want %d", path, w.Code, want)
		}
	}
}

func TestAllowlistAuthorizer(t *testing.T) {
	disabled := func(*http.Request, []byte) error {
		return fmt.Errorf("operator writes are disabled: set --operator-keys")
	}
	allow := func(*http.Request, []byte) error { return nil }
	for _, tc := range []struct {
		name      string
		immutable bool
		write     allowlist.WriteAuthorizer
		keys      string
		refused   string
		writers   string
	}{
		{"writable", false, allow, "abc", "", "abc"},
		{"immutable", true, allow, "abc", "immutable", types.OperatorKeysNone},
		{"no operator keys", false, disabled, "", "--operator-keys", types.OperatorKeysNone},
	} {
		authorize, writers := allowlistAuthorizer(tc.immutable, tc.write, tc.keys)
		err := authorize(httptest.NewRequest(http.MethodPut, "/allowlist", nil), nil)
		if writers != tc.writers || (tc.refused == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tc.refused)) {
			t.Errorf("%s: writers %q, err %v; want %q, refusal containing %q", tc.name, writers, err, tc.writers, tc.refused)
		}
	}
}
