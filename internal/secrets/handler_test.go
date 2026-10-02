package secrets

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/ratls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const (
	testSandbox = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	// testSandbox2 runs the same containers as testSandbox, so it matches the
	// same workload entry; testBulkSandbox matches the other one.
	testSandbox2    = "1023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testBulkSandbox = "2023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testHost        = "10.0.0.7"
	testAppImg      = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	// testAppImg2 is the entry's second main: release is gated on both running.
	testAppImg2  = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	testInjected = "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	testOther    = "sha256:8888888888888888888888888888888888888888888888888888888888888888"
	// testInjectedOld is the previous release's injected image, still running in
	// pods created before an upgrade.
	testInjectedOld = "sha256:7777777777777777777777777777777777777777777777777777777777777777"
	// testWorkerImg is the main of a second workload entry, declared only by
	// tests that need one.
	testWorkerImg = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
	// testBulkImg is the main of the "bulk" entry, likewise declared where it
	// is needed. Its digest is its own: a digest two entries share matches both
	// the moment either widens its argv, and MatchWorkload answers ambiguous.
	testBulkImg = "sha256:4444444444444444444444444444444444444444444444444444444444444444"
)

// --- fakes ---

type fakeChallenges struct{ used map[string]bool }

func (f *fakeChallenges) Consume(c []byte) bool {
	k := string(c)
	if f.used[k] {
		return false
	}
	if f.used == nil {
		f.used = map[string]bool{}
	}
	f.used[k] = true
	return true
}

// keys is per host so a token signed under another inventory's key fails
// verification the way it would against the real client, which resolves the
// key by dialling the host.
type fakeInventory struct {
	keys       map[string]*ecdsa.PublicKey
	containers []workloadclaims.SandboxContainer
	// bySandbox overrides containers for the sandboxes it names.
	bySandbox    map[string][]workloadclaims.SandboxContainer
	err          error
	legacyMounts bool
}

func (f *fakeInventory) InventoryKey(_ context.Context, host string) (*ecdsa.PublicKey, error) {
	key, ok := f.keys[host]
	if !ok {
		return nil, fmt.Errorf("no inventory at %s", host)
	}
	return key, nil
}
func (f *fakeInventory) FetchSandbox(_ context.Context, _, sandboxID string) (workloadclaims.SandboxDigestsResponse, error) {
	if f.err != nil {
		return workloadclaims.SandboxDigestsResponse{}, f.err
	}
	containers, ok := f.bySandbox[sandboxID]
	if !ok {
		containers = f.containers
	}
	containers = slices.Clone(containers)
	if !f.legacyMounts {
		for i := range containers {
			if containers[i].Mounts == nil {
				containers[i].Mounts = []pkgallowlist.ObservedMount{}
			}
		}
	}
	digests := make([]string, 0, len(containers))
	for _, c := range containers {
		digests = append(digests, c.Digest)
	}
	return workloadclaims.SandboxDigestsResponse{Digests: digests, Containers: containers}, nil
}

type fakeBindings struct{ host string }

func (f fakeBindings) Lookup(string) (string, bool) {
	if f.host == "" {
		return "", false
	}
	return f.host, true
}

type fakePolicy struct{ al *pkgallowlist.Allowlist }

func (f fakePolicy) Allowlist() (*pkgallowlist.Allowlist, error) { return f.al, nil }

// --- scaffolding ---

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// anyEntry is a one-container entry admitting digest under any argv.
func anyEntry(t *testing.T, digest, image string) pkgallowlist.Workload {
	t.Helper()
	return pkgallowlist.Workload{Label: image, Containers: []pkgallowlist.Container{{
		Digest:  mustDigest(t, digest),
		Image:   image,
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
	}}}
}

// leafFor mints a client certificate carrying sandboxID, as CDS stamps it.
func leafFor(t *testing.T, sandboxID string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "workload"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if sandboxID != "" {
		ext, err := ratls.MarshalSandboxIDExtension(sandboxID)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

type harness struct {
	h          Handler
	signer     *workloadclaims.SandboxTokenSigner
	leaf       *x509.Certificate
	challenges *fakeChallenges
	inv        *fakeInventory
	store      *MemoryStore
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	signer, err := workloadclaims.NewSandboxTokenSigner(testHost)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := leafFor(t, testSandbox)
	cidrs, err := workloadclaims.ParseInventoryHosts([]string{"10.0.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	al := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{
		"c8s":     anyEntry(t, testInjected, "ghcr.io/confidential-dot-ai/c8s@"+testInjected),
		"c8s-old": anyEntry(t, testInjectedOld, "ghcr.io/confidential-dot-ai/c8s@"+testInjectedOld),
		"busybox": anyEntry(t, testOther, "docker.io/library/busybox@"+testOther),
		// Two mains: release is gated on every main container running, so the
		// gate is only exercisable with more than one.
		"api": {
			Containers: []pkgallowlist.Container{
				{
					Digest:  mustDigest(t, testAppImg),
					Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/serve"}},
					Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
				},
				{
					Digest:  mustDigest(t, testAppImg2),
					Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/metrics"}},
					Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
				},
			},
			Secrets: &pkgallowlist.SecretsPolicy{
				Policy: pkgallowlist.PolicyAllow,
				Read:   []string{"/api/**"},
				Write:  []string{"/api/**"},
			},
		},
	}}
	inv := &fakeInventory{
		keys: map[string]*ecdsa.PublicKey{testHost: signer.PublicKey()},
		containers: []workloadclaims.SandboxContainer{
			{Digest: testAppImg, Argv: []string{"/serve"}},
			{Digest: testAppImg2, Argv: []string{"/metrics"}},
			{Digest: testInjected, Argv: []string{"get-cert", "--san=x"}},
		},
	}
	challenges := &fakeChallenges{used: map[string]bool{}}
	store := NewMemoryStore(16, 15, 64)
	return &harness{
		h: Handler{
			Store:          store,
			Challenges:     challenges,
			Inventory:      inv,
			Bindings:       fakeBindings{host: testHost},
			Policy:         fakePolicy{al: al},
			InventoryHosts: cidrs,
		},
		signer: signer, leaf: leaf, challenges: challenges, inv: inv, store: store,
	}
}

// setStore swaps in a store bounded for the test at hand.
func (hn *harness) setStore(t *testing.T, s *MemoryStore) {
	t.Helper()
	hn.store, hn.h.Store = s, s
}

// declareBulkEntry adds a second granted entry, running in testBulkSandbox, and
// returns the leaf that sandbox presents.
func (hn *harness) declareBulkEntry(t *testing.T) *x509.Certificate {
	t.Helper()
	al, err := hn.h.Policy.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	al.Workloads["bulk"] = pkgallowlist.Workload{
		Containers: []pkgallowlist.Container{{
			Digest:  mustDigest(t, testBulkImg),
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/bulk"}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		}},
		Secrets: &pkgallowlist.SecretsPolicy{
			Policy: pkgallowlist.PolicyAllow,
			Read:   []string{"/bulk/**"},
			Write:  []string{"/bulk/**"},
		},
	}
	if hn.inv.bySandbox == nil {
		hn.inv.bySandbox = map[string][]workloadclaims.SandboxContainer{}
	}
	hn.inv.bySandbox[testBulkSandbox] = []workloadclaims.SandboxContainer{
		{Digest: testBulkImg, Argv: []string{"/bulk"}},
		{Digest: testInjected, Argv: []string{"get-secret"}},
	}
	leaf, _ := leafFor(t, testBulkSandbox)
	return leaf
}

// request builds a request as the fetcher would send it.
func (hn *harness) request(t *testing.T, method, path string) *http.Request {
	t.Helper()
	return hn.requestWith(t, method, path, hn.leaf, testSandbox, []byte("nonce-"+path+method))
}

func (hn *harness) requestWith(t *testing.T, method, path string, leaf *x509.Certificate, tokenSandbox string, nonce []byte) *http.Request {
	t.Helper()
	token := mintToken(t, hn.signer, tokenSandbox, leaf.PublicKey, nonce)
	return hn.requestWithToken(t, method, path, leaf, token, nonce)
}

// requestWithToken sends an explicitly minted token against nonce, so a test
// controls what the token proves independently of what the request carries.
func (hn *harness) requestWithToken(t *testing.T, method, path string, leaf *x509.Certificate, token *workloadclaims.SignedSandboxToken, nonce []byte) *http.Request {
	t.Helper()
	body, _ := json.Marshal(token)
	r := httptest.NewRequest(method, "/secrets"+path, nil)
	r.Header.Set(ChallengeHeader, base64.StdEncoding.EncodeToString(nonce))
	r.Header.Set("Authorization", AuthScheme+base64.StdEncoding.EncodeToString(body))
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
		VerifiedChains:   [][]*x509.Certificate{{leaf}},
	}
	return r
}

// mintToken signs with signer over the given sandbox, requester key, and
// nonce — the axes verifyToken checks, each bendable on its own.
func mintToken(t *testing.T, signer *workloadclaims.SandboxTokenSigner, sandboxID string, pub crypto.PublicKey, nonce []byte) *workloadclaims.SignedSandboxToken {
	t.Helper()
	keyDigest, err := workloadclaims.RequesterKeyDigest(pub)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signer.Sign(sandboxID, keyDigest, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// seed plants a value directly, bypassing the release path under test.
func (hn *harness) seed(t *testing.T, path string, value []byte) {
	t.Helper()
	if _, err := hn.store.Put(context.Background(), path, value); err != nil {
		t.Fatal(err)
	}
}

// seedAs is seed charged to holder rather than to the operator.
func (hn *harness) seedAs(t *testing.T, path string, holder Holder) {
	t.Helper()
	if _, _, err := hn.store.PutIfAbsent(context.Background(), path, []byte("neighbour-value"), holder); err != nil {
		t.Fatal(err)
	}
}

// loggedHolder is one census entry as it lands in CDS's JSON log.
type loggedHolder struct {
	Holder string `json:"holder"`
	Paths  int    `json:"paths"`
}

// logCensus collects the holders attribute from every captured log line.
func logCensus(t *testing.T, out string) []loggedHolder {
	t.Helper()
	var found []loggedHolder
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		var rec struct {
			Holders []loggedHolder `json:"holders"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		found = append(found, rec.Holders...)
	}
	return found
}

// assertNoRelease fails if a refused response carries value, raw or base64.
func assertNoRelease(t *testing.T, w *httptest.ResponseRecorder, value []byte) {
	t.Helper()
	for _, leak := range []string{string(value), base64.StdEncoding.EncodeToString(value)} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("a refused request leaked the secret: %s", w.Body)
		}
	}
}

func do(h Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decodeValue(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var v valueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	return v.Value
}

// --- tests ---

func TestCreateThenRead(t *testing.T) {
	hn := newHarness(t)

	w := do(hn.h, hn.request(t, http.MethodPost, "/api/db"))
	if w.Code != http.StatusCreated {
		t.Fatalf("POST = %d (%s), want 201", w.Code, w.Body)
	}
	created := decodeValue(t, w)

	w = do(hn.h, hn.request(t, http.MethodGet, "/api/db"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d (%s), want 200", w.Code, w.Body)
	}
	if got := decodeValue(t, w); got != created {
		t.Fatal("GET returned a different value than POST created")
	}
}

// The replica that loses the create race is told 409 with no value, and
// recovers by reading.
func TestCreateOnExistingConflicts(t *testing.T) {
	hn := newHarness(t)
	do(hn.h, hn.request(t, http.MethodPost, "/api/db"))

	w := do(hn.h, hn.requestWith(t, http.MethodPost, "/api/db", hn.leaf, testSandbox, []byte("n2")))
	if w.Code != http.StatusConflict {
		t.Fatalf("second POST = %d, want 409", w.Code)
	}
	if strings.Contains(w.Body.String(), "value") {
		t.Fatalf("409 leaked a value: %s", w.Body)
	}
}

func TestUngrantedPathIsNotFound(t *testing.T) {
	hn := newHarness(t)
	w := do(hn.h, hn.request(t, http.MethodGet, "/other/db"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("ungranted GET = %d, want 404 (indistinguishable from absent)", w.Code)
	}
}

func TestChallengeIsSingleUse(t *testing.T) {
	hn := newHarness(t)
	nonce := []byte("reused")
	if w := do(hn.h, hn.requestWith(t, http.MethodPost, "/api/db", hn.leaf, testSandbox, nonce)); w.Code != http.StatusCreated {
		t.Fatalf("first = %d", w.Code)
	}
	if w := do(hn.h, hn.requestWith(t, http.MethodGet, "/api/db", hn.leaf, testSandbox, nonce)); w.Code != http.StatusBadRequest {
		t.Fatalf("replayed challenge = %d, want 400", w.Code)
	}
}

// A denied request spends its nonce: a nonce that survived a denial could be
// replayed with a valid token against another method or path.
func TestChallengeIsConsumedEvenOnDenial(t *testing.T) {
	hn := newHarness(t)
	nonce := []byte("spent-on-denial")
	bad := mintToken(t, hn.signer, testSandbox, hn.leaf.PublicKey, []byte("another-challenge"))
	if w := do(hn.h, hn.requestWithToken(t, http.MethodGet, "/api/db", hn.leaf, bad, nonce)); w.Code != http.StatusForbidden {
		t.Fatalf("denied request = %d, want 403", w.Code)
	}
	good := mintToken(t, hn.signer, testSandbox, hn.leaf.PublicKey, nonce)
	if w := do(hn.h, hn.requestWithToken(t, http.MethodPost, "/api/db", hn.leaf, good, nonce)); w.Code != http.StatusBadRequest {
		t.Fatalf("replayed nonce = %d, want 400", w.Code)
	}
}

// An unverified chain must never be trusted for the sandbox ID: a self-signed
// leaf's extension is whatever its minter chose.
func TestUnverifiedChainRefused(t *testing.T) {
	hn := newHarness(t)
	r := hn.request(t, http.MethodGet, "/api/db")
	r.TLS.VerifiedChains = nil
	if w := do(hn.h, r); w.Code != http.StatusForbidden {
		t.Fatalf("unverified chain = %d, want 403", w.Code)
	}
}

func TestNoClientCertRefused(t *testing.T) {
	hn := newHarness(t)
	r := hn.request(t, http.MethodGet, "/api/db")
	r.TLS = &tls.ConnectionState{}
	if w := do(hn.h, r); w.Code != http.StatusForbidden {
		t.Fatalf("certless = %d, want 403", w.Code)
	}
}

func TestCertWithoutSandboxIDRefused(t *testing.T) {
	hn := newHarness(t)
	bare, _ := leafFor(t, "")
	r := hn.requestWith(t, http.MethodGet, "/api/db", bare, testSandbox, []byte("n"))
	if w := do(hn.h, r); w.Code != http.StatusForbidden {
		t.Fatalf("no sandbox ID = %d, want 403", w.Code)
	}
}

// A token for a sandbox other than the certificate's must not be redeemable.
func TestTokenSandboxMustMatchCert(t *testing.T) {
	hn := newHarness(t)
	other := strings.Repeat("a", 64)
	r := hn.requestWith(t, http.MethodGet, "/api/db", hn.leaf, other, []byte("n"))
	if w := do(hn.h, r); w.Code != http.StatusForbidden {
		t.Fatalf("mismatched sandbox = %d, want 403", w.Code)
	}
}

// Without a ledger binding there is no inventory this process will believe.
func TestUnboundSandboxRefused(t *testing.T) {
	hn := newHarness(t)
	hn.h.Bindings = fakeBindings{}
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("unbound sandbox = %d, want 403", w.Code)
	}
}

// A token naming an inventory other than the bound one is refused even though
// its signature verifies: the binding, not the token, chooses who is asked.
func TestTokenHostMustMatchBinding(t *testing.T) {
	hn := newHarness(t)
	hn.h.Bindings = fakeBindings{host: "10.0.0.9"}
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("host mismatch = %d, want 403", w.Code)
	}
}

// The signature must verify under the key the bound inventory serves: an
// impostor naming the right host still signs with the wrong key.
func TestTokenSignedByAnotherInventoryRefused(t *testing.T) {
	hn := newHarness(t)
	impostor, err := workloadclaims.NewSandboxTokenSigner(testHost)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("impostor")
	token := mintToken(t, impostor, testSandbox, hn.leaf.PublicKey, nonce)
	stored := []byte("stored-secret")
	hn.seed(t, "/api/db", stored)
	w := do(hn.h, hn.requestWithToken(t, http.MethodGet, "/api/db", hn.leaf, token, nonce))
	if w.Code != http.StatusForbidden {
		t.Fatalf("impostor-signed token = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, stored)
}

// The token is bound to one requester key: a token minted for another key must
// not be redeemable by this pod's leaf.
func TestTokenBoundToAnotherKeyRefused(t *testing.T) {
	hn := newHarness(t)
	other, _ := leafFor(t, testSandbox)
	nonce := []byte("bound-to-another-key")
	token := mintToken(t, hn.signer, testSandbox, other.PublicKey, nonce)
	stored := []byte("stored-secret")
	hn.seed(t, "/api/db", stored)
	w := do(hn.h, hn.requestWithToken(t, http.MethodGet, "/api/db", hn.leaf, token, nonce))
	if w.Code != http.StatusForbidden {
		t.Fatalf("token for another key = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, stored)
}

// The token carries this request's challenge: one minted against another
// challenge is stale here even though its signature verifies.
func TestTokenForAnotherChallengeRefused(t *testing.T) {
	hn := newHarness(t)
	token := mintToken(t, hn.signer, testSandbox, hn.leaf.PublicKey, []byte("another-challenge"))
	stored := []byte("stored-secret")
	hn.seed(t, "/api/db", stored)
	w := do(hn.h, hn.requestWithToken(t, http.MethodGet, "/api/db", hn.leaf, token, []byte("this-request")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("token for another challenge = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, stored)
}

// An any-argv image the entry does not declare is still foreign: unconstrained
// admission alone must not drop a container, or a pod could add busybox running
// a shell and have it ignored.
func TestForeignAnyArgvContainerRefused(t *testing.T) {
	hn := newHarness(t)
	hn.inv.containers = append(hn.inv.containers,
		workloadclaims.SandboxContainer{Digest: testOther, Argv: []string{"/bin/sh"}})
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("foreign container = %d, want 403", w.Code)
	}
}

// The injected image is an argv-unconstrained entry, so it is dropped only
// when running an injected entrypoint. A pod that adds it running a shell
// must not have that container ignored.
func TestInjectedImageWithForeignArgvIsNotDropped(t *testing.T) {
	hn := newHarness(t)
	hn.inv.containers = append(hn.inv.containers,
		workloadclaims.SandboxContainer{Digest: testInjected, Argv: []string{"/bin/sh", "-c", "cat /run/c8s/secrets/*"}})
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("smuggled injected-image container = %d, want 403", w.Code)
	}
}

// An inventory too old to report per-container detail cannot support a
// (digest, argv) decision, so it is refused rather than silently matched on
// digests alone.
func TestInventoryWithoutContainerDetailRefused(t *testing.T) {
	hn := newHarness(t)
	hn.inv.containers = nil
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("detail-less inventory = %d, want 403", w.Code)
	}
}

func TestEntryWithoutGrantRefused(t *testing.T) {
	hn := newHarness(t)
	al := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{
		"c8s":     anyEntry(t, testInjected, "ghcr.io/confidential-dot-ai/c8s@"+testInjected),
		"c8s-old": anyEntry(t, testInjectedOld, "ghcr.io/confidential-dot-ai/c8s@"+testInjectedOld),
		"busybox": anyEntry(t, testOther, "docker.io/library/busybox@"+testOther),
		"api": {Containers: []pkgallowlist.Container{{
			Digest:  mustDigest(t, testAppImg),
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/serve"}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		}}},
	}}
	hn.h.Policy = fakePolicy{al: al}
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("grantless entry = %d, want 403", w.Code)
	}
}

// A grant on an entry that leaves a container's argv unconstrained is refused
// at release, whatever the write path let through: the value would go to
// whatever command line the host chose.
func TestGrantOnUnpinnedEntryRefused(t *testing.T) {
	hn := newHarness(t)
	var log bytes.Buffer
	hn.h.Logger = slog.New(slog.NewTextHandler(&log, nil))
	hn.h.Policy = fakePolicy{al: &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{
		"c8s": anyEntry(t, testInjected, "ghcr.io/confidential-dot-ai/c8s@"+testInjected),
		"api": {
			Containers: []pkgallowlist.Container{
				{
					Digest:  mustDigest(t, testAppImg),
					Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/serve"}},
					Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
				},
				{
					Digest:  mustDigest(t, testAppImg2),
					Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/metrics"}},
					Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
				},
			},
			Secrets: &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/api/**"}},
		},
	}}}
	stored := []byte("stored-secret")
	hn.seed(t, "/api/db", stored)

	w := do(hn.h, hn.request(t, http.MethodGet, "/api/db"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("unpinned entry with a grant = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, stored)
	if !strings.Contains(log.String(), "unconstrained") {
		t.Fatalf("refusal did not name the unpinned argv:\n%s", log.String())
	}
}

// Release is gated on the whole container set: until every main the entry
// declares is running, the sandbox matches nothing and is refused.
func TestReleaseRefusedUntilEveryMainIsRunning(t *testing.T) {
	hn := newHarness(t)
	stored := []byte("stored-secret")
	hn.seed(t, "/api/db", stored)
	hn.inv.containers = []workloadclaims.SandboxContainer{
		{Digest: testAppImg, Argv: []string{"/serve"}},
		{Digest: testInjected, Argv: []string{"get-cert", "--san=x"}},
	}
	w := do(hn.h, hn.request(t, http.MethodGet, "/api/db"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("one main not yet running = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, stored)
}

// Two entries the running set satisfies equally are a refusal, driven through
// Handler.authorize.
func TestAmbiguousMatchRefused(t *testing.T) {
	hn := newHarness(t)
	stored := []byte("stored-secret")
	hn.seed(t, "/api/db", stored)
	al, err := hn.h.Policy.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	al.Workloads["api-copy"] = al.Workloads["api"]
	w := do(hn.h, hn.request(t, http.MethodGet, "/api/db"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("ambiguous match = %d, want 403", w.Code)
	}
	assertNoRelease(t, w, stored)
}

// The grant honoured is the matched entry's own: a path only another entry
// grants is as absent as an ungranted one.
func TestGrantOfAnotherEntryIsNotHonoured(t *testing.T) {
	hn := newHarness(t)
	al, err := hn.h.Policy.Allowlist()
	if err != nil {
		t.Fatal(err)
	}
	al.Workloads["worker"] = pkgallowlist.Workload{
		Containers: []pkgallowlist.Container{{
			Digest:  mustDigest(t, testWorkerImg),
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/work"}},
			Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
		}},
		Secrets: &pkgallowlist.SecretsPolicy{
			Policy: pkgallowlist.PolicyAllow,
			Read:   []string{"/worker/**"},
			Write:  []string{"/worker/**"},
		},
	}
	// The store holds the other entry's secret, so honouring its grant would
	// release it.
	hn.seed(t, "/worker/db", []byte("worker-secret"))
	w := do(hn.h, hn.request(t, http.MethodGet, "/worker/db"))
	if w.Code != http.StatusNotFound {
		t.Fatalf("another entry's path = %d, want 404", w.Code)
	}
	if strings.Contains(w.Body.String(), "worker-secret") {
		t.Fatalf("another entry's grant released a value: %s", w.Body)
	}
}

func TestNonCanonicalPathRejected(t *testing.T) {
	hn := newHarness(t)
	for _, p := range []string{"/api/../etc", "/api/db/", "/api%2Fdb", ""} {
		r := hn.request(t, http.MethodGet, "/api/db")
		r.URL.Path = "/secrets" + p
		r.URL.RawPath = "/secrets" + p
		if w := do(hn.h, r); w.Code != http.StatusBadRequest {
			t.Fatalf("path %q = %d, want 400", p, w.Code)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	hn := newHarness(t)
	r := hn.request(t, http.MethodDelete, "/api/db")
	if w := do(hn.h, r); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE = %d, want 405", w.Code)
	}
}

// A pod created before a c8s image bump still runs the previous injected image.
// Both digests are configured for the length of an upgrade, so such a pod is
// not refused its secret until it happens to be recreated.
func TestInjectedImageFromPreviousReleaseIsDropped(t *testing.T) {
	hn := newHarness(t)
	hn.inv.containers = []workloadclaims.SandboxContainer{
		{Digest: testAppImg, Argv: []string{"/serve"}},
		{Digest: testAppImg2, Argv: []string{"/metrics"}},
		{Digest: testInjectedOld, Argv: []string{"get-cert", "--san=x"}},
	}
	if w := do(hn.h, hn.request(t, http.MethodPost, "/api/db")); w.Code != http.StatusCreated {
		t.Fatalf("pod running the previous injected image = %d, want 201", w.Code)
	}
}

// The store charges a created path to the allowlist entry that authorized it,
// so a workload that floods its quota does not spend another workload's.
func TestFloodingWorkloadDoesNotRefuseAnother(t *testing.T) {
	hn := newHarness(t)
	hn.setStore(t, NewMemoryStore(16, 2, 64))
	bulkLeaf := hn.declareBulkEntry(t)

	created, refused := 0, 0
	for i := range 10 {
		p := fmt.Sprintf("/bulk/%d", i)
		switch w := do(hn.h, hn.requestWith(t, http.MethodPost, p, bulkLeaf, testBulkSandbox, []byte("bulk"+p))); w.Code {
		case http.StatusCreated:
			created++
		case http.StatusInsufficientStorage:
			refused++
		default:
			t.Fatalf("flood POST %s = %d (%s), want 201 or 507", p, w.Code, w.Body)
		}
	}
	if created != 2 || refused != 8 {
		t.Fatalf("the flooding workload created %d paths and was refused %d, want 2 and 8", created, refused)
	}

	if w := do(hn.h, hn.request(t, http.MethodPost, "/api/db")); w.Code != http.StatusCreated {
		t.Fatalf("POST for another workload during the flood = %d (%s), want 201", w.Code, w.Body)
	}
}

// Two sandboxes of one workload share its quota. The charge is the allowlist
// entry the inventory's report matched, so restarting pods to get fresh sandbox
// IDs buys no room.
func TestQuotaIsPerWorkloadNotPerSandbox(t *testing.T) {
	hn := newHarness(t)
	hn.setStore(t, NewMemoryStore(16, 1, 64))
	sibling, _ := leafFor(t, testSandbox2)

	if w := do(hn.h, hn.request(t, http.MethodPost, "/api/db")); w.Code != http.StatusCreated {
		t.Fatalf("first POST = %d (%s), want 201", w.Code, w.Body)
	}
	w := do(hn.h, hn.requestWith(t, http.MethodPost, "/api/hf", sibling, testSandbox2, []byte("sibling")))
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("POST from a second sandbox of the same workload = %d, want 507", w.Code)
	}
	if hn.store.Len() != 1 {
		t.Fatalf("store holds %d paths, want 1", hn.store.Len())
	}
}

// A workload that has spent none of its quota is still refused by the ceiling
// when other holders have filled the store, and the refusal names the ceiling
// rather than the quota. Who holds the paths reaches the CDS log; the body
// carries the code and nothing else.
func TestCeilingRefusesAWorkloadUnderItsQuota(t *testing.T) {
	hn := newHarness(t)
	hn.setStore(t, NewMemoryStore(7, 3, 64))
	var log bytes.Buffer
	hn.h.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Six neighbours fill the store, the first holding two paths: enough for
	// the census to have a largest holder and one holder it must leave out.
	hn.seedAs(t, "/n1/a", WorkloadHolder("neighbour-1"))
	hn.seedAs(t, "/n1/b", WorkloadHolder("neighbour-1"))
	for i := 2; i <= 6; i++ {
		hn.seedAs(t, fmt.Sprintf("/n%d/a", i), WorkloadHolder(fmt.Sprintf("neighbour-%d", i)))
	}

	w := do(hn.h, hn.request(t, http.MethodPost, "/api/db"))
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("first POST against a full store = %d (%s), want 507", w.Code, w.Body)
	}
	if code := errorCode(t, w); code != types.ErrorCodeSecretStoreFull {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeSecretStoreFull)
	}
	if hn.store.Len() != 7 {
		t.Fatalf("store holds %d paths after a refusal, want the 7 it started with", hn.store.Len())
	}

	want := []loggedHolder{
		{`workload "neighbour-1"`, 2},
		{`workload "neighbour-2"`, 1},
		{`workload "neighbour-3"`, 1},
		{`workload "neighbour-4"`, 1},
		{`workload "neighbour-5"`, 1},
	}
	if got := logCensus(t, log.String()); !slices.Equal(got, want) {
		t.Fatalf("logged census = %+v, want the %d largest holders %+v:\n%s", got, censusHolders, want, log.String())
	}
	for _, leak := range []string{"neighbour", "holders", "paths"} {
		if strings.Contains(w.Body.String(), leak) {
			t.Fatalf("the refusal body carried the census (%q): %s", leak, w.Body)
		}
	}
}

// A workload at its own quota is told so, below a store that has room. The
// census belongs to the ceiling, so this refusal does not carry one.
func TestQuotaRefusalNamesTheQuota(t *testing.T) {
	hn := newHarness(t)
	hn.setStore(t, NewMemoryStore(16, 1, 64))
	var log bytes.Buffer
	hn.h.Logger = slog.New(slog.NewJSONHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

	if w := do(hn.h, hn.request(t, http.MethodPost, "/api/db")); w.Code != http.StatusCreated {
		t.Fatalf("first POST = %d (%s), want 201", w.Code, w.Body)
	}
	w := do(hn.h, hn.request(t, http.MethodPost, "/api/hf"))
	if w.Code != http.StatusInsufficientStorage {
		t.Fatalf("POST past the quota = %d (%s), want 507", w.Code, w.Body)
	}
	if code := errorCode(t, w); code != types.ErrorCodeSecretHolderQuota {
		t.Fatalf("error code = %q, want %q", code, types.ErrorCodeSecretHolderQuota)
	}
	if got := logCensus(t, log.String()); len(got) != 0 {
		t.Fatalf("a quota refusal logged a census: %+v\n%s", got, log.String())
	}
}

// The two codes are a published wire contract: docs/secrets.md and every
// deployed client switch on these exact strings.
func TestSecretErrorCodeWireValues(t *testing.T) {
	if types.ErrorCodeSecretHolderQuota != "secret_holder_quota" || types.ErrorCodeSecretStoreFull != "secret_store_full" {
		t.Fatalf("error codes = %q, %q; want %q, %q",
			types.ErrorCodeSecretHolderQuota, types.ErrorCodeSecretStoreFull, "secret_holder_quota", "secret_store_full")
	}
}

// An allowlist with no c8s image in it drops nothing, so the injected sidecar
// looks like a container the entry does not declare and release is refused.
// (It also has no workloads, so there is nothing to match either.)
func TestEmptyAllowlistRefuses(t *testing.T) {
	hn := newHarness(t)
	hn.h.Policy = fakePolicy{al: &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}}
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusForbidden {
		t.Fatalf("unconfigured drop set = %d, want 403", w.Code)
	}
}

// Logs leave the TEE (docs/engineering-standards.md §8), so a secret value
// must never reach one — on a served read, a create that mints it, a denial,
// a miss, or a store failure alike.
func TestSecretValueNeverReachesTheLog(t *testing.T) {
	hn := newHarness(t)
	var log bytes.Buffer
	hn.h.Logger = slog.New(slog.NewTextHandler(&log, &slog.HandlerOptions{Level: slog.LevelDebug}))

	value := []byte("sentinel-plaintext-value")
	valueB64 := base64.StdEncoding.EncodeToString(value)
	hn.seed(t, "/api/db", value)

	// The read serves the value in its body by design; every other surface is
	// asserted clean below.
	if w := do(hn.h, hn.request(t, http.MethodGet, "/api/db")); w.Code != http.StatusOK ||
		!strings.Contains(w.Body.String(), valueB64) {
		t.Fatalf("read = %d (%s), want 200 carrying the value", w.Code, w.Body)
	}

	// The create's body carries the minted value by design; parse it out so
	// the log can be checked against those exact bytes.
	created := do(hn.h, hn.request(t, http.MethodPost, "/api/new"))
	if created.Code != http.StatusCreated {
		t.Fatalf("create = %d (%s), want 201", created.Code, created.Body)
	}
	mintedB64 := decodeValue(t, created)
	minted, err := base64.StdEncoding.DecodeString(mintedB64)
	if err != nil {
		t.Fatal(err)
	}

	impostor, err := workloadclaims.NewSandboxTokenSigner(testHost)
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("denied-read")
	denied := do(hn.h, hn.requestWithToken(t, http.MethodGet, "/api/db", hn.leaf,
		mintToken(t, impostor, testSandbox, hn.leaf.PublicKey, nonce), nonce))
	ungranted := do(hn.h, hn.request(t, http.MethodGet, "/other/db"))
	missing := do(hn.h, hn.request(t, http.MethodGet, "/api/never-created"))
	deniedCreate := do(hn.h, hn.request(t, http.MethodPost, "/other/db"))

	hn.h.Store = failingStore{err: fmt.Errorf("backend down")}
	unavailable := do(hn.h, hn.requestWith(t, http.MethodGet, "/api/db", hn.leaf, testSandbox, []byte("store-down")))
	failedCreate := do(hn.h, hn.request(t, http.MethodPost, "/api/db"))

	// minted is binary: a text log would carry it quoted, as base64, or as a
	// byte dump, so raw containment alone is not enough.
	leaks := []string{
		string(value), valueB64,
		string(minted), mintedB64, strconv.Quote(string(minted)), fmt.Sprintf("%v", minted),
	}
	drives := []struct {
		name string
		w    *httptest.ResponseRecorder
		want int
	}{
		{"denied read", denied, http.StatusForbidden},
		{"ungranted path", ungranted, http.StatusNotFound},
		{"absent secret", missing, http.StatusNotFound},
		{"denied create", deniedCreate, http.StatusNotFound},
		{"store failure", unavailable, http.StatusInternalServerError},
		{"failed create", failedCreate, http.StatusInternalServerError},
	}
	for _, d := range drives {
		if d.w.Code != d.want {
			t.Fatalf("%s = %d (%s), want %d", d.name, d.w.Code, d.w.Body, d.want)
		}
		for _, leak := range leaks {
			if strings.Contains(d.w.Body.String(), leak) {
				t.Fatalf("%s body carried the secret: %s", d.name, d.w.Body)
			}
		}
	}

	out := log.String()
	if !strings.Contains(out, "secret request denied") {
		t.Fatalf("the denial never reached the captured log; capture is broken:\n%s", out)
	}
	for _, leak := range leaks {
		if strings.Contains(out, leak) {
			t.Fatalf("the secret reached the log as %q:\n%s", leak, out)
		}
	}
}

func TestSecretReleaseEnforcesEnvEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     []string
		unknown bool
		want    int
	}{
		{"matches", []string{"MODE=production"}, false, http.StatusCreated},
		{"wrong", []string{"MODE=unsafe"}, false, http.StatusForbidden},
		{"old inventory", nil, true, http.StatusForbidden},
		{"empty", nil, false, http.StatusForbidden},
		{"duplicate", []string{"MODE=unsafe", "MODE=production"}, false, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			al := hn.h.Policy.(fakePolicy).al
			al.Workloads["api"].Containers[0].Env = pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyExact, Values: map[string]string{"MODE": "production"}}
			if !tc.unknown {
				hn.inv.containers[0].Env, _ = pkgallowlist.ObserveEnv(tc.env)
			}
			w := do(hn.h, hn.request(t, http.MethodPost, "/api/db"))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}

func TestSecretReleaseEnforcesMixedEnvironmentMatchers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    []string
		legacy bool
		want   int
	}{
		{"matches", []string{"MODE=production", "GPU_SERIAL=one"}, false, http.StatusCreated},
		{"changed present", []string{"MODE=production", "GPU_SERIAL=two"}, false, http.StatusCreated},
		{"empty present", []string{"MODE=production", "GPU_SERIAL="}, false, http.StatusCreated},
		{"changed exact", []string{"MODE=unsafe", "GPU_SERIAL=one"}, false, http.StatusForbidden},
		{"missing", []string{"MODE=production"}, false, http.StatusForbidden},
		{"extra", []string{"MODE=production", "GPU_SERIAL=one", "LD_PRELOAD=unsafe"}, false, http.StatusForbidden},
		{"old evidence", []string{"MODE=production", "GPU_SERIAL=one"}, true, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			al := hn.h.Policy.(fakePolicy).al
			var policy pkgallowlist.EnvPolicy
			if err := json.Unmarshal([]byte(`{"policy":"match","variables":{"MODE":{"exact":"production"},"GPU_SERIAL":{"present":true}}}`), &policy); err != nil {
				t.Fatal(err)
			}
			al.Workloads["api"].Containers[0].Env = policy
			observation, err := pkgallowlist.ObserveEnv(tc.env)
			if err != nil {
				t.Fatal(err)
			}
			if tc.legacy {
				observation.VariableDigests = nil
			}
			hn.inv.containers[0].Env = observation
			w := do(hn.h, hn.request(t, http.MethodPost, "/api/db"))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body, tc.want)
			}
		})
	}
}

func TestSecretReleaseEnforcesMountEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mounts []pkgallowlist.ObservedMount
		want   int
	}{
		{"listed", []pkgallowlist.ObservedMount{{Destination: "/mnt/c8s-data/config", Class: pkgallowlist.MountData, Storage: pkgallowlist.MountMemory}}, http.StatusCreated},
		{"foreign", []pkgallowlist.ObservedMount{{Destination: "/etc/ld.so.preload", Class: pkgallowlist.MountData, Storage: pkgallowlist.MountMemory}}, http.StatusForbidden},
		{"old inventory", nil, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hn := newHarness(t)
			al := hn.h.Policy.(fakePolicy).al
			al.Workloads["api"].Containers[0].Mounts = pkgallowlist.MountPolicy{Policy: pkgallowlist.PolicyExact, Rules: []pkgallowlist.MountRule{{Destination: "/mnt/c8s-data/config", Kind: pkgallowlist.MountData}}}
			hn.inv.containers[0].Mounts = tc.mounts
			hn.inv.legacyMounts = tc.mounts == nil
			w := do(hn.h, hn.request(t, http.MethodPost, "/api/db"))
			if w.Code != tc.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}
