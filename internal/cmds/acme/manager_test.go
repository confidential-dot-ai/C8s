package acme

import (
	"bytes"
	"context"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

var testDomains = []string{"lb.example.com", "infer.lb.example.com"}

// newTestManager wires a manager to a fake directory whose http-01
// validation hits the manager's own challenge handler.
func newTestManager(t *testing.T, ca *testCA, domains []string) *manager {
	t.Helper()
	mgr := newManager("", "ops@example.com", t.TempDir(), domains, slog.Default())
	challengeSrv := httptest.NewServer(mgr.handler())
	t.Cleanup(challengeSrv.Close)
	// The front-door probe hits the challenge listener directly.
	mgr.httpPort = serverPort(t, challengeSrv.URL)
	mgr.probe = testPublicProbeClient(t, challengeSrv.URL)
	mgr.directoryURL = newFakeACME(t, ca, challengeSrv.URL).directoryURL()
	return mgr
}

// serverPort extracts the TCP port of an httptest server URL.
func serverPort(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestIssueHTTP01MultiSAN(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.ensure(ctx)

	if mgr.needsIssue() {
		t.Fatal("no serviceable certificate after issuance")
	}
	leaf, err := mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	// One multi-SAN certificate covering exactly --domains.
	got := slices.Clone(leaf.DNSNames)
	want := slices.Clone(testDomains)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("leaf SANs = %v, want %v", leaf.DNSNames, testDomains)
	}
	// Chain includes the CA; the key is group-readable on disk.
	chain, err := os.ReadFile(mgr.certPath())
	if err != nil {
		t.Fatal(err)
	}
	var blocks int
	for rest := chain; ; blocks++ {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
	}
	if blocks != 2 {
		t.Fatalf("chain blocks = %d, want leaf + CA", blocks)
	}
	info, err := os.Stat(mgr.keyPath())
	if err != nil {
		t.Fatal(err)
	}
	// Group-readable: nginx serves this key as another identity, and the
	// pod's fsGroup owns the directory.
	if info.Mode().Perm() != keyMode {
		t.Fatalf("key mode = %v, want %v", info.Mode().Perm(), os.FileMode(keyMode))
	}
	// The challenge tokens are gone after issuance (no dangling responders).
	if len(mgr.tokens) != 0 {
		t.Fatalf("dangling challenge tokens: %v", mgr.tokens)
	}
}

func TestNeedsIssueAtTwoThirdsLifetime(t *testing.T) {
	ca := newTestCA(t)
	mgr := newManager("", "", t.TempDir(), testDomains, slog.Default())

	// A cert 3/4 through its lifetime must renew; install one backdated.
	key, chain := backdatedCert(t, ca, testDomains, -9*time.Hour, 3*time.Hour)
	writeCertPair(t, mgr, key, chain)
	if !mgr.needsIssue() {
		t.Fatal("cert past 2/3 lifetime not renewed")
	}
}

// A certificate covering a different SAN set than --domains is re-issued,
// in both directions.
func TestNeedsIssueOnDomainSetChange(t *testing.T) {
	ca := newTestCA(t)
	for _, tc := range []struct {
		name       string
		certNames  []string
		configured []string
	}{
		{"missing domain", []string{"lb.example.com"}, testDomains},
		{"stale extra domain", testDomains, []string{"lb.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mgr := newManager("", "", t.TempDir(), tc.configured, slog.Default())
			key, chain := backdatedCert(t, ca, tc.certNames, -time.Hour, 24*time.Hour)
			writeCertPair(t, mgr, key, chain)
			if !mgr.needsIssue() {
				t.Fatal("SAN-set mismatch not re-issued")
			}
		})
	}
}

// bootstrap gives nginx startable cert files before the first issuance; the
// placeholder always reads as needing issuance and is not overwritten once a
// real certificate is installed.
func TestBootstrapWritesSelfSignedPlaceholder(t *testing.T) {
	ca := newTestCA(t)
	mgr := newManager("", "", t.TempDir(), testDomains, slog.Default())
	if err := mgr.bootstrap(); err != nil {
		t.Fatal(err)
	}
	leaf, err := mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	got := slices.Clone(leaf.DNSNames)
	slices.Sort(got)
	want := slices.Clone(testDomains)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("bootstrap SANs = %v, want %v", leaf.DNSNames, testDomains)
	}
	info, err := os.Stat(mgr.keyPath())
	if err != nil {
		t.Fatal(err)
	}
	// Group-readable: nginx serves this key as another identity, and the
	// pod's fsGroup owns the directory.
	if info.Mode().Perm() != keyMode {
		t.Fatalf("key mode = %v, want %v", info.Mode().Perm(), os.FileMode(keyMode))
	}
	if !mgr.needsIssue() {
		t.Fatal("self-signed bootstrap reported serviceable")
	}

	// A CA-issued certificate is left alone.
	key, chain := backdatedCert(t, ca, testDomains, -time.Hour, 24*time.Hour)
	writeCertPair(t, mgr, key, chain)
	if err := mgr.bootstrap(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(mgr.certPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, chain) {
		t.Fatal("bootstrap overwrote an installed certificate")
	}
}

func TestRunLoopIssuesAndStops(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)
	mgr.recheck = 10 * time.Millisecond
	mgr.retry = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { mgr.run(ctx); close(done) }()

	// Poll the published files alone: the manager's own fields belong to run
	// while it is running.
	deadline := time.Now().Add(30 * time.Second)
	for issued := false; !issued; {
		leaf, err := mgr.diskLeaf()
		issued = err == nil && !bytes.Equal(leaf.RawIssuer, leaf.RawSubject)
		if !issued && time.Now().After(deadline) {
			t.Fatal("run never issued the certificate")
		}
		if !issued {
			time.Sleep(10 * time.Millisecond)
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop on ctx done")
	}
}

func TestHandlerRejectsUnknownPaths(t *testing.T) {
	mgr := newManager("", "", t.TempDir(), testDomains, slog.Default())
	mgr.tokens["known"] = "known.auth"
	h := mgr.handler()
	for path, want := range map[string]int{
		"/other":                    http.StatusNotFound,
		challengePrefix:             http.StatusNotFound,
		challengePrefix + "unknown": http.StatusNotFound,
		challengePrefix + "known":   http.StatusOK,
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != want {
			t.Errorf("GET %s = %d, want %d", path, rec.Code, want)
		}
	}
}

func TestAccountKey(t *testing.T) {
	mgr := newManager("", "", t.TempDir(), testDomains, slog.Default())
	key, err := mgr.accountKey()
	if err != nil {
		t.Fatal(err)
	}
	// A second call reuses the persisted key.
	again, err := mgr.accountKey()
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(again) {
		t.Fatal("account key regenerated instead of reused")
	}

	// A corrupted key fails closed, through acmeClient too.
	path := filepath.Join(mgr.dir, accountKeyFile)
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.accountKey(); err == nil {
		t.Fatal("corrupted account key accepted")
	}
	if _, err := mgr.acmeClient(context.Background()); err == nil {
		t.Fatal("acmeClient built on a corrupted account key")
	}

	// An unreadable key path (a directory) is an error, not a regeneration.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.accountKey(); err == nil {
		t.Fatal("unreadable account key path accepted")
	}
}

func TestAccountKeyStoreErrors(t *testing.T) {
	// Key store dir not creatable.
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	mgr := newManager("", "", filepath.Join(ro, "acme"), testDomains, slog.Default())
	if _, err := mgr.accountKey(); err == nil {
		t.Fatal("account key created under an un-creatable dir")
	}

	// Key store dir not writable.
	mgr.dir = ro
	if _, err := mgr.accountKey(); err == nil {
		t.Fatal("account key written into a read-only dir")
	}
}

func TestClientRegistrationFailure(t *testing.T) {
	mgr := newManager("http://127.0.0.1:1/dir", "ops@example.com", t.TempDir(), testDomains, slog.Default())
	if _, err := mgr.acmeClient(context.Background()); err == nil {
		t.Fatal("acmeClient succeeded against an unreachable directory")
	}
}

// A fresh certificate is left alone: the second ensure must not re-issue, so
// the leaf on disk keeps the serial the first one installed.
func TestEnsureSkipsFreshCert(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.ensure(ctx)
	first, err := mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	mgr.ensure(ctx)
	second, err := mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) != 0 {
		t.Fatalf("certificate re-issued: serial %v then %v", first.SerialNumber, second.SerialNumber)
	}
}

func TestEnsureLogsIssuanceFailure(t *testing.T) {
	mgr := newManager("http://127.0.0.1:1/dir", "", t.TempDir(), testDomains, slog.Default())
	mgr.ensure(context.Background())
	if !mgr.needsIssue() {
		t.Fatal("certificate exists after failed issuance")
	}
}

func TestNeedsIssueRequiresKeyBesideCert(t *testing.T) {
	ca := newTestCA(t)
	mgr := newManager("", "", t.TempDir(), testDomains, slog.Default())
	_, chain := backdatedCert(t, ca, testDomains, -time.Hour, 24*time.Hour)
	if err := os.WriteFile(mgr.certPath(), chain, 0o644); err != nil {
		t.Fatal(err)
	}
	if !mgr.needsIssue() {
		t.Fatal("certificate without its key reported serviceable")
	}
}

// Directory-side failures at each RFC 8555 step fail the issuance closed:
// no cert lands.
func TestEnsureFailsClosedOnDirectoryErrors(t *testing.T) {
	for _, tc := range []struct {
		name     string
		sabotage func(*fakeACME)
	}{
		{"no http-01 challenge offered", func(f *fakeACME) { f.noHTTP01 = true }},
		{"new order refused", func(f *fakeACME) { f.failNewOrder = true }},
		{"finalize refused", func(f *fakeACME) { f.failFinalize = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ca := newTestCA(t)
			mgr := newManager("", "", t.TempDir(), testDomains, slog.Default())
			challengeSrv := httptest.NewServer(mgr.handler())
			t.Cleanup(challengeSrv.Close)
			f := newFakeACME(t, ca, challengeSrv.URL)
			tc.sabotage(f)
			mgr.directoryURL = f.directoryURL()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			mgr.ensure(ctx)
			if !mgr.needsIssue() {
				t.Fatal("certificate exists after a failed issuance step")
			}
		})
	}
}

// A failed issuance paces the run loop at the retry interval, not the
// recheck interval.
func TestRunLoopRetriesAfterFailure(t *testing.T) {
	attempts := make(chan struct{}, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts <- struct{}{}
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	mgr := newManager(srv.URL+"/dir", "", t.TempDir(), testDomains, slog.Default())
	mgr.recheck = time.Hour
	mgr.retry = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { mgr.run(ctx); close(done) }()
	for range 2 {
		select {
		case <-attempts:
		case <-time.After(30 * time.Second):
			t.Fatal("run loop did not retry a failed issuance")
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("run did not stop on ctx done")
	}
}

// A CA that cannot validate the challenge (the challenge listener is
// unreachable) fails Accept, not the whole process.
func TestEnsureFailsWhenChallengeUnreachable(t *testing.T) {
	ca := newTestCA(t)
	mgr := newManager("", "", t.TempDir(), testDomains, slog.Default())
	// No challenge listener: the fake CA's validation fetch fails.
	f := newFakeACME(t, ca, "http://127.0.0.1:1")
	mgr.directoryURL = f.directoryURL()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.ensure(ctx)
	if !mgr.needsIssue() {
		t.Fatal("certificate exists without a validated challenge")
	}
}

// A cert-dir that turns read-only fails the key install closed.
func TestIssueFailsOnReadOnlyCertDir(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)
	if _, err := mgr.accountKey(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(mgr.dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(mgr.dir, 0o700) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.ensure(ctx)
	if !mgr.needsIssue() {
		t.Fatal("certificate installed into a read-only dir")
	}
}

func TestBootstrapFailsOnUncreatableDir(t *testing.T) {
	ro := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	mgr := newManager("", "", filepath.Join(ro, "tls"), testDomains, slog.Default())
	if err := mgr.bootstrap(); err == nil {
		t.Fatal("bootstrap wrote under an un-creatable dir")
	}
}

func TestFulfillAuthorizationSkipsValidAuthz(t *testing.T) {
	ca := newTestCA(t)
	mgr := newManager("", "", t.TempDir(), []string{"lb.example.com"}, slog.Default())
	challengeSrv := httptest.NewServer(mgr.handler())
	t.Cleanup(challengeSrv.Close)
	f := newFakeACME(t, ca, challengeSrv.URL)
	mgr.directoryURL = f.directoryURL()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	mgr.ensure(ctx)
	if mgr.needsIssue() {
		t.Fatal("issuance failed")
	}
	client, err := mgr.acmeClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The order's authorization is valid now: fulfilling it again is a no-op.
	if err := mgr.fulfillAuthorization(ctx, client, f.srv.URL+"/authz/1-0"); err != nil {
		t.Fatalf("fulfillAuthorization on a valid authz: %v", err)
	}
}

// writeCertPair installs a key + chain under the manager's cert-dir.
func writeCertPair(t *testing.T, mgr *manager, keyPEM, chainPEM []byte) {
	t.Helper()
	if err := os.WriteFile(mgr.keyPath(), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mgr.certPath(), chainPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestIssueWaitsForFrontDoor pins the first-issuance ordering: no order may
// reach the CA while nginx's :80 server is still starting, or the CA burns a
// failed validation per SAN on every fresh pod.
func TestIssueWaitsForFrontDoor(t *testing.T) {
	ca := newTestCA(t)
	mgr := newManager("", "ops@example.com", t.TempDir(), testDomains, slog.Default())

	// Stub nginx: refuses the challenge path until "up" flips, like a
	// container still waiting on its startup gate.
	var up atomic.Bool
	handler := mgr.handler()
	frontDoor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(frontDoor.Close)
	mgr.httpPort = serverPort(t, frontDoor.URL)

	fake := newFakeACME(t, ca, frontDoor.URL)
	fake.onNewOrder = func() {
		if !up.Load() {
			t.Error("order reached the CA before the front door answered")
		}
	}
	mgr.directoryURL = fake.directoryURL()

	go func() {
		time.Sleep(300 * time.Millisecond)
		up.Store(true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mgr.issue(ctx); err != nil {
		t.Fatalf("issue: %v", err)
	}
}

type probeRewriteTransport struct{ base *url.URL }

func (t probeRewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	u := *r.URL
	u.Scheme = t.base.Scheme
	u.Host = t.base.Host
	copy.URL = &u
	copy.Host = r.URL.Host
	return http.DefaultTransport.RoundTrip(copy)
}
func testPublicProbeClient(t *testing.T, base string) *http.Client {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: time.Second, Transport: probeRewriteTransport{u}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// Candidate can obtain and renew TLS while production still reaches another cluster.
// When production later reaches this router, the certificate gains that name.
func TestIndependentHostnameIssuanceAndExpansion(t *testing.T) {
	ca := newTestCA(t)
	mgr := newTestManager(t, ca, testDomains)
	var productionReady atomic.Bool
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == testDomains[0] && !productionReady.Load() {
			http.NotFound(w, r)
			return
		}
		mgr.handler().ServeHTTP(w, r)
	}))
	defer front.Close()
	mgr.probe = testPublicProbeClient(t, front.URL)
	ctx := context.Background()
	mgr.ensure(ctx)
	leaf, err := mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(leaf.DNSNames, testDomains[1:]) {
		t.Fatalf("candidate SANs = %v", leaf.DNSNames)
	}
	before, _ := os.ReadFile(mgr.certPath())
	mgr.ensure(ctx)
	after, _ := os.ReadFile(mgr.certPath())
	if !bytes.Equal(before, after) {
		t.Fatal("issued again without a change")
	}
	// A due candidate certificate renews without production validation.
	key, chain := backdatedCert(t, ca, testDomains[1:], -9*time.Hour, 3*time.Hour)
	writeCertPair(t, mgr, key, chain)
	mgr.ensure(ctx)
	renewed, _ := os.ReadFile(mgr.certPath())
	if bytes.Equal(renewed, chain) {
		t.Fatal("candidate certificate did not renew")
	}
	productionReady.Store(true)
	mgr.ensure(ctx)
	leaf, err = mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	if !sameDomainSet(leaf.DNSNames, testDomains) {
		t.Fatalf("expanded SANs = %v", leaf.DNSNames)
	}
	// A due certificate keeps a name the probe misses until 5/6 of its lifetime.
	productionReady.Store(false)
	key, chain = backdatedCert(t, ca, testDomains, -9*time.Hour, 3*time.Hour)
	writeCertPair(t, mgr, key, chain)
	mgr.ensure(ctx)
	kept, _ := os.ReadFile(mgr.certPath())
	if !bytes.Equal(kept, chain) {
		t.Fatal("renewal dropped a name the certificate still covers")
	}
	key, chain = backdatedCert(t, ca, testDomains, -11*time.Hour, time.Hour)
	writeCertPair(t, mgr, key, chain)
	mgr.ensure(ctx)
	leaf, err = mgr.diskLeaf()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(leaf.DNSNames, testDomains[1:]) {
		t.Fatalf("shrunk SANs = %v", leaf.DNSNames)
	}
	if len(mgr.tokens) != 0 {
		t.Fatal("probe tokens remain")
	}
}

func TestPublicProbeRejectsOtherResponses(t *testing.T) {
	for _, mode := range []string{"not found", "wrong body", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			ca := newTestCA(t)
			mgr := newTestManager(t, ca, testDomains)
			key, chain := backdatedCert(t, ca, testDomains[1:], -time.Hour, 24*time.Hour)
			writeCertPair(t, mgr, key, chain)
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "not found":
					http.NotFound(w, r)
				case "wrong body":
					w.Write([]byte("not this router"))
				case "redirect":
					http.Redirect(w, r, "/elsewhere", http.StatusFound)
				}
			}))
			defer front.Close()
			mgr.probe = testPublicProbeClient(t, front.URL)
			mgr.directoryURL = "http://127.0.0.1:1/must-not-contact"
			mgr.ensure(context.Background())
			after, err := os.ReadFile(mgr.certPath())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, chain) {
				t.Fatal("unreachable names changed the certificate")
			}
			if len(mgr.tokens) != 0 {
				t.Fatal("probe tokens remain")
			}
		})
	}
}
