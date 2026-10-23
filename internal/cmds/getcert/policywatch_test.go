package getcert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// fakeAllowlist is a CDS /allowlist with HandleList's weak-ETag and 304
// semantics.
type fakeAllowlist struct {
	mu       sync.Mutex
	version  int
	body     string
	requests atomic.Int64
	// notModified counts the 304s served.
	notModified atomic.Int64
}

func (f *fakeAllowlist) set(version int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.version, f.body = version, body
}

func (f *fakeAllowlist) snapshot() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strconv.Itoa(f.version), f.body
}

func (f *fakeAllowlist) serve(t *testing.T) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/allowlist", f.handle)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func (f *fakeAllowlist) handle(w http.ResponseWriter, r *http.Request) {
	f.requests.Add(1)
	version, body := f.snapshot()
	etag := `W/"` + version + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		f.notModified.Add(1)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

// stampedLeaf is a leaf CDS issued under the given policy snapshot.
func stampedLeaf(t *testing.T, version, body string) *x509.Certificate {
	t.Helper()
	digest := sha256.Sum256([]byte(body))
	ext, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{
		Name:             "router",
		AllowlistVersion: version,
		AllowlistDigest:  digest[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{NotAfter: time.Now().Add(time.Hour), Extensions: []pkix.Extension{ext}}
}

// issueStamped mints the generation CDS returns under one policy snapshot.
func issueStamped(ca *testCA, creds *credentials, version, body string, ttl time.Duration) (*generation, error) {
	digest := sha256.Sum256([]byte(body))
	ext, err := armtls.MarshalMatchedWorkloadExtension(&armtls.MatchedWorkload{
		Name:             "router",
		AllowlistVersion: version,
		AllowlistDigest:  digest[:],
	})
	if err != nil {
		return nil, err
	}
	key, keyPEM, err := generateKey()
	if err != nil {
		return nil, err
	}
	chain, err := ca.issue(&key.PublicKey, creds.instanceID, ttl, ext)
	if err != nil {
		return nil, err
	}
	return issuedGeneration(chain, key, keyPEM)
}

// policyCredentials publishes a generation whose leaf carries the stamp CDS
// issued under the given policy snapshot.
func policyCredentials(t *testing.T, ca *testCA, version, body string) *credentials {
	t.Helper()
	creds := &credentials{
		volume:     testVolume(t),
		instanceID: testInstanceID,
	}
	g, err := issueStamped(ca, creds, version, body, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := creds.publish(g, time.Now()); err != nil {
		t.Fatal(err)
	}
	return creds
}

// stubIssueUnderCurrentPolicy makes every renewal publish a leaf stamped with
// the policy the fake CDS serves at that moment.
func stubIssueUnderCurrentPolicy(t *testing.T, ca *testCA, cds *fakeAllowlist) func() []time.Time {
	t.Helper()
	return stubObtainCertMinting(t, func(creds *credentials, _ int) (*generation, error) {
		version, body := cds.snapshot()
		return issueStamped(ca, creds, version, body, time.Hour)
	})
}

func policyWatchConfig(t *testing.T) config {
	cfg := unreachableRenewalConfig(t)
	cfg.UnnamedRenewInterval = 0
	cfg.CAWatchInterval = 10 * time.Millisecond
	return cfg
}

func startRenewLoop(t *testing.T, cfg config, url string, creds *credentials) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(url), plaintextPolicyClient(url), creds) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("renewLoop returned %v, want nil on shutdown", err)
			}
		case <-time.After(15 * time.Second):
			t.Error("renewLoop did not shut down when the context was cancelled")
		}
	})
}

const (
	policyWorkload     = `{"containers":[{"digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","command":{"policy":"any"},"args":{"policy":"any"}}]}`
	policyTwoWorkloads = `{"schema":"c8s.allowlist/v1","workloads":{"router":` + policyWorkload + `,"worker":` + policyWorkload + `}}`
	// policyRouterOnly is policyTwoWorkloads with worker removed.
	policyRouterOnly = `{"schema":"c8s.allowlist/v1","workloads":{"router":` + policyWorkload + `}}`
	policyWithBatch  = `{"schema":"c8s.allowlist/v1","workloads":{"batch":` + policyWorkload + `,"router":` + policyWorkload + `}}`
)

// waitForRequests polls until the fake has served at least n /allowlist
// requests.
func (f *fakeAllowlist) waitForRequests(t *testing.T, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.requests.Load() < n {
		if time.Now().After(deadline) {
			t.Fatalf("got %d /allowlist requests, want at least %d", f.requests.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitForTicks waits until the watch has polled n more times, so a renewal
// those ticks would have caused had time to happen.
func (f *fakeAllowlist) waitForTicks(t *testing.T, n int64) {
	t.Helper()
	f.waitForRequests(t, f.requests.Load()+n)
}

// Each allowlist write re-issues the leaf exactly once; --renew-interval is an
// hour, so any renewal inside the test can only come from the policy watch.
func TestRenewLoopRenewsWhenAllowlistPolicyChanges(t *testing.T) {
	cds := &fakeAllowlist{}
	cds.set(4, policyTwoWorkloads)
	url := cds.serve(t)
	ca := newTestCA(t)
	attempts := stubIssueUnderCurrentPolicy(t, ca, cds)

	startRenewLoop(t, policyWatchConfig(t), url, policyCredentials(t, ca, "4", policyTwoWorkloads))

	cds.waitForRequests(t, 3)
	if got := len(attempts()); got != 0 {
		t.Fatalf("%d renewals while the policy matched, want 0", got)
	}

	cds.set(5, policyRouterOnly)
	waitForAttempts(t, attempts, 1)
	cds.waitForTicks(t, 3)
	if got := len(attempts()); got != 1 {
		t.Fatalf("%d renewals after one allowlist write, want 1", got)
	}

	cds.set(6, policyWithBatch)
	waitForAttempts(t, attempts, 2)
	cds.waitForTicks(t, 3)
	if got := len(attempts()); got != 2 {
		t.Fatalf("%d renewals after two allowlist writes, want 2", got)
	}
}

// One watch tick runs both checks: a matching mesh CA does not stop the policy
// check, and a policy change alone still renews.
func TestRenewLoopWatchesCAAndPolicyOnOneTick(t *testing.T) {
	ca := testCertificatePEM(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte(ca), 0644); err != nil {
		t.Fatal(err)
	}
	cds := &fakeAllowlist{}
	cds.set(4, policyTwoWorkloads)
	var caRequests atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/allowlist", cds.handle)
	mux.HandleFunc("/ca", func(w http.ResponseWriter, _ *http.Request) {
		caRequests.Add(1)
		_, _ = io.WriteString(w, ca)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	signer := newTestCA(t)
	attempts := stubIssueUnderCurrentPolicy(t, signer, cds)

	cfg := policyWatchConfig(t)
	cfg.CAPath = caPath
	startRenewLoop(t, cfg, srv.URL, policyCredentials(t, signer, "4", policyTwoWorkloads))

	cds.waitForRequests(t, 3)
	if got := len(attempts()); got != 0 {
		t.Fatalf("%d renewals while the CA and policy matched, want 0", got)
	}
	if got := caRequests.Load(); got < 3 {
		t.Fatalf("%d /ca requests over three watch ticks, want at least 3", got)
	}

	cds.set(5, policyRouterOnly)
	waitForAttempts(t, attempts, 1)
}

// A write that bumps the version but keeps the bytes renews nothing, and the
// watch asks for the new version from then on instead of re-fetching the body.
func TestRenewLoopFollowsServedVersionWithStampedBytes(t *testing.T) {
	cds := &fakeAllowlist{}
	cds.set(4, policyTwoWorkloads)
	url := cds.serve(t)
	ca := newTestCA(t)
	attempts := stubIssueUnderCurrentPolicy(t, ca, cds)

	startRenewLoop(t, policyWatchConfig(t), url, policyCredentials(t, ca, "4", policyTwoWorkloads))
	cds.waitForRequests(t, 1)

	cds.set(5, policyTwoWorkloads)
	cds.waitForTicks(t, 1)
	before := cds.notModified.Load()
	cds.waitForTicks(t, 2)
	if got := len(attempts()); got != 0 {
		t.Fatalf("%d renewals after a write with unchanged bytes, want 0", got)
	}
	if got := cds.notModified.Load() - before; got < 1 {
		t.Fatalf("%d 304s in the two polls after the first 200 at the new version, want at least 1", got)
	}
}

// stubIssueCountingPolls is stubIssueUnderCurrentPolicy that also records how
// many /allowlist requests the fake had served when each renewal started.
// fail reports whether renewal n fails.
func stubIssueCountingPolls(t *testing.T, ca *testCA, cds *fakeAllowlist, fail func(n int) bool) (func() []time.Time, func() []int64) {
	t.Helper()
	var mu sync.Mutex
	var polls []int64
	attempts := stubObtainCertMinting(t, func(creds *credentials, n int) (*generation, error) {
		mu.Lock()
		polls = append(polls, cds.requests.Load())
		mu.Unlock()
		if fail(n) {
			return nil, errors.New("stubbed renewal failure")
		}
		version, body := cds.snapshot()
		return issueStamped(ca, creds, version, body, time.Hour)
	})
	return attempts, func() []int64 {
		mu.Lock()
		defer mu.Unlock()
		return append([]int64(nil), polls...)
	}
}

// Watch ticks while a policy renewal is pending neither fetch /allowlist nor
// re-arm the timer, which would push the renewal out forever at a 10ms tick.
func TestRenewLoopDebouncesPolicyRenewal(t *testing.T) {
	const pending = 300 * time.Millisecond
	old := policyRenewDelayFn
	policyRenewDelayFn = func(time.Duration, time.Duration) time.Duration { return pending }
	t.Cleanup(func() { policyRenewDelayFn = old })

	cds := &fakeAllowlist{}
	cds.set(5, policyRouterOnly)
	url := cds.serve(t)
	ca := newTestCA(t)
	attempts, polls := stubIssueCountingPolls(t, ca, cds, func(int) bool { return false })

	start := time.Now()
	startRenewLoop(t, policyWatchConfig(t), url, policyCredentials(t, ca, "4", policyTwoWorkloads))

	at := waitForAttempts(t, attempts, 1)
	if gap := at[0].Sub(start); gap < pending || gap > pending+time.Second {
		t.Fatalf("renewed %v after the change, want in [%v, %v]", gap, pending, pending+time.Second)
	}
	if got := polls()[0]; got != 1 {
		t.Fatalf("%d /allowlist polls before the pending renewal fired, want 1 (the detection)", got)
	}
	cds.waitForTicks(t, 3)
	if got := len(attempts()); got != 1 {
		t.Fatalf("%d renewals for one change, want 1", got)
	}
}

// A failed policy renewal is retried on the renewalRetryBase backoff; the watch
// stays quiet meanwhile instead of re-arming the timer over the retry.
func TestRenewLoopPolicyWatchHoldsOffDuringRetry(t *testing.T) {
	oldBase := renewalRetryBase
	renewalRetryBase = 200 * time.Millisecond
	t.Cleanup(func() { renewalRetryBase = oldBase })

	cds := &fakeAllowlist{}
	cds.set(5, policyRouterOnly)
	url := cds.serve(t)
	ca := newTestCA(t)
	attempts, polls := stubIssueCountingPolls(t, ca, cds, func(n int) bool { return n == 1 })

	startRenewLoop(t, policyWatchConfig(t), url, policyCredentials(t, ca, "4", policyTwoWorkloads))

	at := waitForAttempts(t, attempts, 2)
	if gap := at[1].Sub(at[0]); gap < renewalRetryBase || gap > renewalRetryBase+time.Second {
		t.Fatalf("retry came %v after the failed renewal, want in [%v, %v]", gap, renewalRetryBase, renewalRetryBase+time.Second)
	}
	if got := polls(); got[1] != got[0] {
		t.Fatalf("/allowlist polled %d times while the retry was pending, want 0", got[1]-got[0])
	}
	cds.waitForTicks(t, 3)
	if got := len(attempts()); got != 2 {
		t.Fatalf("%d renewals for one change and one failure, want 2", got)
	}
}

// The scheduled renewal lands after several watch ticks; none of them polls.
func TestRenewLoopPolicyWatchIgnoresUnnamedLeaf(t *testing.T) {
	cds := &fakeAllowlist{}
	cds.set(5, policyRouterOnly)
	url := cds.serve(t)
	ca := newTestCA(t)
	attempts := stubObtainCert(t, ca, func(int) (time.Duration, error) { return time.Hour, nil })

	cfg := policyWatchConfig(t)
	cfg.RenewInterval = 100 * time.Millisecond
	startRenewLoop(t, cfg, url, publishedCredentials(t, ca, time.Hour))

	waitForAttempts(t, attempts, 1)
	if got := cds.requests.Load(); got != 0 {
		t.Fatalf("%d /allowlist polls for an unnamed leaf, want 0", got)
	}
}

// A leaf naming another entry than --expected-workload still renews on a
// policy change: with the fast poll off, nothing else would re-issue it before
// --renew-interval.
func TestRenewLoopPolicyWatchRenewsUnexpectedWorkload(t *testing.T) {
	cds := &fakeAllowlist{}
	cds.set(4, policyTwoWorkloads)
	url := cds.serve(t)
	ca := newTestCA(t)
	attempts := stubIssueUnderCurrentPolicy(t, ca, cds)

	cfg := policyWatchConfig(t)
	cfg.ExpectedWorkload = "worker"
	startRenewLoop(t, cfg, url, policyCredentials(t, ca, "4", policyTwoWorkloads))

	cds.waitForTicks(t, 2)
	if got := len(attempts()); got != 0 {
		t.Fatalf("%d renewals before the allowlist changed, want 0", got)
	}
	cds.set(5, policyRouterOnly)
	waitForAttempts(t, attempts, 1)
}

func TestStampedPolicyStale(t *testing.T) {
	tests := []struct {
		name        string
		stamp       *x509.Certificate
		served      int
		body        string
		wantVersion string
		want        bool
	}{
		{name: "304 on version match skips the digest", stamp: stampedLeaf(t, "4", policyTwoWorkloads), served: 4, body: policyRouterOnly, wantVersion: "4", want: false},
		{name: "new version", stamp: stampedLeaf(t, "4", policyTwoWorkloads), served: 5, body: policyRouterOnly, wantVersion: "5", want: true},
		{name: "new version, same bytes", stamp: stampedLeaf(t, "4", policyTwoWorkloads), served: 5, body: policyTwoWorkloads, wantVersion: "5", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cds := &fakeAllowlist{}
			cds.set(tt.served, tt.body)
			stamp, err := armtls.MatchedWorkloadFromCert(tt.stamp)
			if err != nil {
				t.Fatal(err)
			}
			served, stale, err := stampedPolicyStale(context.Background(), plaintextPolicyClient(cds.serve(t)), stamp.AllowlistVersion, stamp.AllowlistDigest)
			if err != nil {
				t.Fatalf("stampedPolicyStale: %v", err)
			}
			if served != tt.wantVersion || stale != tt.want {
				t.Fatalf("stampedPolicyStale = %q, %v, want %q, %v", served, stale, tt.wantVersion, tt.want)
			}
		})
	}

	t.Run("304 on a matched newer version", func(t *testing.T) {
		cds := &fakeAllowlist{}
		cds.set(5, policyTwoWorkloads)
		stamp, err := armtls.MatchedWorkloadFromCert(stampedLeaf(t, "4", policyTwoWorkloads))
		if err != nil {
			t.Fatal(err)
		}
		served, stale, err := stampedPolicyStale(context.Background(), plaintextPolicyClient(cds.serve(t)), "5", stamp.AllowlistDigest)
		if err != nil {
			t.Fatalf("stampedPolicyStale: %v", err)
		}
		if served != "5" || stale {
			t.Fatalf("stampedPolicyStale = %q, %v, want \"5\", false", served, stale)
		}
		if got := cds.notModified.Load(); got != 1 {
			t.Fatalf("304s served = %d, want 1", got)
		}
	})

	t.Run("same version, different digest", func(t *testing.T) {
		// A 200 can carry the stamped version when CDS's version read fails
		// and it falls back to the full load; only the digest tells then.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `W/"4"`)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(policyRouterOnly))
		}))
		t.Cleanup(srv.Close)
		stamp, err := armtls.MatchedWorkloadFromCert(stampedLeaf(t, "4", policyTwoWorkloads))
		if err != nil {
			t.Fatal(err)
		}
		if _, stale, err := stampedPolicyStale(context.Background(), plaintextPolicyClient(srv.URL), stamp.AllowlistVersion, stamp.AllowlistDigest); err != nil || !stale {
			t.Fatalf("stampedPolicyStale = %v, %v, want stale", stale, err)
		}
	})

	t.Run("stamped with the seed layer", func(t *testing.T) {
		// The seed layer is fixed for CDS's lifetime, so a leaf it stamped
		// never goes stale on an upload.
		seed := sha256.Sum256([]byte(policyTwoWorkloads))
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `W/"5"`)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set(pkgallowlist.SeedHeader, "sha256:"+hex.EncodeToString(seed[:]))
			_, _ = w.Write([]byte(policyRouterOnly))
		}))
		t.Cleanup(srv.Close)
		stamp, err := armtls.MatchedWorkloadFromCert(stampedLeaf(t, "4", policyTwoWorkloads))
		if err != nil {
			t.Fatal(err)
		}
		if _, stale, err := stampedPolicyStale(context.Background(), plaintextPolicyClient(srv.URL), stamp.AllowlistVersion, stamp.AllowlistDigest); err != nil || stale {
			t.Fatalf("stampedPolicyStale = %v, %v, want not stale", stale, err)
		}
	})

	for _, etag := range []string{"", `"5"`} {
		t.Run("200 with ETag "+strconv.Quote(etag), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if etag != "" {
					w.Header().Set("ETag", etag)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(policyRouterOnly))
			}))
			t.Cleanup(srv.Close)
			stamp, err := armtls.MatchedWorkloadFromCert(stampedLeaf(t, "4", policyTwoWorkloads))
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := stampedPolicyStale(context.Background(), plaintextPolicyClient(srv.URL), stamp.AllowlistVersion, stamp.AllowlistDigest); err == nil {
				t.Fatal("stampedPolicyStale succeeded, want error without a weak ETag")
			}
		})
	}

	t.Run("cds error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "store down", http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)
		stamp, err := armtls.MatchedWorkloadFromCert(stampedLeaf(t, "4", policyTwoWorkloads))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := stampedPolicyStale(context.Background(), plaintextPolicyClient(srv.URL), stamp.AllowlistVersion, stamp.AllowlistDigest); err == nil {
			t.Fatal("stampedPolicyStale succeeded, want error on a 500")
		}
	})
}

func TestPolicyRenewDelay(t *testing.T) {
	tests := []struct {
		name      string
		interval  time.Duration
		remaining time.Duration
		max       time.Duration
	}{
		{name: "half the interval", interval: time.Minute, remaining: time.Hour, max: 30 * time.Second},
		{name: "clamped to the scheduled renewal", interval: time.Minute, remaining: 5 * time.Second, max: 5 * time.Second},
		{name: "overdue renewal", interval: time.Minute, remaining: -time.Second, max: 0},
		{name: "sub-2ns interval", interval: 1, remaining: time.Hour, max: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 1000 {
				if got := policyRenewDelay(tt.interval, tt.remaining); got < 0 || got > tt.max {
					t.Fatalf("policyRenewDelay(%v, %v) = %v, want in [0, %v]", tt.interval, tt.remaining, got, tt.max)
				}
			}
		})
	}
}

// TestCDSWatchInterval parses --ca-watch-interval through NewCmd, then applies
// the default and validation as RunE does.
func TestCDSWatchInterval(t *testing.T) {
	base := config{
		CDSURL:            "https://cds:8443",
		AttestationApiURL: "http://localhost:8400",
		SAN:               "router.example.com",
		RenewInterval:     time.Hour,
	}
	tests := []struct {
		name    string
		args    []string
		mutate  func(*config)
		want    time.Duration
		wantErr error
	}{
		{name: "default with a renewal loop", mutate: func(*config) {}, want: time.Minute},
		{name: "default without renew interval", mutate: func(c *config) { c.RenewInterval = 0 }, want: 0},
		{name: "explicitly disabled", args: []string{"--ca-watch-interval=0"}, mutate: func(*config) {}, want: 0},
		{name: "explicit without renew interval", args: []string{"--ca-watch-interval=30s"}, mutate: func(c *config) { c.RenewInterval = 0 }, want: 30 * time.Second, wantErr: errInvalidCAWatchInterval},
		{name: "one second", args: []string{"--ca-watch-interval=1s"}, mutate: func(*config) {}, want: time.Second},
		{name: "negative", args: []string{"--ca-watch-interval=-1m"}, mutate: func(*config) {}, want: -time.Minute, wantErr: errInvalidCAWatchInterval},
		{name: "sub-second", args: []string{"--ca-watch-interval=500ms"}, mutate: func(*config) {}, want: 500 * time.Millisecond, wantErr: errInvalidCAWatchInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := NewCmd().Flags()
			if err := flags.Parse(tt.args); err != nil {
				t.Fatal(err)
			}
			interval, err := flags.GetDuration("ca-watch-interval")
			if err != nil {
				t.Fatal(err)
			}
			cfg := base
			cfg.CAWatchInterval = interval
			tt.mutate(&cfg)
			applyCDSWatchDefault(&cfg, flags)
			if cfg.CAWatchInterval != tt.want {
				t.Errorf("applyCDSWatchDefault(%v) interval = %v, want %v", tt.args, cfg.CAWatchInterval, tt.want)
			}
			if err := validateConfig(cfg); !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateConfig() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
