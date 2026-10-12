package getcert

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// fakeAllowlist is a CDS /allowlist with HandleList's weak-ETag and 304
// semantics.
type fakeAllowlist struct {
	mu       sync.Mutex
	version  int
	body     string
	requests atomic.Int64
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/allowlist" {
			http.NotFound(w, r)
			return
		}
		f.requests.Add(1)
		version, body := f.snapshot()
		etag := `W/"` + version + `"`
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
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

// stubIssueUnderCurrentPolicy makes every renewal return a leaf stamped with
// the policy the fake CDS serves at that moment.
func stubIssueUnderCurrentPolicy(t *testing.T, cds *fakeAllowlist) func() []time.Time {
	t.Helper()
	return stubObtainCert(t, func(int) (*x509.Certificate, error) {
		version, body := cds.snapshot()
		return stampedLeaf(t, version, body), nil
	})
}

func policyWatchConfig() config {
	cfg := unreachableRenewalConfig()
	cfg.WorkloadClaims = true
	cfg.UnnamedRenewInterval = 0
	cfg.PolicyWatchInterval = 10 * time.Millisecond
	cfg.ReloadNginx = false
	return cfg
}

func startRenewLoop(t *testing.T, cfg config, url string, leaf *x509.Certificate) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(url), leaf, true) }()
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
	policyTwoWorkloads = `{"workloads":[{"name":"router"},{"name":"worker"}]}`
	policyRouterOnly   = `{"workloads":[{"name":"router"}]}`
	policyWithBatch    = `{"workloads":[{"name":"batch"},{"name":"router"}]}`
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
	attempts := stubIssueUnderCurrentPolicy(t, cds)

	startRenewLoop(t, policyWatchConfig(), url, stampedLeaf(t, "4", policyTwoWorkloads))

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

// stubIssueCountingPolls is stubIssueUnderCurrentPolicy that also records how
// many /allowlist requests the fake had served when each renewal started.
// fail reports whether renewal n fails.
func stubIssueCountingPolls(t *testing.T, cds *fakeAllowlist, fail func(n int) bool) (func() []time.Time, func() []int64) {
	t.Helper()
	var mu sync.Mutex
	var polls []int64
	attempts := stubObtainCert(t, func(n int) (*x509.Certificate, error) {
		mu.Lock()
		polls = append(polls, cds.requests.Load())
		mu.Unlock()
		if fail(n) {
			return nil, errors.New("stubbed renewal failure")
		}
		version, body := cds.snapshot()
		return stampedLeaf(t, version, body), nil
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
	attempts, polls := stubIssueCountingPolls(t, cds, func(int) bool { return false })

	start := time.Now()
	startRenewLoop(t, policyWatchConfig(), url, stampedLeaf(t, "4", policyTwoWorkloads))

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
	attempts, polls := stubIssueCountingPolls(t, cds, func(n int) bool { return n == 1 })

	startRenewLoop(t, policyWatchConfig(), url, stampedLeaf(t, "4", policyTwoWorkloads))

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

func TestRenewLoopPolicyWatchIgnoresUnnamedLeaf(t *testing.T) {
	cds := &fakeAllowlist{}
	cds.set(5, policyRouterOnly)
	url := cds.serve(t)
	attempts := stubIssueUnderCurrentPolicy(t, cds)

	startRenewLoop(t, policyWatchConfig(), url, &x509.Certificate{NotAfter: time.Now().Add(time.Hour)})

	time.Sleep(100 * time.Millisecond)
	if got := len(attempts()); got != 0 {
		t.Fatalf("%d renewals for an unnamed leaf, want 0", got)
	}
	if got := cds.requests.Load(); got != 0 {
		t.Fatalf("%d /allowlist polls for an unnamed leaf, want 0", got)
	}
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
		{name: "unchanged version is a 304", stamp: stampedLeaf(t, "4", policyTwoWorkloads), served: 4, body: policyRouterOnly, wantVersion: "4", want: false},
		{name: "new version", stamp: stampedLeaf(t, "4", policyTwoWorkloads), served: 5, body: policyRouterOnly, wantVersion: "5", want: true},
		{name: "new version, same bytes", stamp: stampedLeaf(t, "4", policyTwoWorkloads), served: 5, body: policyTwoWorkloads, wantVersion: "5", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cds := &fakeAllowlist{}
			cds.set(tt.served, tt.body)
			stamp, err := armtls.MatchedWorkloadFromCert(tt.stamp)
			if err != nil {
				t.Fatal(err)
			}
			served, stale, err := stampedPolicyStale(context.Background(), plaintextCDSClient(cds.serve(t)), stamp)
			if err != nil {
				t.Fatalf("stampedPolicyStale: %v", err)
			}
			if served != tt.wantVersion || stale != tt.want {
				t.Fatalf("stampedPolicyStale = %q, %v, want %q, %v", served, stale, tt.wantVersion, tt.want)
			}
		})
	}

	t.Run("same version, different digest", func(t *testing.T) {
		// A 200 can carry the stamped version when CDS's version read fails
		// and it falls back to the full load; only the digest tells then.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("ETag", `W/"4"`)
			_, _ = w.Write([]byte(policyRouterOnly))
		}))
		t.Cleanup(srv.Close)
		stamp, err := armtls.MatchedWorkloadFromCert(stampedLeaf(t, "4", policyTwoWorkloads))
		if err != nil {
			t.Fatal(err)
		}
		if _, stale, err := stampedPolicyStale(context.Background(), plaintextCDSClient(srv.URL), stamp); err != nil || !stale {
			t.Fatalf("stampedPolicyStale = %v, %v, want stale", stale, err)
		}
	})

	t.Run("cds error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "store down", http.StatusInternalServerError)
		}))
		t.Cleanup(srv.Close)
		stamp, err := armtls.MatchedWorkloadFromCert(stampedLeaf(t, "4", policyTwoWorkloads))
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := stampedPolicyStale(context.Background(), plaintextCDSClient(srv.URL), stamp); err == nil {
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

func TestValidateConfigPolicyWatchInterval(t *testing.T) {
	base := config{
		CDSURL:              "https://cds:8443",
		AttestationApiURL:   "http://localhost:8400",
		SAN:                 "router.example.com",
		RenewInterval:       time.Hour,
		WorkloadClaims:      true,
		PolicyWatchInterval: time.Minute,
	}
	tests := []struct {
		name    string
		mutate  func(*config)
		wantErr error
	}{
		{name: "valid", mutate: func(*config) {}},
		{name: "disabled without claims", mutate: func(c *config) { c.PolicyWatchInterval, c.WorkloadClaims = 0, false }},
		{name: "missing workload claims", mutate: func(c *config) { c.WorkloadClaims = false }, wantErr: errInvalidPolicyWatchInterval},
		{name: "missing renew interval", mutate: func(c *config) { c.RenewInterval = 0 }, wantErr: errInvalidPolicyWatchInterval},
		{name: "one second", mutate: func(c *config) { c.PolicyWatchInterval = time.Second }},
		{name: "negative", mutate: func(c *config) { c.PolicyWatchInterval = -time.Minute }, wantErr: errInvalidPolicyWatchInterval},
		{name: "sub-second", mutate: func(c *config) { c.PolicyWatchInterval = 500 * time.Millisecond }, wantErr: errInvalidPolicyWatchInterval},
		{name: "ca watch one second", mutate: func(c *config) { c.CAOutPath, c.CAWatchInterval = "/tls/ca.pem", time.Second }},
		{name: "ca watch sub-second", mutate: func(c *config) { c.CAOutPath, c.CAWatchInterval = "/tls/ca.pem", 500*time.Millisecond }, wantErr: errInvalidCAWatchInterval},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			if err := validateConfig(cfg); !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateConfig() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
