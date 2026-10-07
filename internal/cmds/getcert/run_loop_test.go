package getcert

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// capturedRecord is one captured slog record: message plus resolved attrs.
type capturedRecord struct {
	level slog.Level
	msg   string
	attrs map[string]slog.Value
}

// logCapture is a slog.Handler that stores records for later inspection.
type logCapture struct {
	mu      sync.Mutex
	records []capturedRecord
}

func (c *logCapture) Enabled(context.Context, slog.Level) bool { return true }

func (c *logCapture) Handle(_ context.Context, r slog.Record) error {
	rec := capturedRecord{level: r.Level, msg: r.Message, attrs: map[string]slog.Value{}}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Resolve()
		return true
	})
	c.mu.Lock()
	c.records = append(c.records, rec)
	c.mu.Unlock()
	return nil
}

func (c *logCapture) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *logCapture) WithGroup(string) slog.Handler      { return c }

func (c *logCapture) find(msg string) (capturedRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, rec := range c.records {
		if rec.msg == msg {
			return rec, true
		}
	}
	return capturedRecord{}, false
}

// captureDefaultLogger swaps the process default logger for a capture handler
// and restores it on cleanup.
func captureDefaultLogger(t *testing.T) *logCapture {
	t.Helper()
	c := &logCapture{}
	old := slog.Default()
	slog.SetDefault(slog.New(c))
	t.Cleanup(func() { slog.SetDefault(old) })
	return c
}

// holdSIGTERM keeps a test-side SIGTERM subscription for the test's lifetime,
// so signalling the process can never hit the default terminate action.
func holdSIGTERM(t *testing.T) {
	t.Helper()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGTERM)
	t.Cleanup(func() { signal.Stop(ch) })
}

// unreachableRenewalConfig is a config whose certificate requests always fail
// fast (nothing listens on port 1) but whose validation passes, carrying run
// into the renewal loop via continue-on-initial-error.
func unreachableRenewalConfig(t *testing.T) config {
	return stagePodEnvironment(t, config{
		CDSURL:                 "https://127.0.0.1:1",
		AttestationApiURL:      "http://127.0.0.1:1",
		SAN:                    "host.example.com",
		InitialRetryTimeout:    0,
		ContinueOnInitialError: true,
		RenewInterval:          time.Hour,
	})
}

func terminateRun(t *testing.T, done <-chan error) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("run did not shut down after SIGTERM")
	}
}

// stubObtainCert makes every certificate request publish what issue(n) asks
// for — a leaf TTL, or an error — where n is the 1-based attempt number. The
// generation is minted by ca for the pod's own key and published the way
// obtainCert does, so the loop runs against real credential state.
func stubObtainCert(t *testing.T, ca *testCA, issue func(n int) (time.Duration, error)) func() []time.Time {
	return stubObtainCertMinting(t, func(creds *credentials, n int) (*Generation, error) {
		ttl, err := issue(n)
		if err != nil {
			return nil, err
		}
		return issueFor(ca, creds, ttl)
	})
}

// stubObtainCertNaming publishes a named generation on every request: the pod's
// workload has been matched.
func stubObtainCertNaming(t *testing.T, ca *testCA) func() []time.Time {
	return stubObtainCertMinting(t, func(creds *credentials, _ int) (*Generation, error) {
		return issueNamedFor(ca, creds, time.Hour)
	})
}

// stubObtainCertFailing makes every certificate request fail.
func stubObtainCertFailing(t *testing.T) func() []time.Time {
	return stubObtainCertMinting(t, func(*credentials, int) (*Generation, error) {
		return nil, errors.New("stubbed certificate request failure")
	})
}

// stubObtainCertMinting replaces the issuance step and returns a reader for the
// attempts' timestamps.
func stubObtainCertMinting(t *testing.T, mint func(creds *credentials, n int) (*Generation, error)) func() []time.Time {
	t.Helper()
	var mu sync.Mutex
	var at []time.Time
	old := obtainCertFn
	obtainCertFn = func(_ context.Context, _ config, _ attestclient.Client, creds *credentials) error {
		mu.Lock()
		at = append(at, time.Now())
		n := len(at)
		mu.Unlock()
		generation, err := mint(creds, n)
		if err != nil {
			return err
		}
		return creds.publish(generation, time.Now())
	}
	t.Cleanup(func() { obtainCertFn = old })
	return func() []time.Time {
		mu.Lock()
		defer mu.Unlock()
		return append([]time.Time(nil), at...)
	}
}

// waitForAttempts polls until at least n certificate attempts were made.
func waitForAttempts(t *testing.T, attempts func() []time.Time, n int) []time.Time {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if at := attempts(); len(at) >= n {
			return at
		}
		if time.Now().After(deadline) {
			t.Fatalf("got %d certificate attempts, want at least %d", len(attempts()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// catchSIGHUP subscribes for the reload signal ReloadNginx sends the master.
func catchSIGHUP(t *testing.T) <-chan os.Signal {
	t.Helper()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(hup) })
	return hup
}

// presentAsNginxMaster makes ReloadNginx find this test process under root.
func presentAsNginxMaster(t *testing.T, root string) {
	t.Helper()
	pidDir := filepath.Join(root, strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(pidDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("nginx\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "cmdline"), []byte("nginx: master process\x00"), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRunRenewalLoopRetriesFailedRenewal(t *testing.T) {
	holdSIGTERM(t)

	oldBase := renewalRetryBase
	renewalRetryBase = 40 * time.Millisecond
	t.Cleanup(func() { renewalRetryBase = oldBase })

	// The initial request must succeed: only with a generation published is a
	// failing tick a renewal. While none has landed the loop is on the
	// initial-retry backoff instead (TestRunRetriesInitialCertOffTheRetryBackoff).
	attempts := stubObtainCert(t, newTestCA(t), func(n int) (time.Duration, error) {
		if n == 1 {
			return time.Hour, nil
		}
		return 0, errors.New("stubbed certificate request failure")
	})

	cfg := unreachableRenewalConfig(t)
	cfg.RenewInterval = 200 * time.Millisecond
	cfg.ReloadNginx = false

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	at := waitForAttempts(t, attempts, 4)
	terminateRun(t, done)

	// at[0] is the initial request, at[1] the first renewal tick. After each
	// failure the loop must wait ~renewalRetryBase, then ~2x — never a whole
	// --renew-interval.
	if gap := at[2].Sub(at[1]); gap < renewalRetryBase || gap >= cfg.RenewInterval {
		t.Errorf("first retry came %v after the failed renewal, want [%v, %v)", gap, renewalRetryBase, cfg.RenewInterval)
	}
	if gap := at[3].Sub(at[2]); gap < 2*renewalRetryBase || gap >= cfg.RenewInterval {
		t.Errorf("second retry came %v after the failed renewal, want [%v, %v)", gap, 2*renewalRetryBase, cfg.RenewInterval)
	}
}

// A renewal that succeeds after failures resets the backoff: the loop keeps
// running, paces the next renewal a full --renew-interval out, and a later
// failure retries from renewalRetryBase again — not the pre-recovery climbed
// delay.
func TestRunRenewalLoopRecoversAfterFailedRenewals(t *testing.T) {
	holdSIGTERM(t)

	oldBase := renewalRetryBase
	renewalRetryBase = 40 * time.Millisecond
	t.Cleanup(func() { renewalRetryBase = oldBase })

	// The stub publishes a generation, fails three renewals — climbing the
	// backoff — then publishes a long-lived one on attempt 5, so post-recovery
	// pacing is a full --renew-interval.
	attempts := stubObtainCert(t, newTestCA(t), func(n int) (time.Duration, error) {
		if n == 1 || n == 5 {
			return time.Hour, nil
		}
		return 0, errors.New("stubbed certificate request failure")
	})

	cfg := unreachableRenewalConfig(t)
	cfg.RenewInterval = 200 * time.Millisecond
	cfg.ReloadNginx = false

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	at := waitForAttempts(t, attempts, 7)
	terminateRun(t, done)

	// at[4] is the recovered renewal, at[5] the next tick a full interval out,
	// at[6] the retry after at[5] fails — back at renewalRetryBase, proving the
	// failures counter reset.
	if gap := at[5].Sub(at[4]); gap < cfg.RenewInterval {
		t.Errorf("post-recovery renewal came %v after the success, want a full interval >= %v", gap, cfg.RenewInterval)
	}
	if gap := at[6].Sub(at[5]); gap < renewalRetryBase || gap >= cfg.RenewInterval {
		t.Errorf("retry after the post-recovery failure came %v, want [%v, %v) — failures did not reset", gap, renewalRetryBase, cfg.RenewInterval)
	}
}

// A changed watch file triggers an nginx reload, and a failed reload does
// not stop the watcher: later changes still reload.
func TestRunRenewalLoopReloadsOnWatchChange(t *testing.T) {
	holdSIGTERM(t)
	hup := catchSIGHUP(t)

	// No nginx master yet, so the first reloads fail; the watcher proving
	// live afterwards means those failures were tolerated.
	root := t.TempDir()
	overrideProcRoot(t, root)

	watched := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.WriteFile(watched, []byte("v1"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := unreachableRenewalConfig(t)
	cfg.ReloadNginx = true
	cfg.ReloadWatchPaths = []string{watched}
	cfg.ReloadWatchInterval = 20 * time.Millisecond

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	// A change written before the loop's initial snapshot is invisible to the
	// watcher, so keep changing the file: every post-snapshot change is a
	// failed reload while the master is absent.
	for i := 2; i <= 4; i++ {
		if err := os.WriteFile(watched, []byte(fmt.Sprintf("v%d", i)), 0644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	presentAsNginxMaster(t, root)
	if err := os.WriteFile(watched, []byte("v5"), 0644); err != nil {
		t.Fatal(err)
	}
	select {
	case <-hup:
	case <-time.After(5 * time.Second):
		t.Fatal("no nginx reload after the watched file changed")
	}
	terminateRun(t, done)
}

// Without watch paths the loop must not set up a watch ticker: a zero watch
// interval is only rejected (or used) when paths are configured, so run must
// come up and shut down cleanly.
func TestRunRenewalLoopWithoutWatchPathsIgnoresWatchInterval(t *testing.T) {
	holdSIGTERM(t)
	attempts := stubObtainCertFailing(t)

	cfg := unreachableRenewalConfig(t)
	cfg.RenewInterval = 25 * time.Millisecond
	cfg.ReloadNginx = true
	cfg.ReloadWatchPaths = nil
	cfg.ReloadWatchInterval = 0

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	// A second attempt means the tolerated initial failure carried run into
	// the renewal loop.
	waitForAttempts(t, attempts, 2)
	terminateRun(t, done)
}

func overrideProcRoot(t *testing.T, root string) {
	t.Helper()
	old := procRoot
	procRoot = root
	t.Cleanup(func() { procRoot = old })
}

func TestRunRenewalModeFailsOnBadWatchSnapshot(t *testing.T) {
	// continue-on-initial-error carries run past the failed first request, and
	// the missing watch path then fails the loop setup.
	cfg := unreachableRenewalConfig(t)
	cfg.ReloadNginx = true
	cfg.ReloadWatchPaths = []string{filepath.Join(t.TempDir(), "missing.crt")}
	cfg.ReloadWatchInterval = time.Minute
	if err := run(cfg); err == nil || !strings.Contains(err.Error(), "stat reload watch path") {
		t.Fatalf("error = %v, want watch snapshot error", err)
	}
}

// A workload is gated on its first certificate by c8s-cert-wait, so while none
// has landed the loop must re-ask on the initial-retry backoff rather than wait
// out --renew-interval. It is an hour here, so four attempts inside the
// deadline can only have come from the backoff.
func TestRunRetriesInitialCertOffTheRetryBackoff(t *testing.T) {
	holdSIGTERM(t)
	attempts := stubObtainCertFailing(t)

	cfg := unreachableRenewalConfig(t)
	cfg.InitialRetryInterval = 10 * time.Millisecond
	cfg.ReloadNginx = false

	done := make(chan error, 1)
	go func() { done <- run(cfg) }()

	waitForAttempts(t, attempts, 4)
	terminateRun(t, done)
}

// The retry cadence has to actually produce a certificate: a CDS that refuses
// twice and then issues must leave the loop holding a generation well inside
// --renew-interval.
func TestRenewLoopRetriesInitialCertBeforeRenewInterval(t *testing.T) {
	stageInventory(t, testInstanceID)
	cdsURL, attURL := startFakeServersRefusing(t, newTestCA(t), 2)

	cfg := config{
		CDSURL:                cdsURL,
		AttestationApiURL:     attURL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
		InitialRetryInterval:  5 * time.Millisecond,
		RenewInterval:         time.Hour,
	}
	creds := testCredentials(t)
	cfg.CertPath = filepath.Join(creds.volume.dir, creds.volume.leafName)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(cfg.CDSURL), creds) }()

	waitForFile(t, cfg.CertPath, done)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("renewLoop returned %v, want nil on shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("renewLoop did not shut down when the context was cancelled")
	}
}

// Once the first generation lands the cadence returns to the ordinary pacing:
// the retry backoff must not keep re-requesting for the life of the process.
func TestRenewLoopStopsRetryingAfterFirstCert(t *testing.T) {
	stageInventory(t, testInstanceID)
	cdsURL, attURL := startFakeServers(t, newTestCA(t))

	cfg := config{
		CDSURL:                cdsURL,
		AttestationApiURL:     attURL,
		SAN:                   "host.example.com",
		WorkloadClaimsTimeout: 5 * time.Second,
		InitialRetryInterval:  time.Millisecond,
		RenewInterval:         time.Hour,
	}
	creds := testCredentials(t)
	cfg.CertPath = filepath.Join(creds.volume.dir, creds.volume.leafName)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(cfg.CDSURL), creds) }()

	waitForFile(t, cfg.CertPath, done)
	before, err := os.Readlink(creds.volume.pointerPath())
	if err != nil {
		t.Fatal(err)
	}
	// Many backoff periods, no renewal tick: another flip here means the loop
	// never left the retry cadence.
	time.Sleep(100 * time.Millisecond)
	after, err := os.Readlink(creds.volume.pointerPath())
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatal("generation republished after the first success: the loop is still on the retry cadence")
	}

	cancel()
	<-done
}

// waitForFile blocks until path exists, failing the test if the loop returns
// first or the wait times out.
func waitForFile(t *testing.T, path string, done <-chan error) {
	t.Helper()
	deadline := time.After(15 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("renewLoop returned before writing %s: %v", path, err)
		case <-deadline:
			t.Fatalf("no certificate at %s: get-cert waited out --renew-interval instead of retrying", path)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// startFakeCAServer serves /ca with whatever bundle serve() returns, so a test
// can swap the "current" CDS mesh CA mid-flight.
func startFakeCAServer(t *testing.T, serve func() string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ca" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, serve())
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestServedCAStale(t *testing.T) {
	caA := testCertificatePEM(t)
	caB := testCertificatePEM(t)

	writeServed := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	tests := []struct {
		name    string
		cds     string
		served  string
		want    bool
		wantErr bool
	}{
		{name: "same CA", cds: caA, served: caA, want: false},
		{name: "regenerated CA", cds: caB, served: caA, want: true},
		{name: "served bundle still carries the current CA", cds: caA, served: caB + caA, want: false},
		{name: "unparseable cds bundle", cds: "not pem", served: caA, wantErr: true},
		{name: "unparseable served bundle", cds: caA, served: "not pem", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := startFakeCAServer(t, func() string { return tt.cds })
			stale, err := servedCAStale(context.Background(), plaintextCDSClient(url), writeServed(t, tt.served))
			if tt.wantErr != (err != nil) {
				t.Fatalf("servedCAStale err = %v, wantErr %v", err, tt.wantErr)
			}
			if stale != tt.want {
				t.Fatalf("servedCAStale = %v, want %v", stale, tt.want)
			}
		})
	}

	t.Run("missing served bundle", func(t *testing.T) {
		url := startFakeCAServer(t, func() string { return caA })
		if _, err := servedCAStale(context.Background(), plaintextCDSClient(url), filepath.Join(t.TempDir(), "missing.pem")); err == nil {
			t.Fatal("servedCAStale succeeded, want read error")
		}
	})

	t.Run("cds unreachable", func(t *testing.T) {
		if _, err := servedCAStale(context.Background(), plaintextCDSClient("http://127.0.0.1:1"), writeServed(t, caA)); err == nil {
			t.Fatal("servedCAStale succeeded, want transport error")
		}
	})
}

// A CDS whose /ca stops matching the served bundle triggers an immediate
// renewal instead of waiting out --renew-interval (an hour here, so any
// renewal inside the deadline can only have come from the CA watch); while the
// bundles match the watch must stay quiet.
func TestRenewLoopRenewsWhenCDSMeshCAChanges(t *testing.T) {
	caA := testCertificatePEM(t)
	caB := testCertificatePEM(t)

	var mu sync.Mutex
	current := caA
	url := startFakeCAServer(t, func() string {
		mu.Lock()
		defer mu.Unlock()
		return current
	})

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, []byte(caA), 0644); err != nil {
		t.Fatal(err)
	}

	ca := newTestCA(t)
	attempts := stubObtainCert(t, ca, func(int) (time.Duration, error) { return time.Hour, nil })

	cfg := unreachableRenewalConfig(t)
	cfg.CAPath = caPath
	cfg.CAWatchInterval = 10 * time.Millisecond
	cfg.ReloadNginx = false

	creds := publishedCredentials(t, ca, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient(url), creds) }()

	// Matching bundles: many watch ticks must pass without a renewal.
	time.Sleep(100 * time.Millisecond)
	if got := attempts(); len(got) != 0 {
		t.Fatalf("%d renewals while the CA matched, want 0", len(got))
	}

	mu.Lock()
	current = caB
	mu.Unlock()
	waitForAttempts(t, attempts, 1)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("renewLoop returned %v, want nil on shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("renewLoop did not shut down when the context was cancelled")
	}
}

func TestRenewLoopPicksUpNameWithinSeconds(t *testing.T) {
	ca := newTestCA(t)
	attempts := stubObtainCertNaming(t, ca)

	cfg := config{
		RenewInterval:        time.Hour,
		UnnamedRenewInterval: 30 * time.Second,
	}
	creds := publishedCredentials(t, ca, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- renewLoop(ctx, cfg, plaintextCDSClient("http://127.0.0.1:1"), creds) }()

	at := waitForAttempts(t, attempts, 1)
	if gap := at[0].Sub(start); gap > 3*time.Second {
		t.Fatalf("renewed the unnamed leaf %v after publication, want within 3s", gap)
	}
	// Named now: no further fast polls.
	time.Sleep(3 * time.Second)
	if n := len(attempts()); n != 1 {
		t.Fatalf("%d renewals after the leaf was named, want 1", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("renewLoop returned %v, want nil on shutdown", err)
	}
}

func TestCDSHTTPClientWarnsOnlyWithoutMeasurements(t *testing.T) {
	base := config{CDSURL: "https://cds:8443", AttestationApiURL: "http://attestation-api:8400"}
	const warnMsg = "--cds-measurements not set; get-cert accepts any armTLS-attested CDS measurement"

	t.Run("unpinned warns", func(t *testing.T) {
		c := captureDefaultLogger(t)
		if _, err := cdsHTTPClient(base); err != nil {
			t.Fatalf("cdsHTTPClient: %v", err)
		}
		if _, ok := c.find(warnMsg); !ok {
			t.Fatal("no warning logged for an unpinned CDS measurement set")
		}
	})

	t.Run("pinned does not warn", func(t *testing.T) {
		c := captureDefaultLogger(t)
		cfg := base
		cfg.CDSMeasurements = strings.Repeat("ab", 48)
		if _, err := cdsHTTPClient(cfg); err != nil {
			t.Fatalf("cdsHTTPClient: %v", err)
		}
		if _, ok := c.find(warnMsg); ok {
			t.Fatal("warning logged despite pinned measurements")
		}
	})
}

func TestCDSHTTPClientParsesRTMRPins(t *testing.T) {
	base := config{CDSURL: "https://cds:8443", AttestationApiURL: "http://attestation-api:8400"}

	cfg := base
	cfg.CDSRTMRs = "1=zz"
	if _, err := cdsHTTPClient(cfg); err == nil || !strings.Contains(err.Error(), "--cds-rtmrs") {
		t.Fatalf("err = %v, want an RTMR parse failure naming the flag", err)
	}

	cfg.CDSMeasurements = strings.Repeat("ab", 48)
	cfg.CDSRTMRs = "1=" + strings.Repeat("cd", 48)
	if _, err := cdsHTTPClient(cfg); err != nil {
		t.Fatalf("cdsHTTPClient with valid pins: %v", err)
	}
}
