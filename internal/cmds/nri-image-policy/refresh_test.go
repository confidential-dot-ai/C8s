package nriimagepolicy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	pushDigestA = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	pushDigestB = "sha256:0000000000000000000000000000000000000000000000000000000000000002"
	pushDigestC = "sha256:0000000000000000000000000000000000000000000000000000000000000003"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// anyAllowlist builds an allowlist with one any-argv entry per digest, named
// "w-" plus the first 12 hex digits of the digest.
func anyAllowlist(digests map[string]string) *allowlist.Allowlist {
	al := &allowlist.Allowlist{Schema: allowlist.Schema, Workloads: map[string]allowlist.Workload{}}
	for d, image := range digests {
		al.Workloads["w-"+d[len("sha256:"):][:12]] = allowlist.Workload{Label: image, Containers: []allowlist.Container{{
			Digest:  mustDigestOrPanic(d),
			Image:   image,
			Command: allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
			Args:    allowlist.ArgvPolicy{Policy: allowlist.PolicyAny},
		}}}
	}
	return al
}

func mustDigestOrPanic(s string) types.Digest {
	d, err := types.ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

// canonicalBody renders an allowlist as the CDS /allowlist wire body.
func canonicalBody(t *testing.T, al *allowlist.Allowlist) []byte {
	t.Helper()
	b, err := al.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return b
}

// admitsDigest mirrors the plugin's admission order: the base allowlist
// first, then the served index.
func admitsDigest(store *policyStore, digest string) bool {
	snap := store.current()
	return store.baseAdmits(allowlist.RunningContainer{Digest: digest}, launchPreliminary) || (snap != nil && snap.index.AdmitsDigest(digest))
}

func TestStartupSourceMode(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config
		want string
	}{
		{
			name: "pull",
			cfg: &config{Allowlist: allowlistConfig{
				Pull: pullConfig{URL: "https://cds.example"},
			}},
			want: "pull",
		},
		{
			name: "base only",
			cfg: &config{Allowlist: allowlistConfig{
				Base: anyAllowlist(map[string]string{pushDigestA: "image-a"}),
			}},
			want: "base",
		},
		{
			name: "label rules only",
			cfg: &config{Policy: policyConfig{
				LabelRules: []labelRule{{Name: "require-tenant"}},
			}},
			want: "label_rules",
		},
		{
			name: "base and label rules",
			cfg: &config{
				Allowlist: allowlistConfig{
					Base: anyAllowlist(map[string]string{pushDigestA: "image-a"}),
				},
				Policy: policyConfig{
					LabelRules: []labelRule{{Name: "require-tenant"}},
				},
			},
			want: "base+label_rules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := startupSourceMode(tt.cfg); got != tt.want {
				t.Fatalf("startupSourceMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- policyStore epoch anti-rollback ---

func TestPolicyStoreEpochAntiRollback(t *testing.T) {
	store := newPolicyStore(anyAllowlist(map[string]string{}))

	if !store.apply(anyAllowlist(map[string]string{pushDigestB: "v5"}), 5) {
		t.Fatal("apply of version 5 rejected")
	}
	if store.current().version != 5 {
		t.Fatalf("version = %d, want 5", store.current().version)
	}

	// A lower version (rolled-back / withheld CDS) must be ignored.
	if store.apply(anyAllowlist(map[string]string{pushDigestC: "v3"}), 3) {
		t.Fatal("rolled-back version 3 was applied")
	}
	if store.current().version != 5 {
		t.Fatalf("version after rollback = %d, want 5 (unchanged)", store.current().version)
	}
	if admitsDigest(store, pushDigestC) {
		t.Fatal("rolled-back digest admitted")
	}
	if !admitsDigest(store, pushDigestB) {
		t.Fatal("version-5 digest dropped by rollback attempt")
	}

	// A forward version applies.
	if !store.apply(anyAllowlist(map[string]string{pushDigestC: "v6"}), 6) {
		t.Fatal("forward version 6 rejected")
	}
	if !admitsDigest(store, pushDigestC) {
		t.Fatal("forward digest not admitted")
	}
}

// After a restart the store is fresh (version 0), so it trusts the first pull it
// sees whatever its version — even one below what a prior process had applied.
// Rollback protection is per-process-lifetime; state re-syncs from CDS.
func TestPolicyStoreTrustsFirstVersionAfterRestart(t *testing.T) {
	// A prior process reached version 9.
	prior := newPolicyStore(anyAllowlist(map[string]string{}))
	prior.apply(anyAllowlist(map[string]string{pushDigestB: "v9"}), 9)

	// A restart is a brand-new store; its first apply is trusted regardless of value.
	fresh := newPolicyStore(anyAllowlist(map[string]string{}))
	if !fresh.apply(anyAllowlist(map[string]string{pushDigestC: "v3"}), 3) {
		t.Fatal("fresh store must trust the first version seen after a restart")
	}
	if fresh.current().version != 3 {
		t.Fatalf("version = %d, want 3", fresh.current().version)
	}
}

// --- pull loop ---

// flippingHandler serves a canonical allowlist body per version with a weak
// ETag, honoring If-None-Match with a 304. idx advances after each 200 so a
// test can script a version sequence.
type flippingHandler struct {
	mu         sync.Mutex
	versions   []string          // sequence of versions to serve
	idx        int               // current position in versions
	hits       atomic.Int32      // total requests seen
	bodyByV    map[string][]byte // canonical allowlist body per version
	statusCode int               // overrides normal logic when non-zero
}

func (f *flippingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.statusCode != 0 {
		w.WriteHeader(f.statusCode)
		return
	}

	version := f.versions[f.idx]
	etag := `W/"` + version + `"`
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(f.bodyByV[version])
	if f.idx < len(f.versions)-1 {
		f.idx++
	}
}

func TestPullLoopOnly200UpdatesIndexAndETag(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"1", "2"},
		bodyByV: map[string][]byte{
			"1": canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"})),
			"2": canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "image-2"})),
		},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:   client,
			store:    store,
			interval: 20 * time.Millisecond,
			timeout:  time.Second,
			etag:     "",
			logger:   discardLogger(),
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !admitsDigest(store, pushDigestB) {
		if time.Now().After(deadline) {
			t.Fatalf("pull loop did not pick up the second update; version=%d", store.current().version)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if store.current().version != 2 {
		t.Fatalf("applied version = %d, want 2", store.current().version)
	}

	cancel()
	<-done
}

func TestPullLoop304LeavesIndexUntouched(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"1"},
		bodyByV:  map[string][]byte{"1": canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}))
	store.apply(anyAllowlist(map[string]string{pushDigestA: "image-1"}), 1)
	before := store.current()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pre-seed the loop with the matching ETag so the first tick should 304.
	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:   client,
			store:    store,
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     `W/"1"`,
			logger:   discardLogger(),
		})
		close(done)
	}()

	// A few 304 ticks must not swap the snapshot.
	time.Sleep(100 * time.Millisecond)
	if store.current() != before {
		t.Fatal("304 ticks should leave the snapshot pointer unchanged")
	}

	cancel()
	<-done
}

func TestPullLoop5xxLeavesIndexUntouched(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{statusCode: http.StatusInternalServerError})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}))
	store.apply(anyAllowlist(map[string]string{pushDigestA: "image-1"}), 5)
	before := store.current()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:   client,
			store:    store,
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     `W/"5"`,
			logger:   discardLogger(),
		})
		close(done)
	}()

	time.Sleep(80 * time.Millisecond)
	if store.current() != before {
		t.Fatal("5xx ticks should leave the snapshot pointer unchanged")
	}

	cancel()
	<-done
}

func TestPullLoopKeepsTheBaseBesidePulled(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"1"},
		bodyByV:  map[string][]byte{"1": canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "pulled-image"}))},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:   client,
			store:    store,
			interval: 10 * time.Millisecond,
			timeout:  time.Second,
			etag:     "",
			logger:   discardLogger(),
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !admitsDigest(store, pushDigestB) {
		if time.Now().After(deadline) {
			t.Fatal("pull loop never delivered the pulled entry")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !admitsDigest(store, pushDigestA) {
		t.Fatal("base entry lost after pull")
	}

	cancel()
	<-done
}

// TestPullLoopIgnoresRolledBackFetch drives the anti-rollback guard through the
// fetch path: CDS serves version 5, then a withheld/rolled-back version 3. The
// loop must keep version 5 and never admit the rolled-back digest.
func TestPullLoopIgnoresRolledBackFetch(t *testing.T) {
	srv := httptest.NewServer(&flippingHandler{
		versions: []string{"5", "3"},
		bodyByV: map[string][]byte{
			"5": canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "v5"})),
			"3": canonicalBody(t, anyAllowlist(map[string]string{pushDigestC: "v3"})),
		},
	})
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			client:   client,
			store:    store,
			interval: 15 * time.Millisecond,
			timeout:  time.Second,
			etag:     "",
			logger:   discardLogger(),
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for !admitsDigest(store, pushDigestB) {
		if time.Now().After(deadline) {
			t.Fatal("pull loop never applied version 5")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Let the loop fetch the rolled-back version 3 several times.
	time.Sleep(150 * time.Millisecond)
	if admitsDigest(store, pushDigestC) {
		t.Fatal("rolled-back version 3 digest was admitted")
	}
	if store.current().version != 5 {
		t.Fatalf("version = %d, want 5 (rollback ignored)", store.current().version)
	}

	cancel()
	<-done
}

func TestPullInitialSucceedsAfterTransientFailures(t *testing.T) {
	orig := allowlistApiInitialDelay
	allowlistApiInitialDelay = time.Millisecond
	defer func() { allowlistApiInitialDelay = orig }()

	body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestB: "pulled-image"}))
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("ETag", `W/"1"`)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}))

	pluginErrCh := make(chan error, 1)
	ctx := t.Context()

	etag, err := pullInitial(ctx, pullArgs{
		client:      client,
		store:       store,
		timeout:     time.Second,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if etag != `W/"1"` {
		t.Fatalf("etag = %q, want W/\"1\"", etag)
	}
	if !admitsDigest(store, pushDigestB) {
		t.Fatal("store missing pulled entry")
	}
	if !admitsDigest(store, pushDigestA) {
		t.Fatal("store missing base entry")
	}
}

func TestPullInitialFailsAfterMaxRetries(t *testing.T) {
	orig := allowlistApiInitialDelay
	allowlistApiInitialDelay = time.Millisecond
	defer func() { allowlistApiInitialDelay = orig }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}))
	pluginErrCh := make(chan error, 1)
	ctx := t.Context()

	_, err := pullInitial(ctx, pullArgs{
		client:      client,
		store:       store,
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected error after max retries against a 5xx server")
	}
	// A fetch failure must NOT look like a dead plugin: run() degrades to
	// the base allowlist on a fetch failure but stays fatal on errPluginDied.
	if errors.Is(err, errPluginDied) {
		t.Fatalf("fetch failure misclassified as errPluginDied: %v", err)
	}
	// The base allowlist still enforces after the failure.
	if !admitsDigest(store, pushDigestA) {
		t.Fatal("base allowlist lost after failed initial pull")
	}
}

// A plugin-half death during init wraps errPluginDied so run() can treat it as
// fatal, unlike a recoverable fetch failure.
func TestPullInitialPluginDeathWrapsErrPluginDied(t *testing.T) {
	pluginErrCh := make(chan error, 1)
	pluginErrCh <- errors.New("nri socket closed")
	_, err := pullInitial(context.Background(), pullArgs{
		client:      allowlistclient.NewClientWithHTTP("https://unused", &http.Client{}),
		store:       newPolicyStore(anyAllowlist(map[string]string{})),
		timeout:     time.Second,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if !errors.Is(err, errPluginDied) {
		t.Fatalf("plugin death not classified as errPluginDied: %v", err)
	}
}

func TestPullInitialNotModifiedDoesNotDereferenceNilAllowlist(t *testing.T) {
	origDelay := allowlistApiInitialDelay
	origRetries := allowlistApiMaxRetries
	allowlistApiInitialDelay = time.Millisecond
	allowlistApiMaxRetries = 1
	defer func() {
		allowlistApiInitialDelay = origDelay
		allowlistApiMaxRetries = origRetries
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	store := newPolicyStore(anyAllowlist(map[string]string{pushDigestA: "bootstrap-image"}))
	before := store.current()
	pluginErrCh := make(chan error, 1)
	ctx := t.Context()

	_, err := pullInitial(ctx, pullArgs{
		client:      client,
		store:       store,
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if err == nil {
		t.Fatal("expected error for initial 304 without a pulled allowlist")
	}
	if !errors.Is(err, errInitialAllowlistNotModified) {
		t.Fatalf("expected errInitialAllowlistNotModified, got %v", err)
	}
	if store.current() != before {
		t.Fatal("initial 304 should leave the snapshot pointer unchanged")
	}
}

func TestPullInitialCancelledMidRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 200 * time.Millisecond})
	store := newPolicyStore(anyAllowlist(map[string]string{}))
	pluginErrCh := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay so we land inside the backoff sleep.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	etag, err := pullInitial(ctx, pullArgs{
		client:      client,
		store:       store,
		timeout:     200 * time.Millisecond,
		pluginErrCh: pluginErrCh,
		logger:      discardLogger(),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation should surface context.Canceled, got err=%v", err)
	}
	if etag != "" {
		t.Fatalf("cancellation should return empty etag, got %q", etag)
	}
}

// TestParseVersion covers the ETag counter extraction used for anti-rollback.
func TestParseVersion(t *testing.T) {
	for _, tc := range []struct {
		etag string
		want uint64
	}{
		{`W/"5"`, 5},
		{`"7"`, 7},
		{"12", 12},
		{"", 0},
		{`W/"not-a-number"`, 0},
	} {
		if got := parseVersion(tc.etag); got != tc.want {
			t.Errorf("parseVersion(%q) = %d, want %d", tc.etag, got, tc.want)
		}
	}
}

// A pulled policy the node cannot measure is not applied, and a measured one
// is measured, by its served digest, before it is.
func TestPullLoopAppliesOnlyMeasuredPolicies(t *testing.T) {
	for _, measureErr := range []error{nil, errors.New("register write failed")} {
		t.Run(fmt.Sprint(measureErr), func(t *testing.T) {
			body := canonicalBody(t, anyAllowlist(map[string]string{pushDigestA: "image-1"}))
			sum := sha256.Sum256(body)
			srv := httptest.NewServer(&flippingHandler{versions: []string{"1"}, bodyByV: map[string][]byte{"1": body}})
			defer srv.Close()
			client := allowlistclient.NewClientWithHTTP(srv.URL, &http.Client{Timeout: 2 * time.Second})
			store := newPolicyStore(anyAllowlist(map[string]string{}))
			var measured, early atomic.Int32
			var digest atomic.Value
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			defer func() { cancel(); <-done }()
			go func() {
				defer close(done)
				runPullLoop(ctx, pullLoopArgs{
					client: client, store: store, interval: 20 * time.Millisecond, timeout: time.Second, logger: discardLogger(),
					measure: func(d string) error {
						if admitsDigest(store, pushDigestA) {
							early.Add(1)
						}
						digest.Store(d)
						measured.Add(1)
						return measureErr
					},
				})
			}()
			deadline := time.Now().Add(2 * time.Second)
			for measured.Load() == 0 || (measureErr == nil && !admitsDigest(store, pushDigestA)) {
				if time.Now().After(deadline) {
					t.Fatalf("measured %d times, applied %v", measured.Load(), admitsDigest(store, pushDigestA))
				}
				time.Sleep(10 * time.Millisecond)
			}
			if early.Load() != 0 {
				t.Fatal("policy applied before it was measured")
			}
			if want := "sha256:" + hex.EncodeToString(sum[:]); digest.Load() != want {
				t.Fatalf("measured %v, want the served digest %s", digest.Load(), want)
			}
			if measureErr != nil && admitsDigest(store, pushDigestA) {
				t.Fatal("a policy the node could not measure was applied")
			}
		})
	}
}

// Policy measuring stays off unless configured, and without a runtime
// directory to keep the journal in.
func TestPolicyMeasurerIsOffByDefault(t *testing.T) {
	dir := t.TempDir()
	for _, cfg := range []*config{
		{Platform: "tdx", WorkloadClaims: workloadClaimsConfig{SocketDir: dir}},
		{Platform: "tdx", Allowlist: allowlistConfig{Pull: pullConfig{MeasurePolicies: true}}},
	} {
		if err := policyMeasurer(cfg, discardLogger())("sha256:" + strings.Repeat("1", 64)); err != nil {
			t.Fatalf("measure = %v, want a no-op", err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("runtime directory holds %v, want no journal", entries)
	}
}
