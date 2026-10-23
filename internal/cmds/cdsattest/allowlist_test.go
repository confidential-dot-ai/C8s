package cdsattest

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// testAllowlist is an allowlist document as the CDS serves it.
const testAllowlist = `{"schema":"c8s.allowlist/v1","workloads":{}}`

// testAllowlistV2 is another served allowlist, standing in for an upload.
const testAllowlistV2 = `{"schema":"c8s.allowlist/v1","workloads":{"app":{"containers":[]}}}`

// fakeCDSAllowlist serves GET /allowlist with whatever body it holds, or 503
// while down.
type fakeCDSAllowlist struct {
	mu   sync.Mutex
	body string
	down bool
}

func (f *fakeCDSAllowlist) set(body string, down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.body, f.down = body, down
}

func (f *fakeCDSAllowlist) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/allowlist" || f.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `W/"1"`)
	io.WriteString(w, f.body)
}

// newTestTracker tracks the allowlist cds serves, on a clock the test moves.
func newTestTracker(t *testing.T, cds *fakeCDSAllowlist, maxAge time.Duration) (*allowlistTracker, *time.Time) {
	t.Helper()
	ts := httptest.NewServer(cds)
	t.Cleanup(ts.Close)
	client := allowlistclient.NewClientWithHTTP(ts.URL, ts.Client())
	tracker := newAllowlistTracker(func(ctx context.Context) ([]byte, error) {
		body, _, err := client.CanonicalBytes(ctx)
		return body, err
	}, maxAge, slog.New(slog.DiscardHandler))
	now := time.Unix(1_700_000_000, 0)
	tracker.now = func() time.Time { return now }
	return tracker, &now
}

func TestAllowlistTrackerDigestAndFreshness(t *testing.T) {
	cds := &fakeCDSAllowlist{body: testAllowlist}
	tracker, now := newTestTracker(t, cds, time.Minute)
	ctx := context.Background()

	if _, err := tracker.Digest(); !errors.Is(err, errAllowlistUnavailable) {
		t.Fatalf("Digest before the first fetch = %v, want errAllowlistUnavailable", err)
	}
	if err := tracker.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	wantDigest := func(want string) {
		t.Helper()
		got, err := tracker.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256([]byte(want)); string(got) != string(sum[:]) {
			t.Fatalf("Digest = %x, want SHA-256 of the served bytes %x", got, sum)
		}
	}
	wantDigest(testAllowlist)

	// An upload changes the digest at the next poll.
	cds.set(testAllowlistV2, false)
	*now = now.Add(10 * time.Second)
	if err := tracker.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	wantDigest(testAllowlistV2)

	// A failed fetch keeps the digest until the maximum age passes.
	cds.set(testAllowlistV2, true)
	*now = now.Add(59 * time.Second)
	if err := tracker.Poll(ctx); err == nil {
		t.Fatal("Poll against an unreachable CDS succeeded")
	}
	wantDigest(testAllowlistV2)
	*now = now.Add(time.Second)
	if _, err := tracker.Digest(); !errors.Is(err, errAllowlistStale) {
		t.Fatalf("Digest at the maximum age = %v, want errAllowlistStale", err)
	}

	// A body that is not an allowlist is a failed fetch, not a new digest.
	cds.set(`not json`, false)
	if err := tracker.Poll(ctx); err == nil {
		t.Fatal("Poll accepted a body that is not an allowlist")
	}
	if _, err := tracker.Digest(); !errors.Is(err, errAllowlistStale) {
		t.Fatalf("Digest after an invalid body = %v, want errAllowlistStale", err)
	}

	// The next successful fetch clears the stale state.
	cds.set(testAllowlist, false)
	if err := tracker.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	wantDigest(testAllowlist)
}

func TestHandshakesBindTheTrackedAllowlistDigest(t *testing.T) {
	cds := &fakeCDSAllowlist{body: testAllowlist}
	tracker, _ := newTestTracker(t, cds, time.Minute)
	if err := tracker.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	d := newDigestServerWith(t, testRoutes(t), tracker)
	d.pqBound(t, testRouteDigest, sha256.Sum256([]byte(testAllowlist)))
	d.lbBound(t, testRouteDigest, sha256.Sum256([]byte(testAllowlist)))

	cds.set(testAllowlistV2, false)
	if err := tracker.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.pqBound(t, testRouteDigest, sha256.Sum256([]byte(testAllowlistV2)))
	d.lbBound(t, testRouteDigest, sha256.Sum256([]byte(testAllowlistV2)))
}

func TestHandshakesRefusedWithoutAFreshAllowlistDigest(t *testing.T) {
	cds := &fakeCDSAllowlist{body: testAllowlist}
	tracker, now := newTestTracker(t, cds, time.Minute)
	d := newDigestServerWith(t, testRoutes(t), tracker)

	refused := func(want string) {
		t.Helper()
		ck, err := overenc.GenerateClientKey()
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(types.AttestPQRequest{Nonce: b64url(make([]byte, 32)), XWingEK: b64url(ck.EncapsulationKey())})
		pq := postAttestPQ(t, d.url, body)
		lb, err := http.Get(d.url + "/.well-known/c8s/attest-lb?nonce=" + b64url(make([]byte, 32)))
		if err != nil {
			t.Fatal(err)
		}
		for name, resp := range map[string]*http.Response{"attest-pq": pq, "attest-lb": lb} {
			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Fatalf("%s status = %d, want 503", name, resp.StatusCode)
			}
			if got := errorCode(t, resp); got != want {
				t.Fatalf("%s error = %q, want %q", name, got, want)
			}
		}
		if d.prov.lastReportData != nil {
			t.Fatal("a refused handshake requested evidence")
		}
	}

	refused(types.ErrorCodeAllowlistUnavailable)
	if err := tracker.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	cds.set(testAllowlist, true)
	*now = now.Add(time.Minute)
	if err := tracker.Poll(context.Background()); err == nil {
		t.Fatal("Poll against an unreachable CDS succeeded")
	}
	refused(types.ErrorCodeAllowlistStale)
}
