package issuer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/time/rate"
)

// TestRateLimitMiddlewareKeysBySourceIP pins that limiter entries are keyed by
// the source IP alone: a client reconnecting from a new ephemeral port must
// not get a fresh bucket.
func TestRateLimitMiddlewareKeysBySourceIP(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(0), 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "10.5.5.5:1111"
	h.ServeHTTP(first, req1)
	if first.Code != http.StatusOK {
		t.Fatalf("first request code = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.5.5.5:2222"
	h.ServeHTTP(second, req2)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("same IP from new port code = %d, want 429", second.Code)
	}
}

func TestNewIPRateLimiterRejectsNonPositiveMaxEntries(t *testing.T) {
	for _, maxEntries := range []int{0, -1} {
		if _, err := NewIPRateLimiter(rate.Limit(10), 20, maxEntries); err == nil {
			t.Errorf("maxEntries=%d: expected error, got nil", maxEntries)
		}
	}
}

func TestRateLimiterEviction(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(10), 20, 10000)
	if err != nil {
		t.Fatal(err)
	}

	rl.allow("10.0.0.1")
	rl.allow("10.0.0.2")
	rl.allow("10.0.0.3")

	rl.mu.Lock()
	if len(rl.limiters) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(rl.limiters))
	}

	oldTime := time.Now().Add(-10 * time.Minute)
	rl.limiters["10.0.0.1"].Value.(*ipLimiterEntry).lastSeen = oldTime
	rl.limiters["10.0.0.2"].Value.(*ipLimiterEntry).lastSeen = oldTime
	rl.mu.Unlock()

	rl.evict(5 * time.Minute)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if len(rl.limiters) != 1 {
		t.Errorf("expected 1 entry after eviction, got %d", len(rl.limiters))
	}
	if _, ok := rl.limiters["10.0.0.3"]; !ok {
		t.Error("expected 10.0.0.3 to survive eviction")
	}
}

// TestRateLimiterMaxEntries pins the full-map boundary: a new key is
// admitted and takes the bucket of the least recently seen key.
func TestRateLimiterMaxEntries(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(10), 20, 3)
	if err != nil {
		t.Fatal(err)
	}

	rl.allow("a")
	rl.allow("b")
	rl.allow("c")
	rl.allow("a")

	if !rl.allow("d") {
		t.Error("allow(d) on a full limiter = false, want true")
	}
	if got := rl.Len(); got != 3 {
		t.Errorf("Len() = %d, want 3", got)
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for key, want := range map[string]bool{"a": true, "b": false, "c": true, "d": true} {
		if _, got := rl.limiters[key]; got != want {
			t.Errorf("bucket for %q held = %v, want %v", key, got, want)
		}
	}
}

func TestRateLimitMiddlewareAllowsThenRejects(t *testing.T) {
	// burst=1, rate=0 -> first request allowed, second rejected.
	rl, err := NewIPRateLimiter(rate.Limit(0), 1, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	var served int
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:5555"
	h.ServeHTTP(first, req)
	if first.Code != http.StatusOK {
		t.Fatalf("first request: code = %d, want 200", first.Code)
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, req)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: code = %d, want 429", second.Code)
	}
	if served != 1 {
		t.Fatalf("handler served %d times, want 1", served)
	}
}

func TestRateLimitMiddlewareHandlesPortlessRemoteAddr(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(100), 10, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "/run/cds.sock" // no host:port
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestIPRateLimiterEvictionLoopStopsOnCancel(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(100), 10, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		rl.EvictionLoop(ctx, time.Millisecond, time.Millisecond)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("EvictionLoop did not return after cancel")
	}
}

// --- keyed limiting ---

// The point of the keyed middleware: two callers arriving from one address get
// one bucket each, so exhausting yours leaves mine untouched.
func TestRateLimitByGivesOneBucketPerKey(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	var key string
	h := RateLimitBy(rl, func(*http.Request) string { return key }, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	send := func() int {
		r := httptest.NewRequest(http.MethodGet, "/secrets/x", nil)
		r.RemoteAddr = "10.0.0.7:34567" // one node address for every caller
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	key = "sandbox:aaa"
	if code := send(); code != http.StatusOK {
		t.Fatalf("first request for aaa = %d, want 200", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("second request for aaa = %d, want 429 (its own burst is spent)", code)
	}
	key = "sandbox:bbb"
	if code := send(); code != http.StatusOK {
		t.Fatalf("a different sandbox from the same address = %d, want 200", code)
	}
}

// A caller that names no key is charged to its address, so withholding an
// identity is not a way out of the limit.
func TestRateLimitByFallsBackToTheAddress(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	h := RateLimitBy(rl, func(*http.Request) string { return "" }, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	send := func(addr string) int {
		r := httptest.NewRequest(http.MethodGet, "/secrets/x", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if code := send("10.0.0.7:1"); code != http.StatusOK {
		t.Fatalf("first = %d, want 200", code)
	}
	if code := send("10.0.0.7:2"); code != http.StatusTooManyRequests {
		t.Fatalf("same address, different port = %d, want 429 (one bucket per address)", code)
	}
	if code := send("10.0.0.8:1"); code != http.StatusOK {
		t.Fatalf("a different address = %d, want 200", code)
	}
}

// Keys are namespaced, so a sandbox ID shaped like an address cannot name the
// bucket that address is charged to.
func TestRateLimitKeyNamespacesDoNotCollide(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(1), 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	h := RateLimitBy(rl, func(r *http.Request) string { return r.Header.Get("X-Key") }, http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	send := func(key string) int {
		r := httptest.NewRequest(http.MethodGet, "/secrets/x", nil)
		r.RemoteAddr = "10.0.0.7:1"
		if key != "" {
			r.Header.Set("X-Key", key)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	// Spend the address bucket.
	if code := send(""); code != http.StatusOK {
		t.Fatalf("address request = %d, want 200", code)
	}
	if code := send(""); code != http.StatusTooManyRequests {
		t.Fatalf("address bucket should be spent, got %d", code)
	}
	// A sandbox whose ID is that same address string is a different bucket.
	if code := send("sandbox:10.0.0.7"); code != http.StatusOK {
		t.Fatalf("an address-shaped sandbox ID shares the address bucket: %d", code)
	}
}

// TestClientPrefixChargesAnIPv6PrefixOnce pins the unit a public client is
// charged to. A client delegated a /64 would otherwise hold 2^64 budgets.
func TestClientPrefixChargesAnIPv6PrefixOnce(t *testing.T) {
	for _, tc := range []struct {
		name, addr, want string
	}{
		{"IPv4 address", "203.0.113.7", "203.0.113.7"},
		{"IPv6 address", "2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"another address in that /64", "2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"},
		{"the neighbouring /64", "2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"IPv4 mapped into IPv6", "::ffff:203.0.113.7", "203.0.113.7"},
		{"not an address", "/run/cds.sock", "/run/cds.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClientPrefix(tc.addr); got != tc.want {
				t.Fatalf("ClientPrefix(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

// TestSourceAddrKeyKeepsAddressesApart pins the other half of that split: CDS
// is reached by nodes and pods, which sit densely inside one subnet, so two of
// them must not land in one bucket.
func TestSourceAddrKeyKeepsAddressesApart(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(0.001), 1, 10)
	if err != nil {
		t.Fatalf("NewIPRateLimiter: %v", err)
	}
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	code := func(remoteAddr string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := code("[2001:db8:1:2::1]:1111"); got != http.StatusOK {
		t.Fatalf("first node: got %d, want 200", got)
	}
	if got := code("[2001:db8:1:2::2]:2222"); got != http.StatusOK {
		t.Fatalf("a second node in the same /64: got %d, want its own budget", got)
	}
	if got := code("[2001:db8:1:2::1]:3333"); got != http.StatusTooManyRequests {
		t.Fatalf("the first node past its burst: got %d, want 429", got)
	}
}

// TestEvictionLoopReclaimsQuietCallers pins that the loop drains buckets
// gone quiet.
func TestEvictionLoopReclaimsQuietCallers(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(0.001), 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 8 {
		rl.allow("client-" + strconv.Itoa(i))
	}

	go rl.EvictionLoop(t.Context(), time.Millisecond, 10*time.Millisecond)

	deadline := time.Now().Add(5 * time.Second)
	for rl.Len() > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("the limiter still meters %d callers that have gone quiet", rl.Len())
		}
		time.Sleep(time.Millisecond)
	}
}

// TestHotKeyStaysLimitedUnderChurn pins that churning through far more keys
// than the map holds never evicts a key that keeps sending, so its spent
// allowance stays spent. rate 0 so nothing refills during the test.
func TestHotKeyStaysLimitedUnderChurn(t *testing.T) {
	const capacity, keys = 4, 10000
	rl, err := NewIPRateLimiter(rate.Limit(0), 1, capacity)
	if err != nil {
		t.Fatal(err)
	}
	if !rl.allow("hot") {
		t.Fatal("allow(hot) first request = false, want true")
	}
	for i := range keys {
		rl.allow("churn-" + strconv.Itoa(i))
		if rl.allow("hot") {
			t.Fatalf("allow(hot) after %d churned keys = true, want false", i+1)
		}
	}
}

// TestSaturationIsCountedNotRejected pins the counters at the HTTP layer: a
// new source admitted to a full map counts as saturation and is served; an
// over-limit request counts only as a rejection.
func TestSaturationIsCountedNotRejected(t *testing.T) {
	rl, err := NewIPRateLimiter(rate.Limit(0), 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	h := RateLimitMiddleware(rl, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	send := func(addr string) int {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = addr
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	satBefore := testutil.ToFloat64(rateLimitSaturationTotal)
	rejBefore := testutil.ToFloat64(rateLimitRejectionsTotal)

	if got := send("10.0.0.1:1"); got != http.StatusOK {
		t.Fatalf("first request: got %d, want 200", got)
	}
	if got := send("10.0.0.1:2"); got != http.StatusTooManyRequests {
		t.Fatalf("over-limit request: got %d, want 429", got)
	}
	if got := send("10.0.0.2:1"); got != http.StatusOK {
		t.Fatalf("new source on a full map: got %d, want 200", got)
	}

	if got := testutil.ToFloat64(rateLimitSaturationTotal) - satBefore; got != 1 {
		t.Errorf("saturation delta = %v, want 1", got)
	}
	if got := testutil.ToFloat64(rateLimitRejectionsTotal) - rejBefore; got != 1 {
		t.Errorf("rejection delta = %v, want 1", got)
	}
}

// TestConcurrentAllowNeverExceedsCapacity stresses the admission path from many
// goroutines with far more keys than the map holds: the map never grows past
// MaxEntries. allow releases rl.mu before touching the bucket, so -race
// exercises the guarded eviction and insert and the unlocked bucket call.
func TestConcurrentAllowNeverExceedsCapacity(t *testing.T) {
	const capacity, keys, goroutines, iterations = 64, 256, 32, 5000
	rl, err := NewIPRateLimiter(rate.Limit(1000), 1000, capacity)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range iterations {
				rl.allow("key-" + strconv.Itoa((g+i)%keys))
				if n := rl.Len(); n > capacity {
					t.Errorf("map holds %d entries, over capacity %d", n, capacity)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if got := rl.Len(); got > capacity {
		t.Errorf("map holds %d entries after the run, over capacity %d", got, capacity)
	}
}
