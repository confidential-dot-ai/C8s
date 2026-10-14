package issuer

import (
	"container/list"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/time/rate"
)

var (
	rateLimitRejectionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cds_rate_limit_rejections_total",
		Help: "Total requests rejected by rate limiter.",
	})

	rateLimitCapacityEvictionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "cds_rate_limit_capacity_evictions_total",
		Help: "Total new keys admitted to a full rate limiter by evicting its least recently seen bucket.",
	})

	rateLimiterEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_rate_limiter_entries",
		Help: "Current number of entries in the rate limiter.",
	})
)

type ipLimiterEntry struct {
	key      string
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter implements keyed rate limiting with bounded memory. It holds
// at most MaxEntries buckets; once it is full a new key takes the least
// recently seen bucket, so a busy key is never the one evicted. EvictionLoop
// reclaims buckets idle longer than IdleTimeout.
// RateLimitMiddleware keys on the source address; RateLimitBy keys on whatever
// identifies the caller.
type IPRateLimiter struct {
	mu         sync.Mutex
	limiters   map[string]*list.Element
	recency    *list.List // of *ipLimiterEntry, most recently seen first
	rate       rate.Limit
	burst      int
	maxEntries int
}

func NewIPRateLimiter(r rate.Limit, burst, maxEntries int) (*IPRateLimiter, error) {
	if maxEntries <= 0 {
		// A non-positive cap leaves no room for even the key being admitted.
		return nil, fmt.Errorf("rate limiter maxEntries must be positive, got %d", maxEntries)
	}
	return &IPRateLimiter{
		limiters:   make(map[string]*list.Element),
		recency:    list.New(),
		rate:       r,
		burst:      burst,
		maxEntries: maxEntries,
	}, nil
}

// allow charges one request to key's bucket and reports whether it may
// proceed. A new key arriving at a full map evicts the least recently seen
// bucket: that only resets the evicted key's allowance, which never lets any
// key exceed its rate, whereas refusing would lock new callers out.
func (rl *IPRateLimiter) allow(key string) bool {
	rl.mu.Lock()
	var entry *ipLimiterEntry
	if elem, ok := rl.limiters[key]; ok {
		rl.recency.MoveToFront(elem)
		entry = elem.Value.(*ipLimiterEntry)
	} else {
		if len(rl.limiters) >= rl.maxEntries {
			oldest := rl.recency.Back()
			rl.recency.Remove(oldest)
			delete(rl.limiters, oldest.Value.(*ipLimiterEntry).key)
			rateLimitCapacityEvictionsTotal.Inc()
		}
		entry = &ipLimiterEntry{key: key, limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.limiters[key] = rl.recency.PushFront(entry)
	}
	entry.lastSeen = time.Now()
	rl.mu.Unlock()
	return entry.limiter.Allow()
}

// Len reports how many callers the limiter is metering, for metrics and tests.
func (rl *IPRateLimiter) Len() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.limiters)
}

// EvictionLoop removes rate limiter entries idle longer than idleTimeout.
// It blocks until ctx is cancelled.
func (rl *IPRateLimiter) EvictionLoop(ctx context.Context, interval, idleTimeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.evict(idleTimeout)
		}
	}
}

func (rl *IPRateLimiter) evict(idleTimeout time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-idleTimeout)
	// recency is ordered by lastSeen, so the idle entries are a run at the back.
	for elem := rl.recency.Back(); elem != nil; elem = rl.recency.Back() {
		entry := elem.Value.(*ipLimiterEntry)
		if !entry.lastSeen.Before(cutoff) {
			break
		}
		rl.recency.Remove(elem)
		delete(rl.limiters, entry.key)
	}
	rateLimiterEntries.Set(float64(len(rl.limiters)))
}

// KeyFunc names the bucket a request is charged to. Returning "" charges it to
// the source address.
//
// Keys carry a kind prefix so two namespaces can share one limiter without a
// value in either being able to name a bucket in the other.
type KeyFunc func(*http.Request) string

// RateLimitMiddleware wraps next with per-source-IP rate limiting against rl.
// On reject it returns 429 and increments the rejection counter.
func RateLimitMiddleware(rl *IPRateLimiter, next http.Handler) http.Handler {
	return RateLimitBy(rl, nil, next)
}

// RateLimitBy wraps next, charging each request to the bucket key names. Use
// it where the source address is not the caller — an attested identity, a
// session, or the address a front door recorded. A request with no identity to
// key on falls back to the source address, so nothing escapes limiting by
// declining to identify itself.
func RateLimitBy(rl *IPRateLimiter, key KeyFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bucket := ""
		if key != nil {
			bucket = key(r)
		}
		if bucket == "" {
			bucket = SourceAddrKey(r)
		}
		if !rl.allow(bucket) {
			rateLimitRejectionsTotal.Inc()
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SourceAddrKey charges a request to the exact address it arrived from. Its
// callers are reached by nodes, pods and operators, whose addresses are
// assigned rather than chosen, and which sit densely inside one subnet: a
// bucket per address is what keeps one node's traffic off another's.
func SourceAddrKey(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}
	return "addr:" + ip
}

// clientPrefixBitsV6 is the IPv6 prefix a public client is charged to. An
// ordinary subscriber is delegated a /64, so charging a full address would let
// one of them name 2^64 buckets.
const clientPrefixBitsV6 = 64

// ClientPrefix names the address block a limit on a public client is charged
// to: one IPv4 address, or one IPv6 /64. Use it where the caller is on the
// internet and picks its own address within a prefix. An address it cannot
// parse is charged verbatim, so nothing escapes a limit by being unparseable.
func ClientPrefix(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return fmt.Sprintf("%s/%d", ip.Mask(net.CIDRMask(clientPrefixBitsV6, 8*net.IPv6len)), clientPrefixBitsV6)
}
