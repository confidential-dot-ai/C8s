package issuer

import (
	"context"
	"hash/maphash"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	activeNodes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_active_nodes",
		Help: "Number of distinct node IPs that received certificates within the TTL window.",
	})

	oldestActiveCertExpiry = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "cds_oldest_active_cert_expiry_seconds",
		Help: "Seconds until the oldest active node certificate expires.",
	})
)

type nodeEntry struct {
	lastSeen   time.Time
	certExpiry time.Time
}

// NodeTracker tracks aggregate certificate issuance metrics without per-IP
// cardinality. Entries older than 2*MaxTTL are evicted on UpdateMetrics().
type NodeTracker struct {
	shards [64]nodeShard
	seed   maphash.Seed
	maxTTL time.Duration
}

type nodeShard struct {
	mu    sync.Mutex
	nodes map[string]nodeEntry
}

func NewNodeTracker(maxTTL time.Duration) *NodeTracker {
	nt := &NodeTracker{seed: maphash.MakeSeed(), maxTTL: maxTTL}
	for i := range nt.shards {
		nt.shards[i].nodes = make(map[string]nodeEntry)
	}
	return nt
}

func (nt *NodeTracker) shard(ip string) *nodeShard {
	return &nt.shards[maphash.String(nt.seed, ip)%uint64(len(nt.shards))]
}

func (nt *NodeTracker) Track(ip string, certExpiry time.Time) {
	s := nt.shard(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[ip] = nodeEntry{
		lastSeen:   time.Now(),
		certExpiry: certExpiry,
	}
}

// UpdateMetrics recomputes aggregate gauges. Call periodically from a
// background goroutine. Each shard is scanned separately, so issuance never
// waits for a whole-fleet scan. Gauges are approximate during concurrent writes.
func (nt *NodeTracker) UpdateMetrics() {
	now := time.Now()
	cutoff := now.Add(-2 * nt.maxTTL)
	count := 0
	var oldest time.Time
	for i := range nt.shards {
		s := &nt.shards[i]
		s.mu.Lock()
		for ip, entry := range s.nodes {
			if entry.lastSeen.Before(cutoff) {
				delete(s.nodes, ip)
				continue
			}
			count++
			if oldest.IsZero() || entry.certExpiry.Before(oldest) {
				oldest = entry.certExpiry
			}
		}
		s.mu.Unlock()
	}

	activeNodes.Set(float64(count))

	if count == 0 {
		oldestActiveCertExpiry.Set(0)
		return
	}

	oldestActiveCertExpiry.Set(oldest.Sub(now).Seconds())
}

// RunUpdater calls UpdateMetrics on each tick until ctx is cancelled.
func (nt *NodeTracker) RunUpdater(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nt.UpdateMetrics()
		}
	}
}
