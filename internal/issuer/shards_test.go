package issuer

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestShardedLimiterBoundsConcurrentChurnAndRetainsHotBuckets(t *testing.T) {
	const capacity = 4097 // Includes the remainder when divided into 64 shards.
	rl, err := NewIPRateLimiter(rate.Limit(0), 1, capacity)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for g := range 32 {
		wg.Go(func() {
			for i := range 1000 {
				rl.allow("churn-" + strconv.Itoa(g*1000+i))
				if n := rl.Len(); n > capacity {
					t.Errorf("capacity=%d observed=%d", capacity, n)
					return
				}
			}
		})
	}
	wg.Wait()
	// A continuously accessed bucket stays limited even as each shard fills.
	rl.allow("hot")
	for i := range 10000 {
		rl.allow("replacement-" + strconv.Itoa(i))
		if rl.allow("hot") {
			t.Fatal("eviction reset a continuously accessed bucket")
		}
	}
	rl.evict(-time.Second)
	if rl.Len() != 0 {
		t.Fatal("shard eviction did not reclaim every bucket")
	}
}

func TestShardedNodeTrackerConcurrentRenewalAndMetrics(t *testing.T) {
	nt := NewNodeTracker(time.Hour)
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Go(func() {
			for i := range 300 {
				nt.Track("node-"+strconv.Itoa(g), time.Now().Add(time.Hour))
				if i%10 == 0 {
					nt.UpdateMetrics()
				}
			}
		})
	}
	wg.Wait()
	for i := range 16 {
		if _, ok := nt.shard("node-" + strconv.Itoa(i)).nodes["node-"+strconv.Itoa(i)]; !ok {
			t.Fatal("lost renewed node")
		}
	}
}

func BenchmarkIndependentLimiterKeys(b *testing.B) {
	rl, err := NewIPRateLimiter(rate.Inf, 1, 10000)
	if err != nil {
		b.Fatal(err)
	}
	keys := make([]string, 4096)
	for i := range keys {
		keys[i] = "node-" + strconv.Itoa(i)
		rl.allow(keys[i])
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			rl.allow(keys[i%len(keys)])
			i++
		}
	})
}
