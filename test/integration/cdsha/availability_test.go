//go:build integration && linux

package cdsha_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// availability polls every running replica's /ha/status every 200 ms for d
// and returns, per node, the fraction of samples it did not serve and the
// number of serving->not-serving transitions. A metric, not an assertion.
func (c *Cluster) availability(d time.Duration) map[string][3]float64 {
	type acc struct {
		samples, down, flaps int
		last                 bool
	}
	accs := map[string]*acc{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	end := time.Now().Add(d)
	for _, i := range c.RunningIDs() {
		node := c.Replicas[i].Node
		a := &acc{last: true}
		accs[node] = a
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(end) {
				st, ok := c.Status(i)
				serving := ok && st.Serving
				mu.Lock()
				a.samples++
				if !serving {
					a.down++
					if a.last {
						a.flaps++
					}
				}
				a.last = serving
				mu.Unlock()
				time.Sleep(200 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	out := map[string][3]float64{}
	for node, a := range accs {
		out[node] = [3]float64{float64(a.down) / float64(max(a.samples, 1)), float64(a.flaps), float64(a.samples)}
	}
	return out
}

// rttAvailability holds a 300-360 ms RTT on every link under the deployed
// Raft timing and the given read lease, records per-replica availability,
// then, with assert, applies A6's own check (every replica serving within
// 5 s); without, it only reports.
func rttAvailability(name string, lease time.Duration, assert bool) scenario {
	return scenario{name: name, productionRaftTiming: true,
		args: []string{"--ha-lease", lease.String()},
		run: func(t *testing.T, c *Cluster, _ *Checker) {
			setAll(c, Link{Latency: 150 * time.Millisecond, Jitter: 30 * time.Millisecond})
			av := c.availability(scaled(30 * time.Second))
			var b strings.Builder
			for _, r := range c.Replicas {
				if v, ok := av[r.Node]; ok {
					st, _ := c.Status(r.Idx)
					fmt.Fprintf(&b, " %s(%s)=%.1f%%/%dflaps/%dsamples", r.Node, st.State, 100*v[0], int(v[1]), int(v[2]))
				}
			}
			c.Logf("availability lease=%s RTT 300-360ms, %% of samples not serving:%s", lease, b.String())
			if !assert {
				// The comparison row: the harness lease is known not to keep
				// reads certified at this RTT. Report only.
				return
			}
			c.WaitAllServing(5 * time.Second)
		}}
}

func TestAvailabilityRTT(t *testing.T) {
	extended(t)
	runScenarios(t, []scenario{
		rttAvailability("A6m-latency-300ms-harness-lease", timing.lease, false),
		rttAvailability("A6m-latency-300ms-deployed-lease", cdsha.DefaultTiming.Lease, true),
	})
}
