//go:build integration && linux

package cdsha_test

import (
	"context"
	"math/rand/v2"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// scenario is one row of the fault matrix, run with the checker's writers
// and readers going.
type scenario struct {
	name                 string
	short                bool // part of the -short subset
	writers              int
	productionRaftTiming bool // RTT availability scenarios use the deployed election/lease margin
	pause                time.Duration
	args                 []string // extra replica flags
	// capacityRefusals: the scenario drives the state to the HA admission
	// cap, so a 507 naming the snapshot capacity is an expected, definite
	// refusal there (counted, not bad5xx). Everywhere else it stays bad5xx.
	capacityRefusals bool
	run              func(t *testing.T, c *Cluster, k *Checker)
}

func runScenarios(t *testing.T, list []scenario) {
	for _, sc := range list {
		t.Run(sc.name, func(t *testing.T) {
			if testing.Short() && !sc.short {
				t.Skip("not in the -short subset")
			}
			heartbeat, election := timing.heartbeat, timing.election
			args := sc.args
			if sc.productionRaftTiming {
				heartbeat, election = cdsha.DefaultTiming.Heartbeat, cdsha.DefaultTiming.Election
				// The deployed read lease too. A row that claims production
				// timing but keeps the harness's 2.5s lease cannot keep reads
				// certified at 300-360ms RTT (followers 81-89% not serving;
				// 0-4% under the deployed 5s lease, TestAvailabilityRTT), so
				// it would test a configuration nobody deploys. A row's own
				// --ha-lease in args still wins: it comes later.
				args = append([]string{"--ha-lease", cdsha.DefaultTiming.Lease.String()}, sc.args...)
			}
			c := newClusterWithRaftTiming(t, heartbeat, election, args...)
			c.WaitVoters(seats, 30*time.Second)
			if sc.writers == 0 {
				sc.writers = 4
			}
			if sc.pause == 0 {
				sc.pause = 20 * time.Millisecond
			}
			k := NewChecker(c, sc.writers, sc.pause)
			k.capacityOK = sc.capacityRefusals
			k.Start()
			time.Sleep(time.Second)
			start := time.Now()
			sc.run(t, c, k)
			c.Heal()
			k.Require(k.Check(90 * time.Second))
			c.Logf("scenario took %s", time.Since(start).Round(time.Millisecond))
		})
	}
}

// scaled is d, or a third of it under -short.
func scaled(d time.Duration) time.Duration {
	if testing.Short() {
		return d / 3
	}
	return d
}

// hold keeps a fault for scaled(d).
func hold(d time.Duration) { time.Sleep(scaled(d)) }

// others are every replica but the listed ones.
func others(c *Cluster, not ...int) []int {
	var out []int
	for i := range c.Replicas {
		if !slices.Contains(not, i) {
			out = append(out, i)
		}
	}
	return out
}

// followerVoter is a voter that is not the leader.
func followerVoter(t *testing.T, c *Cluster, l int) int {
	t.Helper()
	for _, v := range c.Voters() {
		if v != l {
			return v
		}
	}
	t.Fatalf("no follower voter: %s", c.StatusAll())
	return -1
}

func TestNetworkFaults(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "A1-leader-isolated", short: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
			l := c.WaitLeader(10 * time.Second)
			c.Isolate(l)
			stop := c.WaitNotServing(l, timing.lease+3*time.Second)
			nl := c.WaitLeader(20*time.Second, l)
			c.Logf("old leader %s stopped serving after %s; new leader %s", c.Replicas[l].Node, stop, c.Replicas[nl].Node)
			hold(30 * time.Second)
			c.Heal()
			c.Logf("isolated replica serving again after %s", c.WaitAllServing(60*time.Second))
		}},
		{name: "A2-follower-isolated", run: func(t *testing.T, c *Cluster, _ *Checker) {
			l := c.WaitLeader(10 * time.Second)
			f := followerVoter(t, c, l)
			c.Isolate(f)
			c.Logf("%s stopped serving after %s", c.Replicas[f].Node, c.WaitNotServing(f, timing.lease+3*time.Second))
			c.WaitServing(others(c, f), 10*time.Second)
			hold(15 * time.Second)
			c.Heal()
			c.Logf("caught up after %s", c.WaitAllServing(60*time.Second))
		}},
		{name: "A2-nonvoter-isolated", run: func(t *testing.T, c *Cluster, _ *Checker) {
			nv := c.NonVoterIDs()[0]
			c.Isolate(nv)
			c.Logf("%s stopped serving after %s", c.Replicas[nv].Node, c.WaitNotServing(nv, timing.lease+3*time.Second))
			hold(15 * time.Second)
			c.Heal()
			c.Logf("caught up after %s", c.WaitAllServing(60*time.Second))
		}},
		{name: "A3-split-leader-in-minority", short: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
			// Minority: the leader and one non-voter (one voter of three).
			l := c.WaitLeader(10 * time.Second)
			minority := []int{l, c.NonVoterIDs()[0]}
			c.Partition(minority, others(c, minority...))
			for _, i := range minority {
				c.Logf("%s stopped serving after %s", c.Replicas[i].Node, c.WaitNotServing(i, timing.lease+3*time.Second))
			}
			nl := c.WaitLeader(20*time.Second, minority...)
			c.Logf("majority leader %s", c.Replicas[nl].Node)
			// Past dead_after the majority removes the minority, which must
			// then rejoin as new members.
			c.waitFor(timing.deadAfter+15*time.Second, func() bool {
				st, ok := c.Status(nl)
				return ok && len(st.Voters)+len(st.NonVoters) == replicas-len(minority)
			}, func() string { return "minority not removed:" + c.StatusAll() })
			c.Heal()
			c.Logf("minority serving again after %s", c.WaitAllServing(60*time.Second))
			c.WaitVoters(3, 30*time.Second)
		}},
		{name: "A3-split-leader-in-majority", run: func(t *testing.T, c *Cluster, _ *Checker) {
			// Majority side: the leader and one more voter (two of three).
			l := c.WaitLeader(10 * time.Second)
			f := followerVoter(t, c, l)
			majority := []int{l, f}
			minority := others(c, majority...)
			c.Partition(majority, minority)
			for _, i := range minority {
				c.Logf("%s stopped serving after %s", c.Replicas[i].Node, c.WaitNotServing(i, timing.lease+3*time.Second))
			}
			c.WaitServing(majority, 10*time.Second)
			hold(20 * time.Second)
			c.Heal()
			c.Logf("minority serving again after %s", c.WaitAllServing(60*time.Second))
			c.WaitVoters(3, 30*time.Second)
		}},
		asymmetric("A4-asymmetric-leader-cannot-receive", false),
		asymmetric("A4-asymmetric-leader-cannot-send", true),
		{name: "A5-flapping-voter", run: func(t *testing.T, c *Cluster, _ *Checker) {
			end := time.Now().Add(60 * time.Second)
			flaps := 0
			for time.Now().Before(end) {
				v := c.Voters()
				if len(v) == 0 {
					time.Sleep(500 * time.Millisecond)
					continue
				}
				i := v[rand.IntN(len(v))]
				c.Isolate(i)
				time.Sleep(time.Duration(2000+rand.IntN(3000)) * time.Millisecond)
				c.Heal()
				time.Sleep(time.Duration(2000+rand.IntN(3000)) * time.Millisecond)
				flaps++
			}
			c.Logf("%d flaps; serving again after %s", flaps, c.WaitAllServing(60*time.Second))
		}},
		degraded("A6-latency-100ms", Link{Latency: 50 * time.Millisecond, Jitter: 10 * time.Millisecond}), // 100 ms round trip
		degraded("A6-latency-300ms", Link{Latency: 150 * time.Millisecond, Jitter: 30 * time.Millisecond}),
		degraded("A6-loss-10pct", Link{Loss: 0.1}),
	})
}

// asymmetric blackholes every link into the leader (or, with send, out of
// it): the leader must step down and a new one take over.
func asymmetric(name string, send bool) scenario {
	return scenario{name: name, run: func(t *testing.T, c *Cluster, _ *Checker) {
		l := c.WaitLeader(10 * time.Second)
		for _, j := range others(c, l) {
			from, to := j, l
			if send {
				from, to = l, j
			}
			c.Net.Update(from, to, func(x *Link) { x.Blackhole = true })
		}
		c.Logf("%s stopped serving after %s", c.Replicas[l].Node, c.WaitNotServing(l, timing.lease+5*time.Second))
		nl := c.WaitLeader(30*time.Second, l)
		c.Logf("new leader %s", c.Replicas[nl].Node)
		hold(15 * time.Second)
		c.Heal()
		c.Logf("recovered after %s", c.WaitAllServing(60*time.Second))
	}}
}

// degraded holds link l on every pair; every replica must still serve
// under it.
func degraded(name string, l Link) scenario {
	// Raft's leader lease is heartbeat/2. The fast harness's 250ms lease
	// cannot sustain the 300–360ms RTT row. Production's 500ms lease can;
	// use its heartbeat/election rather than weakening quorum checks.
	return scenario{name: name, productionRaftTiming: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
		setAll(c, l)
		hold(30 * time.Second)
		c.WaitAllServing(5 * time.Second)
	}}
}

// setAll applies one link to every pair.
func setAll(c *Cluster, l Link) {
	for i := range c.Replicas {
		for j := range c.Replicas {
			if i != j {
				c.Net.Set(i, j, l)
			}
		}
	}
	c.Logf("every link: %+v", l)
}

func TestProcessFaults(t *testing.T) {
	runScenarios(t, []scenario{
		{name: "B2-kill-leader-during-backup", run: func(t *testing.T, c *Cluster, _ *Checker) {
			// Backups run every second on the leader while state changes, so
			// a kill lands during or right after one.
			for range 3 {
				l := c.WaitLeader(30 * time.Second)
				time.Sleep(time.Duration(800+rand.IntN(400)) * time.Millisecond)
				c.Kill(l)
				c.WaitLeader(30*time.Second, l)
				c.Start(l, false)
				c.WaitAllServing(60 * time.Second)
				c.WaitVoters(3, 60*time.Second)
			}
			requireFreshBackup(t, c)
		}},
		{name: "B3-rolling-restart-readiness-gated", run: func(t *testing.T, c *Cluster, _ *Checker) {
			// What a DaemonSet with maxUnavailable 1 does: the next replica
			// restarts as soon as the previous one is Ready (GET /readyz).
			// Ready must wait until the voter seats are full again, or the
			// third restart takes the majority.
			for i := range c.Replicas {
				c.Restart(i, false)
				c.Logf("%s ready after %s; voters now %v", c.Replicas[i].Node, c.WaitReady(i, 60*time.Second), c.Voters())
			}
			c.WaitAllServing(60 * time.Second)
			c.WaitVoters(3, 60*time.Second)
		}},
		// B5 tests leader kills under a write burst, not capacity: 32 writers
		// with the harness's unbounded history grow the state past what a
		// snapshot holds within about a minute, and the admission cap would
		// then refuse writes (507). Bound the history as a deployment does
		// (TestBigState uses 64Mi; B5 writes faster between the leader's
		// prunes, so half that) to keep it a leader-kill test. The cap
		// itself is CAP1's.
		{name: "B5-repeated-leader-kills-during-write-burst", short: true, writers: 32, pause: time.Millisecond, args: []string{"--allowlist-history-bytes", "32Mi"}, run: func(t *testing.T, c *Cluster, _ *Checker) {
			kills := 6
			if testing.Short() {
				kills = 3
			}
			for n := 0; n < kills; n++ {
				l := c.WaitLeader(30 * time.Second)
				c.Kill(l)
				start := time.Now()
				nl := c.WaitLeader(30*time.Second, l)
				c.Logf("kill %d: new leader %s after %s", n+1, c.Replicas[nl].Node, time.Since(start))
				c.Start(l, false)
				c.WaitAllServing(60 * time.Second)
				c.WaitVoters(3, 60*time.Second)
				time.Sleep(3 * time.Second)
			}
		}},
		{name: "B7-kill-nonvoter-while-promoted", run: func(t *testing.T, c *Cluster, _ *Checker) {
			l := c.WaitLeader(10 * time.Second)
			v := followerVoter(t, c, l)
			nvs := c.NonVoterIDs()
			c.Kill(v)
			// The leader removes v after dead_after and promotes a non-voter
			// once it is stable; kill one non-voter around that moment.
			time.Sleep(timing.deadAfter - 500*time.Millisecond)
			c.Kill(nvs[0])
			c.WaitVoters(3, 60*time.Second)
			c.Start(v, false)
			c.Start(nvs[0], false)
			c.WaitAllServing(60 * time.Second)
		}},
		{name: "B8-pod-restart-same-node", run: func(t *testing.T, c *Cluster, _ *Checker) {
			for n := 0; n < 4; n++ {
				i := rand.IntN(len(c.Replicas))
				c.Restart(i, true) // same allowlist DB file: a new process on the same node
				c.WaitServing([]int{i}, 60*time.Second)
				c.WaitVoters(3, 60*time.Second)
			}
		}},
	})
}

func TestLoad(t *testing.T) {
	runScenarios(t, []scenario{
		// C1 tests throughput and safety under 50 writers, not capacity: with
		// the harness's unbounded history they grow the state to the
		// admission cap within a minute, and every write after is refused
		// (507). Bound the history as a deployment does (like B5); the cap
		// itself is TestCapacity's.
		{name: "C1-write-storm", writers: 50, pause: time.Millisecond, args: []string{"--allowlist-history-bytes", "32Mi"}, run: func(t *testing.T, _ *Cluster, _ *Checker) {
			hold(60 * time.Second)
		}},
	})
}

// TestCapacity drives the state to the HA admission cap (75% of what a
// snapshot holds) with the harness's unbounded history, as B5 did before
// the cap existed (backups then failed every second and leaders stepped
// down). At the cap the cluster must refuse growth with 507 naming the
// snapshot capacity (never 500/503), keep serving reads, keep storing
// backups, keep its leader, and take shrinking writes.
func TestCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("not in the -short subset")
	}
	runScenarios(t, []scenario{
		{name: "CAP1-growth-refused-at-snapshot-capacity", writers: 32, pause: time.Millisecond, capacityRefusals: true, run: func(t *testing.T, c *Cluster, k *Checker) {
			probe := []byte(`{"label":"ghcr.io/it/cap-probe:v1","containers":[{"digest":"sha256:` + strings.Repeat("c", 64) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`)
			if r := c.Do(context.Background(), c.WaitLeader(30*time.Second), http.MethodPut, "/allowlist/workloads/cap-probe", probe, true); r.Code != http.StatusNoContent {
				t.Fatalf("probe entry: %d %s", r.Code, r.Body)
			}
			start := time.Now()
			c.waitFor(5*time.Minute, func() bool { return k.Capacity() > 0 }, func() string { return "no capacity refusal yet: " + c.StatusAll() })
			c.Logf("cap reached after %s", time.Since(start).Round(time.Second))
			l := c.WaitLeader(30 * time.Second)
			lst, _ := c.Status(l)
			hold(20 * time.Second) // writers keep pressing at the cap
			// The same leader, still serving, and every replica serves.
			if now, ok := c.Status(l); !ok || now.State != "Leader" || !now.Serving {
				t.Errorf("leader %s lost its lease at the cap: %+v (was %+v)", c.Replicas[l].Node, now, lst)
			}
			c.WaitAllServing(30 * time.Second)
			// Backups keep being stored, and the leader reports no failure.
			requireFreshBackup(t, c)
			if st, _ := c.Status(c.WaitLeader(30 * time.Second)); st.BackupError != "" {
				t.Errorf("backups failing at the cap: %s", st.BackupError)
			}
			// A shrinking write is taken at the cap, through any replica.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if r := c.Do(ctx, others(c, l)[0], http.MethodDelete, "/allowlist/workloads/cap-probe", nil, true); r.Code != http.StatusNoContent {
				t.Errorf("delete at the cap: %d %s", r.Code, r.Body)
			}
			c.Logf("capacity refusals so far: %d", k.Capacity())
		}},
	})
}
