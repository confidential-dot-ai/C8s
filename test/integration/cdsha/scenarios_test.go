//go:build integration

package cdsha_test

import (
	"math/rand/v2"
	"testing"
	"time"
)

// scenario is one row of the matrix (docs v2-battle-test.md), run with the
// checker's writers and readers going.
type scenario struct {
	name    string
	short   bool // part of the -short subset
	writers int
	pause   time.Duration
	opts    clusterOpts
	run     func(t *testing.T, c *Cluster, k *Checker)
}

func runScenarios(t *testing.T, list []scenario) {
	for _, sc := range list {
		t.Run(sc.name, func(t *testing.T) {
			if testing.Short() && !sc.short {
				t.Skip("not in the -short subset")
			}
			c := NewCluster(t, sc.opts)
			c.WaitVoters(c.Seats, 30*time.Second)
			if sc.writers == 0 {
				sc.writers = 4
			}
			if sc.pause == 0 {
				sc.pause = 20 * time.Millisecond
			}
			k := NewChecker(c, sc.writers, sc.pause)
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

// hold keeps a fault for d (a third of it under -short).
func hold(d time.Duration) {
	if testing.Short() {
		d /= 3
	}
	time.Sleep(d)
}

// others are every replica but the listed ones.
func others(c *Cluster, not ...int) []int {
	var out []int
	for i := range c.Replicas {
		if !contains(not, i) {
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
			hold(20 * time.Second) // past dead_after: the minority is removed and must rejoin
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
		{name: "A4-asymmetric-leader-cannot-receive", run: func(t *testing.T, c *Cluster, _ *Checker) {
			l := c.WaitLeader(10 * time.Second)
			for _, j := range others(c, l) {
				c.Net.Update(j, l, func(x *Link) { x.Blackhole = true })
			}
			c.Logf("%s can send, cannot receive", c.Replicas[l].Node)
			c.Logf("%s stopped serving after %s", c.Replicas[l].Node, c.WaitNotServing(l, timing.lease+5*time.Second))
			nl := c.WaitLeader(30*time.Second, l)
			c.Logf("new leader %s", c.Replicas[nl].Node)
			hold(15 * time.Second)
			c.Heal()
			c.Logf("recovered after %s", c.WaitAllServing(60*time.Second))
		}},
		{name: "A4-asymmetric-leader-cannot-send", run: func(t *testing.T, c *Cluster, _ *Checker) {
			l := c.WaitLeader(10 * time.Second)
			for _, j := range others(c, l) {
				c.Net.Update(l, j, func(x *Link) { x.Blackhole = true })
			}
			c.Logf("%s can receive, cannot send", c.Replicas[l].Node)
			c.Logf("%s stopped serving after %s", c.Replicas[l].Node, c.WaitNotServing(l, timing.lease+5*time.Second))
			nl := c.WaitLeader(30*time.Second, l)
			c.Logf("new leader %s", c.Replicas[nl].Node)
			hold(15 * time.Second)
			c.Heal()
			c.Logf("recovered after %s", c.WaitAllServing(60*time.Second))
		}},
		{name: "A5-flapping-voter", run: func(t *testing.T, c *Cluster, _ *Checker) {
			end := time.Now().Add(60 * time.Second)
			if testing.Short() {
				end = time.Now().Add(20 * time.Second)
			}
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
		{name: "A6-latency-100ms", run: func(t *testing.T, c *Cluster, _ *Checker) {
			setAll(c, Link{Latency: 50 * time.Millisecond, Jitter: 10 * time.Millisecond}) // 100 ms round trip
			hold(30 * time.Second)
			c.Logf("under 100 ms RTT: %s", c.StatusAll())
		}},
		{name: "A6-latency-300ms", run: func(t *testing.T, c *Cluster, _ *Checker) {
			setAll(c, Link{Latency: 150 * time.Millisecond, Jitter: 30 * time.Millisecond})
			hold(30 * time.Second)
			c.Logf("under 300 ms RTT: %s", c.StatusAll())
		}},
		{name: "A6-loss-10pct", run: func(t *testing.T, c *Cluster, _ *Checker) {
			setAll(c, Link{Loss: 0.1})
			hold(30 * time.Second)
			c.Logf("under 10%% loss: %s", c.StatusAll())
		}},
	})
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
		{name: "B1-kill-leader-during-write-burst", short: true, writers: 32, pause: time.Millisecond, run: func(t *testing.T, c *Cluster, _ *Checker) {
			time.Sleep(2 * time.Second)
			l := c.WaitLeader(10 * time.Second)
			c.Kill(l)
			start := time.Now()
			nl := c.WaitLeader(30*time.Second, l)
			c.Logf("new leader %s after %s", c.Replicas[nl].Node, time.Since(start))
			time.Sleep(3 * time.Second)
			c.Start(l, false)
			c.Logf("killed node serving again after %s", c.WaitAllServing(60*time.Second))
			c.WaitVoters(3, 60*time.Second)
		}},
		{name: "B2-kill-leader-during-backup", run: func(t *testing.T, c *Cluster, _ *Checker) {
			// Backups run every second on the leader while state changes, so
			// a kill lands during or right after one.
			for range 3 {
				l := c.WaitLeader(30 * time.Second)
				before := len(c.Backups())
				time.Sleep(time.Duration(800+rand.IntN(400)) * time.Millisecond)
				c.Kill(l)
				c.WaitLeader(30*time.Second, l)
				c.Start(l, false)
				c.Logf("backup objects before %d", before)
				c.WaitAllServing(60 * time.Second)
				c.WaitVoters(3, 60*time.Second)
			}
			requireFreshBackup(t, c)
		}},
		{name: "B3-rolling-restart", run: func(t *testing.T, c *Cluster, _ *Checker) {
			for i := range c.Replicas {
				c.Restart(i, false)
				c.Logf("%s serving after %s", c.Replicas[i].Node, c.WaitServing([]int{i}, 60*time.Second))
				c.WaitVoters(3, 60*time.Second)
			}
		}},
		{name: "B3-rolling-restart-readiness-gated", run: func(t *testing.T, c *Cluster, _ *Checker) {
			// What a DaemonSet with maxUnavailable 1 and readiness = serving
			// does: the next replica restarts as soon as the previous one
			// serves, not when the voter seats are full again.
			for i := range c.Replicas {
				c.Restart(i, false)
				c.Logf("%s serving after %s; voters now %v", c.Replicas[i].Node, c.WaitServing([]int{i}, 60*time.Second), c.Voters())
			}
			c.WaitAllServing(60 * time.Second)
			c.WaitVoters(3, 60*time.Second)
		}},
		{name: "B5-repeated-leader-kills", run: func(t *testing.T, c *Cluster, _ *Checker) {
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
		{name: "C1-write-storm", writers: 50, pause: time.Millisecond, run: func(t *testing.T, _ *Cluster, _ *Checker) {
			hold(60 * time.Second)
		}},
	})
}
