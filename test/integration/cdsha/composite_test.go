//go:build integration && linux

package cdsha_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// --- process stall -----------------------------------------------------------

// procState is the state letter of pid in /proc (R, S, T, ...), or "".
func procState(pid int) string {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	// pid (comm) S ...; comm may hold spaces, so cut at the last ')'.
	s := string(raw)
	j := strings.LastIndexByte(s, ')')
	if j < 0 || j+2 >= len(s) {
		return ""
	}
	return s[j+2 : j+3]
}

// Freeze stops replica i's process with SIGSTOP, as a long GC pause or a VM
// stall would: its sockets stay open, it answers nothing. The process is one
// this test started. A cleanup thaws it, so a failed test never leaves a
// stopped process behind.
func (c *Cluster) Freeze(i int) {
	c.t.Helper()
	r := c.Replicas[i]
	r.mu.Lock()
	if r.cmd == nil || r.frozen {
		r.mu.Unlock()
		return
	}
	pid := r.cmd.Process.Pid
	if err := r.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		r.mu.Unlock()
		c.t.Fatalf("freeze %s: %v", r.Node, err)
	}
	r.frozen = true
	r.mu.Unlock()
	c.t.Cleanup(func() { c.Thaw(i) })
	// SIGSTOP is asynchronous; wait until the kernel reports it stopped.
	deadline := time.Now().Add(2 * time.Second)
	for procState(pid) != "T" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	c.Logf("freeze %s (pid %d, state %s)", r.Node, pid, procState(pid))
}

// Thaw resumes a frozen replica with SIGCONT.
func (c *Cluster) Thaw(i int) {
	r := c.Replicas[i]
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cmd == nil || !r.frozen {
		return
	}
	_ = r.cmd.Process.Signal(syscall.SIGCONT)
	r.frozen = false
	c.Logf("thaw %s (pid %d)", r.Node, r.cmd.Process.Pid)
}

// Frozen reports whether replica i is frozen.
func (c *Cluster) Frozen(i int) bool {
	r := c.Replicas[i]
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.frozen
}

// ThawAll thaws every frozen replica.
func (c *Cluster) ThawAll() {
	for i := range c.Replicas {
		c.Thaw(i)
	}
}

// --- checker helpers ----------------------------------------------------------

// ackedBefore is key -> highest acked seq over writes acknowledged before t.
func (k *Checker) ackedBefore(t time.Time) map[string]int {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := map[string]int{}
	for _, op := range k.ops {
		if op.Acked() && op.End.Before(t) {
			key := op.Kind + "/" + op.Key
			out[key] = max(out[key], op.Seq)
		}
	}
	return out
}

func (k *Checker) ackedCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	n := 0
	for _, op := range k.ops {
		if op.Acked() {
			n++
		}
	}
	return n
}

// recordAux files a request of a scenario's own workload under the
// checker's status rules (5xx other than a retryable 503; 401/409 on a
// fresh valid token).
func (k *Checker) recordAux(i int, method, path string, code int, body string) {
	at := time.Now().Format("15:04:05.000")
	if len(body) > 300 {
		body = body[:300]
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if badStatus(code, body) {
		k.bad5xx = append(k.bad5xx, fmt.Sprintf("%s %s %s at %s: %d %s", at, method, path, k.c.Replicas[i].Node, code, body))
	}
	if code == http.StatusUnauthorized || code == http.StatusConflict {
		k.bad4xx = append(k.bad4xx, fmt.Sprintf("%s %s %s at %s: %d %s", at, method, path, k.c.Replicas[i].Node, code, body))
	}
}

// waitAckProgress waits until n more writes are acknowledged.
func (c *Cluster) waitAckProgress(k *Checker, n int, timeout time.Duration) {
	c.t.Helper()
	base := k.ackedCount()
	c.waitFor(timeout, func() bool { return k.ackedCount() >= base+n },
		func() string { return fmt.Sprintf("fewer than %d writes acknowledged:%s", n, c.StatusAll()) })
}

// --- G1: frozen leader -----------------------------------------------------------

// firstRead is the first served (200) read of one path at a replica.
type firstRead struct {
	path         string
	sent, got    time.Time
	vals         map[string]int
	refused      int // non-200 answers before it
	transportErr int
}

// probeFirstReads sends GET path to replica i in a loop (one goroutine per
// path, several requests in flight) until each path answers 200 once or
// the deadline passes. The requests go out before the caller thaws the
// replica, so the first one is admitted at the first instant it can be.
func (c *Cluster) probeFirstReads(i int, deadline time.Time) func() []firstRead {
	paths := []string{"/allowlist", "/dev/ha/secrets"}
	res := make([]firstRead, len(paths))
	var wg sync.WaitGroup
	for n, path := range paths {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var mu sync.Mutex
			done := false
			var inner sync.WaitGroup
			// Three staggered loops, so a request is always in flight.
			for s := range 3 {
				inner.Add(1)
				go func() {
					defer inner.Done()
					time.Sleep(time.Duration(s) * 20 * time.Millisecond)
					for time.Now().Before(deadline) {
						mu.Lock()
						if done {
							mu.Unlock()
							return
						}
						mu.Unlock()
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						sent := time.Now()
						r := c.Do(ctx, i, http.MethodGet, path, nil, false)
						cancel()
						got := time.Now()
						mu.Lock()
						switch {
						case done:
						case r.Err != nil:
							res[n].transportErr++
						case r.Code != http.StatusOK:
							res[n].refused++
						default:
							var vals map[string]int
							var err error
							if path == "/allowlist" {
								vals, err = parseAllow(r.Body)
							} else {
								vals, err = parseSecrets(r.Body)
							}
							if err == nil {
								res[n].path, res[n].sent, res[n].got, res[n].vals = path, sent, got, vals
								done = true
							}
						}
						mu.Unlock()
						time.Sleep(10 * time.Millisecond)
					}
				}()
			}
			inner.Wait()
		}()
	}
	return func() []firstRead { wg.Wait(); return res }
}

// frozenLeader freezes the leader for freezeFor, longer than lease plus
// election, then thaws it. While frozen a new leader must be elected and
// serve; once thawed, the old leader's first served read must reflect every
// write acknowledged before it was thawed (its read evidence expired while
// it was stopped, so the next one needs a barrier with the new leader), and
// writes through it are checked by the oracle.
func frozenLeader(name string, freezeFor time.Duration) scenario {
	return scenario{name: name, run: func(t *testing.T, c *Cluster, k *Checker) {
		if freezeFor <= timing.lease+timing.election {
			t.Fatalf("freeze %s is not past lease+election", freezeFor)
		}
		l := c.WaitLeader(10 * time.Second)
		c.waitAckProgress(k, 20, 20*time.Second)
		frozeAt := time.Now()
		c.Freeze(l)
		nl := c.WaitLeader(timing.lease+timing.election+20*time.Second, l)
		c.Logf("frozen leader %s; new leader %s after %s", c.Replicas[l].Node, c.Replicas[nl].Node, time.Since(frozeAt).Round(time.Millisecond))
		// The new leader commits under its own term before the thaw.
		c.waitAckProgress(k, 20, 20*time.Second)
		if d := freezeFor - time.Since(frozeAt); d > 0 {
			time.Sleep(d)
		}
		wait := c.probeFirstReads(l, time.Now().Add(60*time.Second))
		time.Sleep(300 * time.Millisecond) // the probes are queued at the stopped process
		thawAt := time.Now()
		acked := k.ackedBefore(thawAt)
		c.Thaw(l)
		c.Logf("%s frozen %s", c.Replicas[l].Node, thawAt.Sub(frozeAt).Round(time.Millisecond))
		// Writes straight through the thawed old leader: the oracle checks
		// each (a fresh key each, so an ack is exact).
		var wwg sync.WaitGroup
		probeOps := make([]Op, 6)
		for n := range probeOps {
			wwg.Add(1)
			go func() {
				defer wwg.Done()
				time.Sleep(time.Duration(n) * 50 * time.Millisecond)
				kind := []string{"allow", "secret"}[n%2]
				probeOps[n] = k.writeAt(l, kind, fmt.Sprintf("g1probe%d", n), 1)
			}()
		}
		reads := wait()
		wwg.Wait()
		for n, op := range probeOps {
			c.Logf("write %d through thawed %s: %s/%s code %d err %q acked %v end +%s", n, c.Replicas[l].Node, op.Kind, op.Key, op.Code, op.Err, op.Acked(), op.End.Sub(thawAt).Round(time.Millisecond))
		}
		st, _ := c.Status(l)
		c.Logf("thawed %s now: state=%s serving=%v epoch=%d", c.Replicas[l].Node, st.State, st.Serving, st.Epoch)
		for _, fr := range reads {
			if fr.vals == nil {
				c.Logf("no read served by thawed %s within 60s", c.Replicas[l].Node)
				continue
			}
			prefix := "allow/"
			if fr.path != "/allowlist" {
				prefix = "secret/"
			}
			var stale []string
			checked := 0
			for key, want := range acked {
				if !strings.HasPrefix(key, prefix) {
					continue
				}
				checked++
				if got, ok := fr.vals[key]; !ok || got < want {
					stale = append(stale, fmt.Sprintf("%s = %d (present %v), acked %d before the thaw", key, got, ok, want))
				}
			}
			c.Logf("first served %s at thawed %s: sent +%s answered +%s after thaw (%d refused, %d transport errors before it); %d acked keys checked, %d stale",
				fr.path, c.Replicas[l].Node, fr.sent.Sub(thawAt).Round(time.Millisecond), fr.got.Sub(thawAt).Round(time.Millisecond), fr.refused, fr.transportErr, checked, len(stale))
			if len(stale) > 0 {
				if len(stale) > 10 {
					stale = append(stale[:10:10], fmt.Sprintf("... and %d more", len(stale)-10))
				}
				t.Errorf("thawed old leader %s served a read older than writes acknowledged before the thaw (%s):\n  %s", c.Replicas[l].Node, fr.path, strings.Join(stale, "\n  "))
			}
		}
		c.Logf("all serving %s after the thaw", c.WaitAllServing(60*time.Second))
		c.WaitVoters(seats, 60*time.Second)
	}}
}

// --- G2..G5 -----------------------------------------------------------------

// setAllLinks gives every pair link l (clears isolation too).
func setAllLinks(c *Cluster, l Link) { setAll(c, l) }

func TestComposite(t *testing.T) {
	runScenarios(t, []scenario{
		frozenLeader("G1-frozen-leader", timing.lease+timing.election+3*time.Second),
		frozenLeader("G1-frozen-leader-past-dead-after", timing.deadAfter+6*time.Second),
		{name: "G1-frozen-follower-voter", run: func(t *testing.T, c *Cluster, k *Checker) {
			l := c.WaitLeader(10 * time.Second)
			f := followerVoter(t, c, l)
			c.Freeze(f)
			c.WaitServing(others(c, f), 20*time.Second)
			c.waitAckProgress(k, 20, 20*time.Second)
			hold(timing.lease + timing.election + 3*time.Second)
			wait := c.probeFirstReads(f, time.Now().Add(60*time.Second))
			time.Sleep(300 * time.Millisecond)
			thawAt := time.Now()
			acked := k.ackedBefore(thawAt)
			c.Thaw(f)
			for _, fr := range wait() {
				if fr.vals == nil {
					continue
				}
				prefix := map[string]string{"/allowlist": "allow/", "/dev/ha/secrets": "secret/"}[fr.path]
				var stale []string
				for key, want := range acked {
					if got, ok := fr.vals[key]; strings.HasPrefix(key, prefix) && (!ok || got < want) {
						stale = append(stale, fmt.Sprintf("%s = %d (present %v), acked %d", key, got, ok, want))
					}
				}
				c.Logf("first served %s at thawed follower %s: answered +%s, %d refused before, %d stale", fr.path, c.Replicas[f].Node, fr.got.Sub(thawAt).Round(time.Millisecond), fr.refused, len(stale))
				if len(stale) > 0 {
					t.Errorf("thawed follower served a read older than writes acked before the thaw (%s): %v", fr.path, stale[:min(10, len(stale))])
				}
			}
			c.WaitAllServing(60 * time.Second)
		}},
		{name: "G2-kill-leader-under-latency", productionRaftTiming: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
			lat := Link{Latency: 50 * time.Millisecond, Jitter: 10 * time.Millisecond} // ~100 ms RTT
			setAllLinks(c, lat)
			hold(5 * time.Second)
			l := c.WaitLeader(30 * time.Second)
			// A non-voter: a voter would leave one voter of three, no majority.
			nv := c.NonVoterIDs()[0]
			start := time.Now()
			c.Kill(l)
			c.Isolate(nv)
			nl := c.WaitLeader(30*time.Second, l, nv)
			c.Logf("new leader %s after %s under ~100ms RTT", c.Replicas[nl].Node, time.Since(start).Round(time.Millisecond))
			c.Logf("isolated %s stopped serving after %s", c.Replicas[nv].Node, c.WaitNotServing(nv, timing.lease+5*time.Second))
			hold(15 * time.Second)
			c.Start(l, false)
			setAllLinks(c, lat) // lift the isolation, keep the latency
			c.Logf("all serving under latency after %s", c.WaitAllServing(60*time.Second))
			c.WaitVoters(seats, 60*time.Second)
		}},
		{name: "G3-heal-then-kill-new-leader", run: func(t *testing.T, c *Cluster, _ *Checker) {
			for round := range 3 {
				l := c.WaitLeader(30 * time.Second)
				minority := []int{l, c.NonVoterIDs()[0]}
				c.Partition(minority, others(c, minority...))
				for _, i := range minority {
					c.WaitNotServing(i, timing.lease+3*time.Second)
				}
				nl := c.WaitLeader(20*time.Second, minority...)
				c.Heal()
				c.Kill(nl) // immediately: old leader rejoins while the new one dies
				start := time.Now()
				nl2 := c.WaitLeader(30*time.Second, nl)
				c.Logf("round %d: old %s, killed new %s, then %s leads after %s", round+1, c.Replicas[l].Node, c.Replicas[nl].Node, c.Replicas[nl2].Node, time.Since(start).Round(time.Millisecond))
				c.Start(nl, false)
				c.WaitAllServing(60 * time.Second)
				c.WaitVoters(seats, 60*time.Second)
			}
		}},
		{name: "G4-rolling-restart-under-loss", productionRaftTiming: true, run: func(t *testing.T, c *Cluster, _ *Checker) {
			setAllLinks(c, Link{Loss: 0.1})
			hold(5 * time.Second)
			for i := range c.Replicas {
				c.Restart(i, false)
				c.Logf("%s ready after %s; voters now %v", c.Replicas[i].Node, c.WaitReady(i, 60*time.Second), c.Voters())
			}
			c.WaitAllServing(60 * time.Second)
			c.WaitVoters(seats, 60*time.Second)
		}},
		{name: "G5-rotate-key-during-follower-restart-write-storm", writers: 32, pause: time.Millisecond, run: func(t *testing.T, c *Cluster, _ *Checker) {
			for round := range 2 {
				l := c.WaitLeader(30 * time.Second)
				f := followerVoter(t, c, l)
				epoch, ca := c.epochCA()
				c.Kill(f)
				name := c.PutDecree(cdsha.Decree{ClusterID: clusterID, IntentID: fmt.Sprintf("rotate-g5-%d", round), Kind: cdsha.RotateKey,
					BaseEpoch: epoch, ExpiresAt: time.Now().Add(time.Hour)}, nil)
				time.Sleep(time.Second)
				c.Start(f, false)
				st := c.WaitDecreeStatus(name, 30*time.Second)
				if st.AppliedEpoch == nil {
					t.Fatalf("RotateKey during follower restart: %+v", st)
				}
				start := time.Now()
				c.requireAllCA("", ca, 60*time.Second)
				c.Logf("round %d: rotated at epoch %d; every replica on the new CA after %s", round+1, *st.AppliedEpoch, time.Since(start).Round(time.Millisecond))
				c.WaitAllServing(60 * time.Second)
				c.WaitVoters(seats, 60*time.Second)
			}
		}},
		{name: "G6-random-nemesis", writers: 8, run: randomNemesis},
	})
}

// --- G6: random nemesis -----------------------------------------------------

// randomNemesis: every 15-45 s one fault from {isolate, partition,
// kill+restart, freeze/thaw, latency, loss}, held for part of the interval
// and then cleared, so at most one fault is active and a majority exists
// between faults. Seeded (CDSHA_NEMESIS_SEED) and logged.
func randomNemesis(t *testing.T, c *Cluster, k *Checker) {
	seed := uint64(time.Now().UnixNano())
	if s := os.Getenv("CDSHA_NEMESIS_SEED"); s != "" {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		seed = v
	}
	dur := 10 * time.Minute
	if s := os.Getenv("CDSHA_NEMESIS_DURATION"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
		dur = d
	}
	dur = scaled(dur)
	rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	sched, err := os.Create(filepath.Join(c.LogDir, "nemesis-schedule.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer sched.Close()
	logS := func(format string, args ...any) {
		line := fmt.Sprintf("%s "+format, append([]any{time.Now().Format("15:04:05.000")}, args...)...)
		fmt.Fprintln(sched, line)
		t.Log("nemesis: " + line)
	}
	logS("seed=%d duration=%s", seed, dur)
	faults := []string{"isolate", "partition", "kill-restart", "freeze-thaw", "latency", "loss"}
	counts := map[string]int{}
	var recoveries []time.Duration
	end := time.Now().Add(dur)
	for step := 1; time.Now().Before(end); step++ {
		interval := time.Duration(15000+rng.IntN(30001)) * time.Millisecond
		holdFor := time.Duration(float64(interval) * (0.4 + 0.4*rng.Float64()))
		f := faults[rng.IntN(len(faults))]
		victim := rng.IntN(len(c.Replicas))
		stepStart := time.Now()
		var clear func()
		switch f {
		case "isolate":
			c.Isolate(victim)
			clear = c.Heal
			logS("step %d: isolate %s for %s (interval %s)", step, c.Replicas[victim].Node, holdFor, interval)
		case "partition":
			perm := rng.Perm(len(c.Replicas))
			a, b := perm[:2], perm[2:]
			c.Partition(a, b)
			clear = c.Heal
			logS("step %d: partition %v | %v for %s (interval %s)", step, a, b, holdFor, interval)
		case "kill-restart":
			keep := rng.IntN(2) == 0
			c.Kill(victim)
			clear = func() { c.Start(victim, keep) }
			logS("step %d: kill %s for %s then restart keepDB=%v (interval %s)", step, c.Replicas[victim].Node, holdFor, keep, interval)
		case "freeze-thaw":
			c.Freeze(victim)
			clear = func() { c.Thaw(victim) }
			logS("step %d: freeze %s for %s (interval %s)", step, c.Replicas[victim].Node, holdFor, interval)
		case "latency":
			lat := time.Duration(20+rng.IntN(31)) * time.Millisecond
			setAll(c, Link{Latency: lat, Jitter: lat / 5})
			clear = c.Heal
			logS("step %d: latency %s one-way on all links for %s (interval %s)", step, lat, holdFor, interval)
		case "loss":
			setAll(c, Link{Loss: 0.1})
			clear = c.Heal
			logS("step %d: 10%% loss on all links for %s (interval %s)", step, holdFor, interval)
		}
		counts[f]++
		time.Sleep(holdFor)
		clear()
		// Metric, not an assertion: time until a leader serves again.
		cleared := time.Now()
		rec := time.Duration(-1)
		for time.Since(cleared) < interval-holdFor && time.Now().Before(end.Add(time.Minute)) {
			if c.Leader() >= 0 {
				rec = time.Since(cleared)
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		recoveries = append(recoveries, rec)
		logS("step %d: cleared %s; leader serving after %s; acked so far %d", step, f, rec.Round(time.Millisecond), k.ackedCount())
		if d := interval - time.Since(stepStart); d > 0 {
			time.Sleep(d)
		}
	}
	c.Heal()
	c.ThawAll()
	for i := range c.Replicas {
		if !c.Running(i) {
			c.Start(i, false)
		}
	}
	logS("done: faults %v; final all-serving after %s", counts, c.WaitAllServing(120*time.Second))
	c.WaitVoters(seats, 60*time.Second)
	nolead := 0
	for _, r := range recoveries {
		if r < 0 {
			nolead++
		}
	}
	logS("steps=%d steps-without-a-leader-before-next-fault=%d", len(recoveries), nolead)
}
