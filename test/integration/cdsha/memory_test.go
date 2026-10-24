//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// memAllowBody is a workload entry of about size bytes: containers with
// distinct digests, so each write changes the served document.
func memAllowBody(name string, seq, size int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, `{"label":"ghcr.io/it/%s:v1","containers":[`, name)
	for n := 0; b.Len() < size-200; n++ {
		if n > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"digest":"sha256:%08x%056x","command":{"policy":"any"},"args":{"policy":"any"}}`, seq, n)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

// memSample is one replica's memory and Raft log at one time.
type memSample struct {
	AtS    float64           `json:"at_s"`
	Node   string            `json:"node"`
	State  string            `json:"state"`
	Mem    map[string]uint64 `json:"mem"`
	Status cdsha.Status      `json:"status"`
}

// TestMemoryLargeDocuments reproduces the soak's large-document phase at a
// steady, seeded rate (3 writers, each putting one of two workloads of
// 64-256 KiB every 500 ms, as the soak does, while readers poll the served
// document) and records every replica's memory (Go classes, RSS) and
// in-memory Raft log every 5 s, with heap profiles at the end. It is a
// measurement: set CDSHA_MEM_OUT to a directory (CDSHA_MEM_DURATION,
// default 4m).
func TestMemoryLargeDocuments(t *testing.T) {
	out := os.Getenv("CDSHA_MEM_OUT")
	if out == "" {
		t.Skip("set CDSHA_MEM_OUT")
	}
	dur := 4 * time.Minute
	if d, err := time.ParseDuration(os.Getenv("CDSHA_MEM_DURATION")); err == nil {
		dur = d
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	c := newClusterWithRaftTiming(t, timing.heartbeat, timing.election,
		"--allowlist-history-bytes", "64Mi", "--allowlist-history-versions", "1000")
	c.WaitVoters(3, 30*time.Second)
	// Three replicas (the voters): the host runs other work.
	for _, i := range c.NonVoterIDs() {
		c.Kill(i)
	}
	live := c.RunningIDs()
	samples, err := os.Create(filepath.Join(out, "samples.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer samples.Close()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	writes, refused := 0, map[int]int{}
	for w := range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewPCG(20261024, uint64(w)))
			for seq := 1; ; seq++ {
				select {
				case <-stop:
					return
				case <-time.After(500 * time.Millisecond):
				}
				name := fmt.Sprintf("mem-%d-%d", w, rng.IntN(2))
				body := memAllowBody(name, seq*16+w, (64+rng.IntN(193))<<10)
				running := c.RunningIDs()
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				r := c.Do(ctx, running[rng.IntN(len(running))], http.MethodPut, "/allowlist/workloads/"+name, body, true)
				cancel()
				mu.Lock()
				writes++
				if r.Code != http.StatusNoContent {
					refused[r.Code]++
				}
				mu.Unlock()
			}
		}()
	}
	for _, i := range live {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				case <-time.After(150 * time.Millisecond):
				}
				_ = c.Get(i, "/allowlist")
			}
		}()
	}
	start := time.Now()
	peak := map[int]uint64{}
	sample := func() {
		enc := json.NewEncoder(samples)
		for _, i := range live {
			r := c.Replicas[i]
			var m map[string]uint64
			if resp := c.Get(i, "/dev/memstats"); resp.Code == http.StatusOK {
				_ = json.Unmarshal(resp.Body, &m)
			}
			st, _ := c.Status(i)
			_ = enc.Encode(memSample{AtS: time.Since(start).Seconds(), Node: r.Node, State: st.State, Mem: m, Status: st})
			if rss := m["/proc/VmRSS:bytes"]; rss > peak[i] {
				peak[i] = rss
				saveHeap(c, i, filepath.Join(out, r.Node+"-peak.heap.pb.gz"))
			}
		}
	}
	// Guards, checked every 2 s from /proc: a replica past rssGuard (the
	// chart's memory limit: reaching it is the result) or the host below
	// hostGuard available ends the run.
	const rssGuard, hostGuard = 4 << 30, 25 << 30
	var why string
	guard := func() bool {
		if a := procKB("/proc/meminfo", "MemAvailable") << 10; a > 0 && a < hostGuard {
			why = fmt.Sprintf("host MemAvailable %d GiB", a>>30)
			return true
		}
		for _, i := range live {
			if rss := procKB(fmt.Sprintf("/proc/%d/status", c.Replicas[i].cmd.Process.Pid), "VmRSS") << 10; rss > rssGuard {
				why = fmt.Sprintf("%s RSS %d MiB", c.Replicas[i].Node, rss>>20)
				return true
			}
		}
		return false
	}
	next := time.Now()
	for time.Since(start) < dur && why == "" {
		time.Sleep(2 * time.Second)
		if guard() {
			break
		}
		if time.Now().After(next) {
			sample()
			next = time.Now().Add(5 * time.Second)
		}
	}
	if why != "" {
		c.Logf("stopping early: %s", why)
		sample() // and the heap at this point
		for _, i := range live {
			saveHeap(c, i, filepath.Join(out, c.Replicas[i].Node+"-guard.heap.pb.gz"))
		}
	}
	close(stop)
	wg.Wait()
	sample()
	for _, i := range live {
		r := c.Replicas[i]
		saveHeap(c, i, filepath.Join(out, r.Node+"-end.heap.pb.gz"))
		c.Logf("%s peak RSS %d MiB", r.Node, peak[i]>>20)
	}
	mu.Lock()
	c.Logf("%d writes, refused %v", writes, refused)
	mu.Unlock()
}

func saveHeap(c *Cluster, i int, path string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if r := c.Do(ctx, i, http.MethodGet, "/dev/pprof/heap", nil, false); r.Code == http.StatusOK {
		_ = os.WriteFile(path, r.Body, 0o644)
	}
}

// procKB is the kB value of key in a /proc file, or 0.
func procKB(path, key string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && k == key {
			var kb uint64
			_, _ = fmt.Sscanf(strings.TrimSpace(v), "%d kB", &kb)
			return kb
		}
	}
	return 0
}
