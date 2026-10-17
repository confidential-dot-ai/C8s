//go:build integration

package cdsha_test

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
)

// RSS is the resident set of replica i's process in MiB (0 if not running).
func (c *Cluster) RSS(i int) float64 {
	r := c.Replicas[i]
	r.mu.Lock()
	cmd := r.cmd
	r.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return 0
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			kb, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), "kB")), 64)
			return kb / 1024
		}
	}
	return 0
}

// TestMemoryGrowth (C3, memory): RSS of every replica against the number of
// allowlist versions, for a small and a large document. The allowlist
// journal keeps a document copy per version, and HA adds the Raft log,
// snapshot and sealed backup copies.
func TestMemoryGrowth(t *testing.T) {
	if testing.Short() {
		t.Skip("not in the -short subset")
	}
	for _, entries := range []int{10, 200} {
		t.Run(fmt.Sprintf("doc-%d-entries", entries), func(t *testing.T) {
			c := NewCluster(t, clusterOpts{})
			c.WaitVoters(3, 30*time.Second)
			put := func(i int, name string, seq int) Response {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				return c.Do(ctx, i, http.MethodPut, "/allowlist/workloads/"+name, allowBody(name, seq), "op")
			}
			for n := 0; n < entries; n++ {
				if r := put(n%5, fmt.Sprintf("base-%d", n), n+1); r.Code != http.StatusNoContent {
					t.Fatalf("seed entry: %d %v %s", r.Code, r.Err, r.Body)
				}
			}
			docBytes := len(c.Get(0, "/allowlist").Body)
			report := func(versions int) {
				var parts []string
				for i := range c.Replicas {
					parts = append(parts, fmt.Sprintf("%s=%.0f", c.Replicas[i].Node, c.RSS(i)))
				}
				hist := len(c.Get(0, "/allowlist/history").Body)
				backup := 0
				if b, err := cdsha.BackupFromConfigMaps(clusterID, c.Backups()); err == nil {
					backup = len(b.Ciphertext)
				}
				c.Logf("MEM doc=%dB versions=%d rss_mib[%s] history=%dKiB backup=%dKiB", docBytes, versions, strings.Join(parts, " "), hist/1024, backup/1024)
			}
			report(entries)
			var versions atomic.Int64
			versions.Store(int64(entries))
			for _, target := range []int64{250, 500, 1000, 2000} {
				var wg sync.WaitGroup
				for w := 0; w < 8; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for versions.Load() < target {
							v := versions.Add(1)
							if r := put(int(v)%5, fmt.Sprintf("churn-%d", w), int(v)); r.Code != http.StatusNoContent {
								t.Errorf("write: %d %v %s", r.Code, r.Err, r.Body)
								return
							}
						}
					}()
				}
				wg.Wait()
				time.Sleep(3 * time.Second) // a backup round and GC
				report(int(target))
			}
			k := NewChecker(c, 0, 0)
			if _, _, err := k.Converge(60 * time.Second); err != nil {
				t.Fatal(err)
			}
		})
	}
}
