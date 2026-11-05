//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

type comparisonResult struct {
	Backend               string      `json:"backend"`
	Storage               string      `json:"storage"`
	AddedRequestLatencyMS int         `json:"added_request_latency_ms"`
	Concurrency           int         `json:"concurrency"`
	Requests              int         `json:"requests"`
	Attempted             int         `json:"attempted"`
	FailedStage           string      `json:"failed_stage,omitempty"`
	Succeeded             int         `json:"succeeded"`
	Failures              map[int]int `json:"failures"`
	Seconds               float64     `json:"seconds"`
	RequestsPerSecond     float64     `json:"requests_per_second"`
	P50MS                 float64     `json:"p50_ms"`
	P95MS                 float64     `json:"p95_ms"`
	P99MS                 float64     `json:"p99_ms"`
	Gets                  uint64      `json:"gets"`
	Puts                  uint64      `json:"puts"`
	Conflicts             uint64      `json:"conflicts"`
	Batches               uint64      `json:"batches"`
	Commands              uint64      `json:"commands"`
	Forwarded             uint64      `json:"forwarded"`
	Takeovers             uint64      `json:"takeovers"`
	Rejected              uint64      `json:"rejected"`
}

// TestPilotComparison is opt-in, uses the SAME release binary in each arm, and
// records errors as well as successful latency. One HTTP policy write commits
// an operator-token consumption and a policy update. No request is retried by
// the load generator. Injected GET/PUT latency is outside fixture shard locks.
func TestPilotComparison(t *testing.T) {
	if os.Getenv("CDSHA_COMPARE") != "1" {
		t.Skip("set CDSHA_COMPARE=1")
	}
	if !releaseProcesses {
		t.Fatal("comparison requires CDSHA_RELEASE=1")
	}
	n := comparisonInt(t, "CDSHA_COMPARE_REQUESTS", 48, 1, 10000)
	concurrencies := comparisonInts(t, "CDSHA_COMPARE_CONCURRENCY", []int{1, 8, 32}, 1, 256)
	delays := comparisonInts(t, "CDSHA_COMPARE_LATENCY_MS", []int{0, 25, 100}, 0, 1000)
	backends := []string{"raft", "object-single-direct", "object-batch-direct", "object-batch-preferred"}
	if filter := os.Getenv("CDSHA_COMPARE_BACKENDS"); filter != "" {
		backends = strings.Split(filter, ",")
		for _, b := range backends {
			if !slices.Contains([]string{"raft", "object-single-direct", "object-batch-direct", "object-batch-preferred"}, b) {
				t.Fatalf("unknown backend %q", b)
			}
		}
	}
	var results []comparisonResult
	for _, backend := range backends {
		storageDelays := delays
		if backend == "raft" || os.Getenv("CDSHA_COMPARE_S3_FILE") != "" {
			storageDelays = []int{0}
		}
		for _, delay := range storageDelays {
			for _, concurrency := range concurrencies {
				t.Run(fmt.Sprintf("%s/%dms/c%d", backend, delay, concurrency), func(t *testing.T) {
					result := comparisonResult{Backend: backend, Storage: "loopback", AddedRequestLatencyMS: delay, Concurrency: concurrency, Requests: n, Failures: map[int]int{}}
					stage := "bootstrap"
					if backend != "raft" && os.Getenv("CDSHA_COMPARE_S3_FILE") != "" {
						result.Storage = "s3"
					}
					t.Cleanup(func() {
						if t.Failed() {
							result.FailedStage = stage
						}
						results = append(results, result)
						encoded, _ := json.Marshal(result)
						t.Log(string(encoded))
					})
					var fixture *objectFixture
					storage := "loopback"
					if backend != "raft" {
						if file := os.Getenv("CDSHA_COMPARE_S3_FILE"); file != "" {
							fixture = externalComparisonStore(t, file)
							storage = "s3/" + fixture.config.Region
						} else {
							fixture = newObjectFixture(t)
						}
						fixture.config.DirectWriters = backend != "object-batch-preferred"
						if backend == "object-single-direct" {
							fixture.config.BatchMaxEntries = 1
						}
					}
					c := newClusterWithObjects(t, threeReplicas, fixture)
					if fixture == nil {
						c.waitRollSafe(time.Minute)
					}
					c.replaceAllowlist(c.replicas[0], "comparison-warmup")
					if fixture != nil {
						fixture.delayNS.Store(int64(time.Duration(delay) * time.Millisecond))
					}
					before := c.comparisonStats()
					result.Storage = storage
					stage = "load"
					type answer struct {
						elapsed time.Duration
						code    int
					}
					answers := make(chan answer, n)
					jobs := make(chan int, n)
					for i := range n {
						jobs <- i
					}
					close(jobs)
					startGate := make(chan struct{})
					var workers sync.WaitGroup
					for range concurrency {
						workers.Go(func() {
							<-startGate
							for i := range jobs {
								start := time.Now()
								code, _ := c.put(c.replicas[i%len(c.replicas)], "/allowlist", allowlistDocument(fmt.Sprintf("comparison-%d", i)))
								answers <- answer{time.Since(start), code}
							}
						})
					}
					start := time.Now()
					result.Attempted = n
					close(startGate)
					workers.Wait()
					result.Seconds = time.Since(start).Seconds()
					close(answers)
					var latencies []time.Duration
					for a := range answers {
						if a.code == http.StatusNoContent {
							result.Succeeded++
							latencies = append(latencies, a.elapsed)
						} else {
							result.Failures[a.code]++
						}
					}
					result.RequestsPerSecond = float64(result.Succeeded) / result.Seconds
					slices.Sort(latencies)
					if len(latencies) > 0 {
						result.P50MS = percentile(latencies, 50)
						result.P95MS = percentile(latencies, 95)
						result.P99MS = percentile(latencies, 99)
					}
					after := c.comparisonStats()
					result.Gets = after.Gets - before.Gets
					result.Puts = after.Puts - before.Puts
					result.Conflicts = after.Conflicts - before.Conflicts
					result.Batches = after.Batches - before.Batches
					result.Commands = after.CommittedCommands - before.CommittedCommands
					result.Forwarded = after.Forwarded - before.Forwarded
					result.Takeovers = after.Takeovers - before.Takeovers
					result.Rejected = after.Rejected - before.Rejected
					stage = "recovery"
					// Check recovery and convergence after the timed window without
					// including these additional writes/reads in the reported counters.
					c.waitServing(time.Minute)
					c.replaceAllowlist(c.replicas[1], "comparison-final")
					c.waitFor("comparison replicas to converge", time.Minute, func() bool { return c.allServe("comparison-final") })
				})
			}
		}
	}
	if file := os.Getenv("CDSHA_COMPARE_OUTPUT"); file != "" {
		body, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, append(body, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func percentile(values []time.Duration, p int) float64 {
	return float64(values[max(0, (len(values)*p+99)/100-1)]) / float64(time.Millisecond)
}
func comparisonInt(t *testing.T, name string, fallback, min, max int) int {
	t.Helper()
	s := os.Getenv(name)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < min || n > max {
		t.Fatalf("invalid %s", name)
	}
	return n
}
func comparisonInts(t *testing.T, name string, fallback []int, min, max int) []int {
	t.Helper()
	s := os.Getenv(name)
	if s == "" {
		return fallback
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(part)
		if err != nil || n < min || n > max {
			t.Fatalf("invalid %s", name)
		}
		out = append(out, n)
	}
	return out
}

func (c *cluster) comparisonStats() objectwal.Stats {
	var total objectwal.Stats
	if c.objectWAL == nil {
		return total
	}
	for _, r := range c.replicas {
		s := c.actorStats(r)
		total.Gets += s.Gets
		total.Puts += s.Puts
		total.Conflicts += s.Conflicts
		total.Batches += s.Batches
		total.CommittedCommands += s.CommittedCommands
		total.Forwarded += s.Forwarded
		total.Takeovers += s.Takeovers
		total.Rejected += s.Rejected
	}
	return total
}

// An operator-local file supplies explicit, temporary credentials. Production
// CDS still reads no host credential chain. Each case uses a random DEK and
// unique prefix; there is no bucket-wide write, delete, cleanup or production IO.
func externalComparisonStore(t *testing.T, file string) *objectFixture {
	t.Helper()
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal("read S3 comparison settings:", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("S3 comparison settings must have mode 0600")
	}
	body, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	var input struct {
		Bucket      string                `json:"bucket"`
		Region      string                `json:"region"`
		Prefix      string                `json:"prefix"`
		Credentials objectwal.Credentials `json:"credentials"`
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		t.Fatal("invalid S3 comparison settings")
	}
	if input.Bucket == "" || input.Region == "" || input.Prefix == "" || input.Credentials.AccessKeyID == "" || input.Credentials.SecretAccessKey == "" {
		t.Fatal("incomplete S3 comparison settings")
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(key)
	f := &objectFixture{config: cdsconfig.ObjectWALPilot{Bucket: input.Bucket, Region: input.Region, Prefix: input.Prefix + "/" + hex.EncodeToString(hash[:8]), KeySHA256: hex.EncodeToString(hash[:])}}
	f.provision, err = json.Marshal(cdsobject.Provision{Key: key, Credentials: input.Credentials})
	clear(key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { clear(f.provision) })
	return f
}
