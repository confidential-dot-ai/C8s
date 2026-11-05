//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type transactionalResult struct {
	comparisonResult
	Runtime                *scaleRuntime `json:"runtime,omitempty"`
	Workload               string        `json:"workload"`
	Repeat                 int           `json:"repeat"`
	MetadataLatencyMS      int           `json:"metadata_added_request_latency_ms"`
	P95AllMS               float64       `json:"p95_all_outcomes_ms"`
	ObjectGets             uint64        `json:"object_gets"`
	ObjectPuts             uint64        `json:"object_puts"`
	MetadataReads          uint64        `json:"metadata_reads"`
	MetadataWrites         uint64        `json:"metadata_writes"`
	MetadataCommits        uint64        `json:"metadata_commits"`
	MetadataConflicts      uint64        `json:"metadata_conflicts"`
	ReplayChecks           int           `json:"replay_checks"`
	SurvivedProcessLoss    bool          `json:"survived_process_loss"`
	RevocationVerified     bool          `json:"revocation_verified"`
	RevocationMS           float64       `json:"revocation_ms"`
	StaleReleaseReads      int           `json:"stale_release_reads"`
	RevocationContract     string        `json:"revocation_contract"`
	RecoveryErrors         map[int]int   `json:"recovery_errors"`
	SlowestRecoveryProbeMS float64       `json:"slowest_recovery_probe_ms"`
	FailoverReadyMS        float64       `json:"failover_ready_ms"`
}

type comparisonWrite struct {
	path          string
	body          []byte
	authorization string
	expected      int
}

// This comparison preserves one total order in ALL arms. Independent business
// keys do not mean the metadata variant implements per-key log partitioning.
// Timed load never retries; replay probes run only for acknowledged successes.
func TestTransactionalComparison(t *testing.T) {
	if os.Getenv("CDSHA_TRANSACTIONAL_COMPARE") != "1" {
		t.Skip("set CDSHA_TRANSACTIONAL_COMPARE=1")
	}
	if !releaseProcesses {
		t.Fatal("comparison requires CDSHA_RELEASE=1")
	}
	n := comparisonInt(t, "CDSHA_COMPARE_REQUESTS", 96, 1, 10000)
	repeats := comparisonInt(t, "CDSHA_COMPARE_REPEATS", 3, 1, 20)
	concurrencies := comparisonInts(t, "CDSHA_COMPARE_CONCURRENCY", []int{1, 16}, 1, 256)
	delays := comparisonInts(t, "CDSHA_COMPARE_LATENCY_MS", []int{0, 25}, 0, 1000)
	metadataDelay := comparisonInt(t, "CDSHA_COMPARE_METADATA_LATENCY_MS", 0, 0, 1000)
	backends := []string{"raft", "object-batch-preferred", "metadata-batch-preferred"}
	if list := os.Getenv("CDSHA_COMPARE_BACKENDS"); list != "" {
		backends = strings.Split(list, ",")
	}
	for _, b := range backends {
		if !slices.Contains([]string{"raft", "object-batch-direct", "object-batch-preferred", "metadata-batch-direct", "metadata-batch-preferred"}, b) {
			t.Fatalf("unknown backend %q", b)
		}
	}
	var results []transactionalResult
	// Cleanup persists partial results even if one cell fails before load.
	t.Cleanup(func() {
		if file := os.Getenv("CDSHA_COMPARE_OUTPUT"); file != "" {
			body, err := json.MarshalIndent(results, "", "  ")
			if err != nil {
				t.Error(err)
				return
			}
			if err := os.WriteFile(file, append(body, '\n'), 0600); err != nil {
				t.Error(err)
			}
		}
	})
	for _, workload := range []string{"independent-secrets", "single-policy"} {
		for repeat := 1; repeat <= repeats; repeat++ {
			// Rotate the order across repetitions to reduce fixed-order bias.
			for b := range backends {
				backend := backends[(b+repeat-1)%len(backends)]
				storageDelays := delays
				if backend == "raft" || os.Getenv("CDSHA_COMPARE_S3_FILE") != "" {
					storageDelays = []int{0}
				}
				for _, delay := range storageDelays {
					for _, concurrency := range concurrencies {
						name := fmt.Sprintf("%s/%s/%dms/c%d/r%d", workload, backend, delay, concurrency, repeat)
						t.Run(name, func(t *testing.T) {
							r := transactionalResult{comparisonResult: comparisonResult{Backend: backend, Storage: "loopback", AddedRequestLatencyMS: delay, Concurrency: concurrency, Requests: n, Failures: map[int]int{}}, Workload: workload, Repeat: repeat, RevocationContract: "immediate-after-acknowledgement"}
							stage := "bootstrap"
							t.Cleanup(func() {
								if t.Failed() && r.FailedStage == "" {
									r.FailedStage = stage
								}
								results = append(results, r)
								body, _ := json.Marshal(r)
								t.Log(string(body))
							})
							var f *objectFixture
							if backend != "raft" {
								if file := os.Getenv("CDSHA_COMPARE_S3_FILE"); file != "" {
									f = externalComparisonStore(t, file)
									r.Storage = "s3"
								} else {
									f = newObjectFixture(t)
								}
								f.config.DirectWriters = strings.HasSuffix(backend, "-direct")
								if strings.HasPrefix(backend, "metadata-") {
									attachMetadata(t, f)
									r.MetadataLatencyMS = metadataDelay
								}
							}
							listener, host := inventoryListener(t)
							nodes := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` + seededNodeImage.mrtd + `"}]}`
							c := newClusterWithNodes(t, threeReplicas, f, nodes, []string{host + "/32"})
							w := startPilotWorkload(c, listener, host)
							if f == nil {
								c.waitRollSafe(time.Minute)
							}
							c.replaceAllowlist(c.replicas[0], "transactional-comparison-warmup")
							w.setPolicy(true)
							c.waitFor("initial workload policy on all replicas", time.Minute, func() bool { return c.allServe("pilot-workload") })
							w.issue(c.replicas[0], c.replicas[1])
							originalCA := c.servedCA(c.replicas[0])
							sentinel := jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString([]byte("load-test-sentinel"))})
							if code, _ := c.put(c.replicas[0], "/secrets/pilot/comparison-sentinel", sentinel); code != http.StatusCreated {
								t.Fatalf("sentinel create: HTTP %d", code)
							}
							// Keep replay probes inside the server's existing five-minute
							// validity bound even when injected latency slows failover.
							comparisonSigner := c.signer.WithTTL(operatorauth.MaxTokenValidity)
							requests := make([]comparisonWrite, n)
							for i := range requests {
								request := comparisonWrite{path: "/allowlist", body: allowlistDocument(fmt.Sprintf("policy-%d", i)), expected: http.StatusNoContent}
								if workload == "independent-secrets" {
									request.path = fmt.Sprintf("/secrets/pilot/comparison-%d", i)
									request.body = jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("synthetic-secret-%d", i)))})
									request.expected = http.StatusCreated
								}
								var err error
								request.authorization, err = comparisonSigner.Authorization(http.MethodPut, request.path, request.body)
								if err != nil {
									t.Fatal(err)
								}
								requests[i] = request
							}
							if f != nil {
								f.delayNS.Store(int64(time.Duration(delay) * time.Millisecond))
								if f.metadata != nil {
									f.metadata.delayNS.Store(int64(time.Duration(metadataDelay) * time.Millisecond))
								}
							}
							before := c.comparisonStats()
							var metaBefore metadatapilot.Stats
							var objectGets, objectPuts uint64
							if f != nil {
								objectGets, objectPuts = f.gets.Load(), f.puts.Load()
								if f.metadata != nil {
									metaBefore = f.metadata.stats()
								}
							}
							stage = "load"
							type answer struct {
								index, code int
								elapsed     time.Duration
							}
							jobs := make(chan int, n)
							answers := make(chan answer, n)
							for i := range n {
								jobs <- i
							}
							close(jobs)
							gate := make(chan struct{})
							var workers sync.WaitGroup
							for range concurrency {
								workers.Go(func() {
									<-gate
									for i := range jobs {
										start := time.Now()
										code, _ := c.sendComparisonWrite(c.replicas[i%3], requests[i])
										answers <- answer{i, code, time.Since(start)}
									}
								})
							}
							start := time.Now()
							r.Attempted = n
							close(gate)
							workers.Wait()
							r.Seconds = time.Since(start).Seconds()
							close(answers)
							var successLatencies, allLatencies []time.Duration
							var acknowledged []int
							for answer := range answers {
								allLatencies = append(allLatencies, answer.elapsed)
								if answer.code == requests[answer.index].expected {
									r.Succeeded++
									acknowledged = append(acknowledged, answer.index)
									successLatencies = append(successLatencies, answer.elapsed)
								} else {
									r.Failures[answer.code]++
								}
							}
							r.RequestsPerSecond = float64(r.Succeeded) / r.Seconds
							slices.Sort(successLatencies)
							slices.Sort(allLatencies)
							if len(successLatencies) > 0 {
								r.P50MS = percentile(successLatencies, 50)
								r.P95MS = percentile(successLatencies, 95)
								r.P99MS = percentile(successLatencies, 99)
							}
							r.P95AllMS = percentile(allLatencies, 95)
							if r.Succeeded != r.Attempted {
								r.FailedStage = "load"
								t.Errorf("timed writes: %d/%d succeeded; failures=%v", r.Succeeded, r.Attempted, r.Failures)
							}
							after := c.comparisonStats()
							r.Gets = after.Gets - before.Gets
							r.Puts = after.Puts - before.Puts
							r.Conflicts = after.Conflicts - before.Conflicts
							r.Batches = after.Batches - before.Batches
							r.Commands = after.CommittedCommands - before.CommittedCommands
							r.Forwarded = after.Forwarded - before.Forwarded
							r.Takeovers = after.Takeovers - before.Takeovers
							r.Rejected = after.Rejected - before.Rejected
							if f != nil {
								if r.Storage == "loopback" {
									r.ObjectGets = f.gets.Load() - objectGets
									r.ObjectPuts = f.puts.Load() - objectPuts
								}
								if f.metadata != nil {
									after := f.metadata.stats()
									r.MetadataReads = after.Reads - metaBefore.Reads
									r.MetadataWrites = after.Writes - metaBefore.Writes
									r.MetadataCommits = after.Commits - metaBefore.Commits
									r.MetadataConflicts = after.Conflicts - metaBefore.Conflicts
								}
							}
							r.Runtime = c.scaleRuntime()
							if f != nil && f.config.AtomicOperatorWrites && r.Succeeded == n && r.Commands != uint64(n) {
								t.Errorf("atomic operator load committed %d commands for %d requests", r.Commands, n)
							}
							stage = "recovery"
							// Latency settings stay active for convergence, replay and failover.
							c.waitServing(time.Minute)
							if r.Succeeded == 0 {
								t.Fatal("no successful operations to verify")
							}
							for _, i := range acknowledged {
								code, body := c.sendComparisonWrite(c.replicas[(i+1)%3], requests[i])
								if code != http.StatusConflict || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
									t.Fatalf("acknowledged token replay %d: HTTP %d %s", i, code, body)
								}
								r.ReplayChecks++
							}
							// Kill the current writer, then verify acknowledged state on survivors.
							lost := c.replicas[0]
							if f == nil {
								c.waitRollSafe(time.Minute)
								lost = c.waitLeader(30 * time.Second)
							} else if !f.config.DirectWriters {
								lost = c.preferredComparisonWriter()
							}
							failedAt := time.Now()
							c.kill(lost)
							if f == nil {
								c.waitLeader(30 * time.Second)
							}
							survivors := c.others(lost)
							c.waitFor("both survivors ready after process loss", 30*time.Second, func() bool { return len(c.serving()) == 2 })
							c.replaceAllowlist(survivors[0], "after-load-failover")
							r.FailoverReadyMS = float64(time.Since(failedAt)) / float64(time.Millisecond)
							for position, i := range acknowledged {
								code, body := c.safeRecoveryProbe(&r, func() (int, []byte) { return c.sendComparisonWrite(survivors[position%len(survivors)], requests[i]) })
								if code != http.StatusConflict || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
									t.Fatalf("replay after writer loss %d: HTTP %d %s", i, code, body)
								}
								if workload == "independent-secrets" {
									// PutIfAbsent on a known acknowledged path is an idempotent
									// verification probe; it never overwrites a secret.
									if code, _ := c.safeRecoveryProbe(&r, func() (int, []byte) {
										return c.put(survivors[position%len(survivors)], requests[i].path, requests[i].body)
									}); code != http.StatusConflict {
										t.Fatalf("acknowledged secret verification after writer loss: %d HTTP %d", i, code)
									}
								}
							}
							c.measureRestart(lost, r.Runtime, originalCA)
							r.SurvivedProcessLoss = true
							stage = "release-and-revocation"
							w.setPolicy(true)
							c.waitFor("restored workload policy on all replicas", time.Minute, func() bool { return c.allServe("pilot-workload") })
							w.assertEveryReplicaReads("/pilot/comparison-sentinel", []byte("load-test-sentinel"))
							if workload == "independent-secrets" {
								for _, i := range acknowledged {
									w.assertReads(c.replicas[i%3], strings.TrimPrefix(requests[i].path, "/secrets"), []byte(fmt.Sprintf("synthetic-secret-%d", i)))
								}
							}
							w.setPolicy(false)
							revokedAt := time.Now()
							for _, replica := range c.replicas {
								// Identical acceptance rule for every arm, including Raft:
								// no successful release started after revocation acknowledgement.
								code, _ := pilotDo(t, w.client, w.secretRequest(replica, http.MethodGet, "/pilot/comparison-sentinel"))
								if code == http.StatusOK {
									r.StaleReleaseReads++
								}
								if code != http.StatusForbidden {
									t.Fatalf("immediate revocation contract violated on replica %d: HTTP %d", replica.index, code)
								}
							}
							r.RevocationMS = float64(time.Since(revokedAt)) / float64(time.Millisecond)
							r.RevocationVerified = true
						})
					}
				}
			}
		}
	}
}

// Only replay of already-spent tokens and conditional create on an acknowledged
// path use this retry helper. It is never used by the measured business load.
// 503/transport errors are availability observations, not proof of data loss.
func (c *cluster) safeRecoveryProbe(result *transactionalResult, probe func() (int, []byte)) (int, []byte) {
	started := time.Now()
	defer func() {
		result.SlowestRecoveryProbeMS = max(result.SlowestRecoveryProbeMS, float64(time.Since(started))/float64(time.Millisecond))
	}()
	for {
		code, body := probe()
		if code != http.StatusServiceUnavailable && code != noAnswer {
			return code, body
		}
		if result.RecoveryErrors == nil {
			result.RecoveryErrors = map[int]int{}
		}
		result.RecoveryErrors[code]++
		if time.Since(started) >= 30*time.Second {
			c.t.Fatalf("safe recovery probe remained unavailable for 30 seconds: HTTP %d", code)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (c *cluster) preferredComparisonWriter() *replica {
	c.t.Helper()
	var owner objectwal.Owner
	for _, replica := range c.replicas {
		code, body := c.get(replica, "/ha/object-wal/status")
		var stats objectwal.Stats
		if code != http.StatusOK || json.Unmarshal(body, &stats) != nil {
			c.t.Fatal("cannot locate preferred writer")
		}
		if stats.Writer.Epoch > owner.Epoch {
			owner = stats.Writer
		}
	}
	for _, replica := range c.replicas {
		if c.awaitStatus(replica).ID == owner.ID {
			return replica
		}
	}
	c.t.Fatal("preferred writer is not a live CDS process")
	return nil
}

func (c *cluster) sendComparisonWrite(replica *replica, request comparisonWrite) (int, []byte) {
	r, err := http.NewRequest(http.MethodPut, replica.base+request.path, bytes.NewReader(request.body))
	if err != nil {
		c.t.Fatal(err)
	}
	r.GetBody = nil
	r.Header.Set("Authorization", request.authorization)
	response, err := c.client.Do(r)
	if err != nil {
		return noAnswer, nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxAnswer))
	if err != nil {
		return noAnswer, nil
	}
	return response.StatusCode, body
}
