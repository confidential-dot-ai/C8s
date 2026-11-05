//go:build integration && linux

package cdsha_test

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type certificateBurstResult struct {
	Round     int     `json:"round"`
	Completed int     `json:"completed"`
	Seconds   float64 `json:"seconds"`
	P95MS     float64 `json:"p95_ms"`
	P99MS     float64 `json:"p99_ms"`
}

type scaleResult struct {
	transactionalResult
	Cluster                        string                   `json:"cluster"`
	ConcurrentClusters             int                      `json:"concurrent_clusters"`
	CrossClusterCredentialRejected bool                     `json:"cross_cluster_credential_rejected"`
	MetadataCredentialIsolation    bool                     `json:"metadata_credential_isolation"`
	ChecksComplete                 bool                     `json:"checks_complete"`
	CertificateBursts              []certificateBurstResult `json:"certificate_and_release_bursts"`
}

// Every cluster has its own launch, CA, signer, encryption key, history and
// admission actors. Metadata clusters share ONE Fleet service process, with a
// database and admission budget per namespace. All arms run the same binary.
// Synthetic object latency is outside shard locks; this is not a cloud/storage
// durability benchmark. No measured operation is retried.
func TestStorageScaleComparison(t *testing.T) {
	if os.Getenv("CDSHA_SCALE_COMPARE") != "1" {
		t.Skip("set CDSHA_SCALE_COMPARE=1")
	}
	if !releaseProcesses {
		t.Fatal("comparison requires CDSHA_RELEASE=1")
	}
	count := comparisonInt(t, "CDSHA_SCALE_CLUSTERS", 4, 2, 16)
	perCluster := comparisonInt(t, "CDSHA_SCALE_REQUESTS_PER_CLUSTER", 16, 1, 256)
	concurrency := comparisonInt(t, "CDSHA_SCALE_CONCURRENCY", 16, 1, 256)
	burstSize := comparisonInt(t, "CDSHA_SCALE_CERTIFICATE_BURST", 12, 1, 64)
	delays := comparisonInts(t, "CDSHA_COMPARE_LATENCY_MS", []int{0, 100}, 0, 1000)
	metadataDelay := comparisonInt(t, "CDSHA_COMPARE_METADATA_LATENCY_MS", 2, 0, 1000)
	backends := []string{"raft", "object-batch-preferred", "metadata-batch-preferred"}
	if value := os.Getenv("CDSHA_COMPARE_BACKENDS"); value != "" {
		backends = strings.Split(value, ",")
	}
	var results []scaleResult
	t.Cleanup(func() {
		if file := os.Getenv("CDSHA_SCALE_OUTPUT"); file != "" {
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
	for _, backend := range backends {
		if !slices.Contains([]string{"raft", "object-batch-preferred", "metadata-batch-preferred"}, backend) {
			t.Fatalf("unknown backend %q", backend)
		}
		storageDelays := delays
		if backend == "raft" {
			storageDelays = []int{0}
		}
		for _, delay := range storageDelays {
			t.Run(fmt.Sprintf("%s/%dms", backend, delay), func(t *testing.T) {
				rows := make([]scaleResult, count)
				stage := "bootstrap"
				t.Cleanup(func() {
					for i := range rows {
						if t.Failed() && !rows[i].ChecksComplete && rows[i].FailedStage == "" {
							rows[i].FailedStage = stage
						}
						results = append(results, rows[i])
						body, _ := json.Marshal(rows[i])
						t.Log(string(body))
					}
				})
				fixtures := make([]*objectFixture, count)
				if backend != "raft" {
					fixtures = scaleObjectFixtures(t, count)
					if strings.HasPrefix(backend, "metadata-") {
						scaleMetadataFleet(t, fixtures)
					}
				}
				// One privileged inventory endpoint can be bound on this host.
				// Load needs no inventory calls; security/issuance checks use each
				// cluster's separately pinned inventory server sequentially below.
				listener, host := inventoryListener(t)
				clusters := make([]*cluster, count)
				cas := make([]string, count)
				nodes := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"node","measurement":"` + seededNodeImage.mrtd + `"}]}`
				for i := range count {
					c := newClusterWithNodesAt(t, threeReplicas, fixtures[i], nodes, []string{host + "/32"}, fmt.Sprintf("scale-%d", i), i*4)
					clusters[i] = c
					if fixtures[i] == nil {
						c.waitRollSafe(time.Minute)
					}
					c.replaceAllowlist(c.replicas[0], "scale-warmup")
					cas[i] = c.servedCA(c.replicas[0])
					if slices.Contains(cas[:i], cas[i]) {
						t.Fatal("independent clusters unexpectedly share a CA")
					}
					value := []byte(fmt.Sprintf("sentinel-%s", c.id()))
					if code, _ := c.put(c.replicas[0], "/secrets/pilot/scale-sentinel", jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString(value)})); code != http.StatusCreated {
						t.Fatalf("sentinel: HTTP %d", code)
					}
					rows[i] = scaleResult{transactionalResult: transactionalResult{comparisonResult: comparisonResult{
						Backend: backend, Storage: "shared-loopback-fixture", AddedRequestLatencyMS: delay,
						Concurrency: concurrency, Requests: perCluster, Failures: map[int]int{}}, Workload: "independent-clusters", RevocationContract: "immediate-after-acknowledgement"},
						Cluster: c.id(), ConcurrentClusters: count}
				}
				stage = "credential-isolation"
				for i, c := range clusters {
					other := clusters[(i+1)%count]
					body := allowlistDocument("wrong-cluster")
					auth, err := other.signer.Authorization(http.MethodPut, "/allowlist", body)
					if err != nil {
						t.Fatal(err)
					}
					if code, _ := c.sendComparisonWrite(c.replicas[0], comparisonWrite{path: "/allowlist", body: body, authorization: auth}); code != http.StatusUnauthorized {
						t.Fatalf("foreign operator: HTTP %d", code)
					}
					rows[i].CrossClusterCredentialRejected = true
					if f := fixtures[i]; f != nil && f.metadata != nil {
						req, _ := http.NewRequest(http.MethodGet, f.metadata.endpoint+"/v1/stats", nil)
						req.Header.Set("X-CDS-Namespace", f.metadata.namespace)
						req.Header.Set("Authorization", "Bearer "+fixtures[(i+1)%count].metadata.token)
						res, err := f.metadata.client.Do(req)
						if err != nil {
							t.Fatal(err)
						}
						res.Body.Close()
						if res.StatusCode != http.StatusUnauthorized {
							t.Fatalf("foreign metadata token: HTTP %d", res.StatusCode)
						}
						rows[i].MetadataCredentialIsolation = true
					}
				}
				requests := make([][]comparisonWrite, count)
				minted := time.Now()
				for i, c := range clusters {
					requests[i] = make([]comparisonWrite, perCluster)
					for j := range perCluster {
						r := comparisonWrite{path: fmt.Sprintf("/secrets/pilot/scale-%d", j), expected: http.StatusCreated,
							body: jsonBody(t, secrets.PutRequest{Value: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s/value-%d", c.id(), j)))})}
						var err error
						r.authorization, err = c.signer.WithTTL(operatorauth.MaxTokenValidity).Authorization(http.MethodPut, r.path, r.body)
						if err != nil {
							t.Fatal(err)
						}
						requests[i][j] = r
					}
					if f := fixtures[i]; f != nil {
						f.delayNS.Store(int64(time.Duration(delay) * time.Millisecond))
						if f.metadata != nil {
							f.metadata.delayNS.Store(int64(time.Duration(metadataDelay) * time.Millisecond))
							rows[i].MetadataLatencyMS = metadataDelay
						}
					}
				}
				before := make([]scaleCounters, count)
				for i, c := range clusters {
					before[i] = readScaleCounters(c)
				}
				type answer struct {
					cluster, request, code int
					elapsed                time.Duration
				}
				jobs, answers := make(chan int, count*perCluster), make(chan answer, count*perCluster)
				for i := range count * perCluster {
					jobs <- i
				}
				close(jobs)
				gate := make(chan struct{})
				var workers sync.WaitGroup
				for range concurrency {
					workers.Go(func() {
						<-gate
						for job := range jobs {
							i, j := job%count, job/count
							start := time.Now()
							c := clusters[i]
							code, _ := c.sendComparisonWrite(c.replicas[j%3], requests[i][j])
							answers <- answer{i, j, code, time.Since(start)}
						}
					})
				}
				stage = "load"
				started := time.Now()
				close(gate)
				workers.Wait()
				elapsed := time.Since(started)
				close(answers)
				latencies, all := make([][]time.Duration, count), make([][]time.Duration, count)
				acked := make([][]int, count)
				for a := range answers {
					r := &rows[a.cluster]
					r.Attempted++
					all[a.cluster] = append(all[a.cluster], a.elapsed)
					if a.code == requests[a.cluster][a.request].expected {
						r.Succeeded++
						acked[a.cluster] = append(acked[a.cluster], a.request)
						latencies[a.cluster] = append(latencies[a.cluster], a.elapsed)
					} else {
						r.Failures[a.code]++
					}
				}
				for i, c := range clusters {
					r := &rows[i]
					r.Seconds = elapsed.Seconds()
					r.RequestsPerSecond = float64(r.Succeeded) / r.Seconds
					slices.Sort(latencies[i])
					slices.Sort(all[i])
					if len(latencies[i]) > 0 {
						r.P50MS = percentile(latencies[i], 50)
						r.P95MS = percentile(latencies[i], 95)
						r.P99MS = percentile(latencies[i], 99)
					}
					if len(all[i]) > 0 {
						r.P95AllMS = percentile(all[i], 95)
					}
					if r.Succeeded != perCluster {
						t.Errorf("%s: %d/%d succeeded: %v", c.id(), r.Succeeded, perCluster, r.Failures)
						r.FailedStage = "load"
					}
					applyScaleCounters(&r.transactionalResult, before[i], readScaleCounters(c))
					r.Runtime = c.scaleRuntime()
					if fixtures[i] != nil && fixtures[i].config.AtomicOperatorWrites && r.Succeeded == perCluster && r.Commands != uint64(perCluster) {
						t.Errorf("atomic operator cluster committed %d commands for %d requests", r.Commands, perCluster)
					}
				}
				stage = "recovery-and-revocation"
				for i, c := range clusters {
					r := &rows[i]
					w := startPilotWorkload(c, listener, host)
					w.setPolicy(true)
					c.waitFor("workload policy", time.Minute, func() bool { return c.allServe("pilot-workload") })
					w.issue(c.replicas[0], c.replicas[1])
					lost := c.replicas[0]
					if fixtures[i] == nil {
						c.waitRollSafe(time.Minute)
						lost = c.waitLeader(30 * time.Second)
					} else {
						lost = c.preferredComparisonWriter()
					}
					failedAt := time.Now()
					c.kill(lost)
					if fixtures[i] == nil {
						c.waitLeader(30 * time.Second)
					}
					survivors := c.others(lost)
					c.waitFor("two surviving replicas", 30*time.Second, func() bool { return len(c.serving()) == 2 })
					c.replaceAllowlist(survivors[0], "after-scale-failover")
					r.FailoverReadyMS = float64(time.Since(failedAt)) / float64(time.Millisecond)
					for _, j := range acked[i] {
						if time.Since(minted) >= operatorauth.MaxTokenValidity-5*time.Second {
							t.Fatal("replay proof would be outside the token validity window")
						}
						code, body := c.safeRecoveryProbe(&r.transactionalResult, func() (int, []byte) { return c.sendComparisonWrite(survivors[j%2], requests[i][j]) })
						if code != http.StatusConflict || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
							t.Fatalf("%s replay %d: HTTP %d %s", c.id(), j, code, body)
						}
						r.ReplayChecks++
					}
					c.measureRestart(lost, r.Runtime, cas[i])
					r.SurvivedProcessLoss = true
					w.setPolicy(true)
					c.waitFor("restored workload policy", time.Minute, func() bool { return c.allServe("pilot-workload") })
					w.assertEveryReplicaReads("/pilot/scale-sentinel", []byte(fmt.Sprintf("sentinel-%s", c.id())))
					for _, j := range acked[i] {
						w.assertReads(c.replicas[j%3], fmt.Sprintf("/pilot/scale-%d", j), []byte(fmt.Sprintf("%s/value-%d", c.id(), j)))
					}
					r.CertificateBursts = measureCertificateBursts(w, burstSize, []byte(fmt.Sprintf("sentinel-%s", c.id())))
					w.setPolicy(false)
					revokedAt := time.Now()
					for _, replica := range c.replicas {
						code, _ := pilotDo(t, w.client, w.secretRequest(replica, http.MethodGet, "/pilot/scale-sentinel"))
						if code == http.StatusOK {
							r.StaleReleaseReads++
						}
						if code != http.StatusForbidden {
							t.Fatalf("%s stale access after acknowledged revocation: HTTP %d", c.id(), code)
						}
					}
					r.RevocationMS = float64(time.Since(revokedAt)) / float64(time.Millisecond)
					r.RevocationVerified = true
					r.ChecksComplete = true
					listener.Close()
					if i+1 < count {
						var nextHost string
						listener, nextHost = inventoryListener(t)
						if nextHost != host {
							t.Fatal("inventory address changed")
						}
					}
				}
			})
		}
	}
}

type scaleCounters struct {
	gets, puts, conflicts, batches, commands, forwarded, takeovers, rejected uint64
	objectGets, objectPuts                                                   uint64
	metadata                                                                 metadatapilot.Stats
}

func readScaleCounters(c *cluster) scaleCounters {
	s := c.comparisonStats()
	r := scaleCounters{gets: s.Gets, puts: s.Puts, conflicts: s.Conflicts, batches: s.Batches, commands: s.CommittedCommands, forwarded: s.Forwarded, takeovers: s.Takeovers, rejected: s.Rejected}
	if f := c.objectWAL; f != nil {
		r.objectGets, r.objectPuts = f.gets.Load(), f.puts.Load()
		if f.metadata != nil {
			r.metadata = f.metadata.stats()
		}
	}
	return r
}

func applyScaleCounters(r *transactionalResult, a, b scaleCounters) {
	r.Gets = b.gets - a.gets
	r.Puts = b.puts - a.puts
	r.Conflicts = b.conflicts - a.conflicts
	r.Batches = b.batches - a.batches
	r.Commands = b.commands - a.commands
	r.Forwarded = b.forwarded - a.forwarded
	r.Takeovers = b.takeovers - a.takeovers
	r.Rejected = b.rejected - a.rejected
	r.ObjectGets = b.objectGets - a.objectGets
	r.ObjectPuts = b.objectPuts - a.objectPuts
	r.MetadataReads = b.metadata.Reads - a.metadata.Reads
	r.MetadataWrites = b.metadata.Writes - a.metadata.Writes
	r.MetadataCommits = b.metadata.Commits - a.metadata.Commits
	r.MetadataConflicts = b.metadata.Conflicts - a.metadata.Conflicts
}

// Measures the complete attested workload certificate + secret release flow.
// Round two uses the same worker keys for renewal. This does not exercise the
// separate managed-Kubernetes node-token enrollment API or native attestation.
func measureCertificateBursts(w *pilotWorkload, size int, sentinel []byte) []certificateBurstResult {
	t := w.c.t
	workers := make([]pilotWorkload, size)
	for i := range workers {
		workers[i] = *w
		workers[i].client = nil
		workers[i].key = newKey(t)
		csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, workers[i].key)
		if err != nil {
			t.Fatal(err)
		}
		workers[i].csr = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
	}
	var results []certificateBurstResult
	for round := range 2 {
		gate := make(chan struct{})
		answers := make(chan time.Duration, size)
		var wg sync.WaitGroup
		for i := range workers {
			wg.Go(func() {
				<-gate
				start := time.Now()
				workers[i].issue(w.c.replicas[i%3], w.c.replicas[(i+1)%3])
				workers[i].assertReads(w.c.replicas[(i+2)%3], "/pilot/scale-sentinel", sentinel)
				answers <- time.Since(start)
			})
		}
		start := time.Now()
		close(gate)
		wg.Wait()
		elapsed := time.Since(start)
		close(answers)
		var latencies []time.Duration
		for duration := range answers {
			latencies = append(latencies, duration)
		}
		if len(latencies) != size {
			t.Fatalf("certificate burst completed %d/%d", len(latencies), size)
		}
		slices.Sort(latencies)
		results = append(results, certificateBurstResult{Round: round + 1, Completed: len(latencies), Seconds: elapsed.Seconds(), P95MS: percentile(latencies, 95), P99MS: percentile(latencies, 99)})
	}
	return results
}
