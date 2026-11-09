package cdscurrent_test

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anishathalye/porcupine"
	"github.com/confidential-dot-ai/c8s/internal/casregister"
	"github.com/confidential-dot-ai/c8s/internal/cdscurrent"
)

type lostReplyPeer struct {
	casregister.Peer
	drop     *atomic.Bool
	accepted *atomic.Int64
}

func (p lostReplyPeer) Accept(
	ctx context.Context,
	cluster string,
	ballot casregister.Ballot,
	value []byte,
) error {
	if err := p.Peer.Accept(
		ctx,
		cluster,
		ballot,
		value,
	); err != nil {
		return err
	}
	if p.drop.Load() {
		p.accepted.Add(1)
		return context.DeadlineExceeded
	}
	return nil
}

func TestUnknownAcceptanceDoesNotReapplyAnOperatorMutation(t *testing.T) {
	f := newFixture(
		t,
		testCluster,
	)
	var drop atomic.Bool
	var accepted atomic.Int64
	peers := f.peers()
	for i, peer := range peers {
		peers[i] = lostReplyPeer{
			Peer:     peer,
			drop:     &drop,
			accepted: &accepted,
		}
	}
	r := f.replica(
		testCluster,
		peers,
	)
	if err := r.Bootstrap(t.Context()); err != nil {
		t.Fatal(err)
	}
	body := policy(
		t,
		"reply-was-lost",
		false,
	)
	auth := f.authorization(
		"/allowlist",
		body,
	)
	drop.Store(true)
	w := request(
		r,
		http.MethodPut,
		"/allowlist",
		body,
		auth,
		"",
	)
	requireStatus(
		t,
		w,
		http.StatusServiceUnavailable,
	)
	if w.Header().Get("X-CDS-Outcome") != "unknown" {
		t.Fatal("possible acceptance was reported as a definite failure")
	}
	f.loseCompute()
	if n := accepted.Load(); n < 2 || n > 3 {
		t.Fatalf(
			"accepted %d times; want one phase-two dispatch to three members",
			n,
		)
	}
	drop.Store(false)
	replacement := f.start(
		testCluster,
		false,
	)
	w = request(
		replacement[1],
		http.MethodGet,
		"/allowlist",
		nil,
		"",
		"",
	)
	requireStatus(
		t,
		w,
		http.StatusOK,
	)
	marker, err := policyMarker(w.Body.Bytes())
	if err != nil || marker != "reply-was-lost" {
		t.Fatalf(
			"lost successful acceptance was not recovered: %q, %v",
			marker,
			err,
		)
	}
	assertLiveToken(
		t,
		f,
		"/allowlist",
		body,
		auth,
	)
	requireStatus(
		t,
		request(
			replacement[2],
			http.MethodPut,
			"/allowlist",
			body,
			auth,
			"",
		),
		http.StatusConflict,
	)
}

type historyInput struct {
	cluster string
	write   bool
	marker  string
}

type pausedClusterPeer struct {
	casregister.Peer
	paused  *atomic.Bool
	entered chan<- struct{}
	release <-chan struct{}
}

func (p pausedClusterPeer) Prepare(
	ctx context.Context,
	cluster string,
	ballot casregister.Ballot,
) (casregister.Promise, error) {
	if p.paused.Load() && cluster == "blocked-cluster" {
		select {
		case p.entered <- struct{}{}:
		default:
		}
		select {
		case <-p.release:
		case <-ctx.Done():
			return casregister.Promise{}, ctx.Err()
		}
	}
	return p.Peer.Prepare(
		ctx,
		cluster,
		ballot,
	)
}

func TestClusterBackpressureDoesNotBlockAnotherCluster(t *testing.T) {
	f := newFixture(
		t,
		"blocked-cluster",
		"available-cluster",
	)
	config := f.policies["blocked-cluster"]
	config.QueueSize = 1
	f.policies["blocked-cluster"] = config
	var paused atomic.Bool
	entered := make(
		chan struct{},
		3,
	)
	release := make(chan struct{})
	var resume sync.Once
	defer resume.Do(func() { close(release) })
	peers := f.peers()
	for i, peer := range peers {
		peers[i] = pausedClusterPeer{
			Peer:    peer,
			paused:  &paused,
			entered: entered,
			release: release,
		}
	}
	blocked := f.replica(
		"blocked-cluster",
		peers,
	)
	available := f.replica(
		"available-cluster",
		peers,
	)
	for _, replica := range []*cdscurrent.Replica{
		blocked,
		available,
	} {
		if err := replica.Bootstrap(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	body := policy(
		t,
		"accepted-once",
		false,
	)
	auth := f.authorization(
		"/allowlist",
		body,
	)
	first := make(
		chan *httptest.ResponseRecorder,
		1,
	)
	paused.Store(true)
	go func() {
		first <- request(
			blocked,
			http.MethodPut,
			"/allowlist",
			body,
			auth,
			"",
		)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first request never reached the paused authority")
	}
	overload := request(
		blocked,
		http.MethodGet,
		"/allowlist",
		nil,
		"",
		"",
	)
	requireStatus(
		t,
		overload,
		http.StatusServiceUnavailable,
	)
	if overload.Header().Get("X-CDS-Outcome") == "unknown" {
		t.Fatal("admission rejection must have no possible effect")
	}
	// The identical token can be spent independently in another cluster.
	requireStatus(
		t,
		request(
			available,
			http.MethodPut,
			"/allowlist",
			body,
			auth,
			"",
		),
		http.StatusNoContent,
	)
	requireStatus(
		t,
		request(
			available,
			http.MethodGet,
			"/allowlist",
			nil,
			"",
			"",
		),
		http.StatusOK,
	)
	resume.Do(func() { close(release) })
	select {
	case response := <-first:
		requireStatus(
			t,
			response,
			http.StatusNoContent,
		)
	case <-time.After(5 * time.Second):
		t.Fatal("admitted request did not finish after authority resumed")
	}
}

type historyOutput struct {
	status  int
	marker  string
	unknown bool
}

// Unknown writes stay pending and may either have changed the register or have
// had no effect. Modeling every timeout as a definite failure hides lost replies.
func registerModel() porcupine.Model {
	nondeterministic := porcupine.NondeterministicModel{
		Init: func() []any { return []any{"seed"} },
		Step: func(
			state any,
			input any,
			output any,
		) []any {
			in, out := input.(historyInput), output.(historyOutput)
			if out.status == http.StatusServiceUnavailable {
				if in.write && out.unknown {
					return []any{
						state,
						in.marker,
					}
				}
				return []any{state}
			}
			if in.write {
				if out.status != http.StatusNoContent {
					return nil
				}
				return []any{in.marker}
			}
			if out.status != http.StatusOK || out.marker != state.(string) {
				return nil
			}
			return []any{state}
		},
		Equal: func(
			a any,
			b any,
		) bool {
			return a.(string) == b.(string)
		},
		DescribeOperation: func(
			input any,
			output any,
		) string {
			return fmt.Sprintf(
				"%+v → %+v",
				input,
				output,
			)
		},
	}
	model := nondeterministic.ToModel()
	model.Partition = func(history []porcupine.Operation) [][]porcupine.Operation {
		partitions := make(map[string][]porcupine.Operation)
		for _, op := range history {
			cluster := op.Input.(historyInput).cluster
			partitions[cluster] = append(
				partitions[cluster],
				op,
			)
		}
		result := make(
			[][]porcupine.Operation,
			0,
			len(partitions),
		)
		for _, partition := range partitions {
			result = append(
				result,
				partition,
			)
		}
		return result
	}
	return model
}

func TestThreeClientsRemainLinearizableAcrossReplicaLoss(t *testing.T) {
	for _, independent := range []bool{
		false,
		true,
	} {
		name := "one-contended-policy"
		clusters := []string{testCluster}
		if independent {
			name, clusters = "independent-clusters", []string{
				"cluster-0",
				"cluster-1",
				"cluster-2",
			}
		}
		t.Run(
			name,
			func(t *testing.T) {
				f := newFixture(
					t,
					clusters...,
				)
				replicas := make(map[string][]*cdscurrent.Replica)
				for _, cluster := range clusters {
					replicas[cluster] = f.start(
						cluster,
						true,
					)
					body := policy(
						t,
						"seed",
						false,
					)
					requireStatus(
						t,
						request(
							replicas[cluster][0],
							http.MethodPut,
							"/allowlist",
							body,
							f.authorization(
								"/allowlist",
								body,
							),
							"",
						),
						http.StatusNoContent,
					)
				}
				type write struct {
					body   []byte
					auth   string
					marker string
				}
				var writes [3][6]write
				for client := range writes {
					for step := range writes[client] {
						marker := fmt.Sprintf(
							"client-%d-step-%d",
							client,
							step,
						)
						body := policy(
							t,
							marker,
							false,
						)
						writes[client][step] = write{
							body: body,
							auth: f.authorization(
								"/allowlist",
								body,
							),
							marker: marker,
						}
					}
				}
				var histories [3][]porcupine.Operation
				var successes [3][2]int
				var lost atomic.Bool
				var workers sync.WaitGroup
				start := make(chan struct{})
				failures := make(
					chan error,
					3,
				)
				epoch := time.Now()
				for client := range 3 {
					workers.Add(1)
					go func() {
						defer workers.Done()
						<-start
						cluster := clusters[0]
						if independent {
							cluster = clusters[client]
						}
						for step, update := range writes[client] {
							if client == 0 && step == 2 {
								lost.Store(true)
								for _, endpoints := range replicas {
									endpoints[0].Close()
								}
							}
							for _, write := range []bool{
								true,
								false,
							} {
								index := (client + step) % 3
								if lost.Load() {
									index = 1 + (client+step)%2
								}
								method, body, auth := http.MethodGet, []byte(nil), ""
								if write {
									method, body, auth = http.MethodPut, update.body, update.auth
								}
								call := time.Since(epoch).Nanoseconds()
								response := request(
									replicas[cluster][index],
									method,
									"/allowlist",
									body,
									auth,
									"",
								)
								returned := time.Since(epoch).Nanoseconds()
								out := historyOutput{
									status:  response.Code,
									unknown: response.Header().Get("X-CDS-Outcome") == "unknown",
								}
								if !write && response.Code == http.StatusOK {
									var err error
									out.marker, err = policyMarker(response.Body.Bytes())
									if err != nil {
										failures <- err
										return
									}
									successes[client][0]++
								} else if write && response.Code == http.StatusNoContent {
									successes[client][1]++
								} else if response.Code != http.StatusServiceUnavailable {
									failures <- fmt.Errorf(
										"client %d unexpected HTTP %d: %s",
										client,
										response.Code,
										response.Body.String(),
									)
									return
								}
								if write && out.unknown {
									returned = math.MaxInt64
								}
								histories[client] = append(
									histories[client],
									porcupine.Operation{
										ClientId: client,
										Input: historyInput{
											cluster: cluster,
											write:   write,
											marker:  update.marker,
										},
										Call:   call,
										Output: out,
										Return: returned,
									},
								)
							}
						}
					}()
				}
				close(start)
				workers.Wait()
				close(failures)
				for err := range failures {
					t.Error(err)
				}
				var history []porcupine.Operation
				for client, operations := range histories {
					if successes[client][0] == 0 || successes[client][1] == 0 {
						t.Errorf(
							"client %d lacked successful reads or writes: %v",
							client,
							successes[client],
						)
					}
					history = append(
						history,
						operations...,
					)
				}
				// One failed authority still leaves the original majority available.
				if err := f.authorities[0].Close(); err != nil {
					t.Fatal(err)
				}
				for _, cluster := range clusters {
					call := time.Since(epoch).Nanoseconds()
					response := request(
						replicas[cluster][2],
						http.MethodGet,
						"/allowlist",
						nil,
						"",
						"",
					)
					returned := time.Since(epoch).Nanoseconds()
					requireStatus(
						t,
						response,
						http.StatusOK,
					)
					marker, err := policyMarker(response.Body.Bytes())
					if err != nil {
						t.Fatal(err)
					}
					history = append(
						history,
						porcupine.Operation{
							ClientId: 3,
							Input:    historyInput{cluster: cluster},
							Call:     call,
							Output: historyOutput{
								status: http.StatusOK,
								marker: marker,
							},
							Return: returned,
						},
					)
				}
				model := registerModel()
				result, info := porcupine.CheckOperationsVerbose(
					model,
					history,
					10*time.Second,
				)
				if result != porcupine.Ok {
					path := filepath.Join(
						t.TempDir(),
						"allowlist-history.html",
					)
					if err := porcupine.VisualizePath(
						model,
						info,
						path,
					); err != nil {
						t.Logf(
							"visualization: %v",
							err,
						)
					}
					t.Fatalf(
						"history is %s; visualization: %s",
						result,
						path,
					)
				}
				t.Logf(
					"checked %d real-handler operations; client read/write successes %v",
					len(history),
					successes,
				)
			},
		)
	}
}
