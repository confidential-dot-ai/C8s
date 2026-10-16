package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

// The Lease API has 1 s granularity, so lease_duration cannot go lower.
var fastTiming = Timing{Heartbeat: 100 * time.Millisecond, LeaseDuration: time.Second, AckTimeout: 500 * time.Millisecond}

type node struct {
	r      *Replica
	cancel context.CancelFunc
	done   chan struct{}
}

type testCl struct {
	t     *testing.T
	kube  kubernetes.Interface
	port  int
	op    []byte
	mu    sync.Mutex
	nodes map[int]*node // index -> running replica on 127.0.0.<index+2>
	all   []int
	ever  []*Replica // every replica started, for mint counting
}

// rvClient is a fake clientset that enforces resourceVersion preconditions
// on Lease and ConfigMap updates, as the API server does. Without it every
// replica wins the Lease at once.
func rvClient() *fake.Clientset {
	c := fake.NewClientset()
	var mu sync.Mutex
	rv := 0
	for _, res := range []string{"leases", "configmaps"} {
		c.PrependReactor("create", res, func(a ktesting.Action) (bool, runtime.Object, error) {
			mu.Lock()
			defer mu.Unlock()
			obj := a.(ktesting.CreateAction).GetObject().DeepCopyObject()
			m, _ := meta.Accessor(obj)
			rv++
			m.SetResourceVersion(strconv.Itoa(rv))
			return true, obj, c.Tracker().Create(a.GetResource(), obj, a.GetNamespace())
		})
		c.PrependReactor("update", res, func(a ktesting.Action) (bool, runtime.Object, error) {
			mu.Lock()
			defer mu.Unlock()
			obj := a.(ktesting.UpdateAction).GetObject().DeepCopyObject()
			m, _ := meta.Accessor(obj)
			cur, err := c.Tracker().Get(a.GetResource(), a.GetNamespace(), m.GetName())
			if err != nil {
				return true, nil, err
			}
			cm, _ := meta.Accessor(cur)
			if m.GetResourceVersion() != cm.GetResourceVersion() {
				return true, nil, apierrors.NewConflict(a.GetResource().GroupResource(), m.GetName(), errors.New("resourceVersion mismatch"))
			}
			rv++
			m.SetResourceVersion(strconv.Itoa(rv))
			return true, obj, c.Tracker().Update(a.GetResource(), obj, a.GetNamespace())
		})
	}
	return c
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newTestCluster(t *testing.T, n int, op []byte) *testCl {
	c := &testCl{t: t, kube: rvClient(), port: freePort(t), op: op, nodes: map[int]*node{}}
	for i := range n {
		c.all = append(c.all, i)
	}
	t.Cleanup(func() {
		for i := range c.nodes {
			c.stop(i)
		}
	})
	return c
}

func (c *testCl) addr(i int) string { return fmt.Sprintf("127.0.0.%d:%d", i+2, c.port) }

func logger() *slog.Logger {
	if os.Getenv("CDSHA_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (c *testCl) start(i int, clusterID, measurement string) *Replica {
	c.t.Helper()
	return c.startWith(i, clusterID, measurement, c.kube, []string{"cds-v1"})
}

// startIsolated starts a replica whose peer discovery returns nobody.
func (c *testCl) startIsolated(i int, clusterID, measurement string) *Replica {
	c.t.Helper()
	return c.startPeers(i, clusterID, measurement, c.kube, []string{"cds-v1"}, func(context.Context) ([]string, error) { return nil, nil })
}

// startWith lets a test give a replica its own control plane, e.g. one that
// grants it the Lease regardless of the others (R1).
func (c *testCl) startWith(i int, clusterID, measurement string, kube kubernetes.Interface, baked []string) *Replica {
	c.t.Helper()
	return c.startPeers(i, clusterID, measurement, kube, baked, nil)
}

func (c *testCl) startPeers(i int, clusterID, measurement string, kube kubernetes.Interface, baked []string, peers func(context.Context) ([]string, error)) *Replica {
	c.t.Helper()
	self := c.addr(i)
	if peers == nil {
		peers = func(context.Context) ([]string, error) {
			c.mu.Lock()
			defer c.mu.Unlock()
			var out []string
			for _, j := range c.all {
				if a := c.addr(j); a != self {
					out = append(out, a)
				}
			}
			return out, nil
		}
	}
	r, err := New(Config{
		ClusterID:      clusterID,
		Identity:       fmt.Sprintf("replica-%d", i),
		ListenAddr:     self,
		Peers:          peers,
		Attestor:       testAttestor{measurement: measurement},
		BakedPins:      baked,
		OperatorPubKey: c.op,
		Kube:           kube,
		Namespace:      "c8s-system",
		CACommonName:   "test mesh CA",
		CAValidity:     time.Hour,
		Timing:         fastTiming,
		Logger:         logger().With("replica", i),
	})
	if err != nil {
		c.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	nd := &node{r: r, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(nd.done)
		if err := r.Run(ctx); err != nil {
			c.t.Errorf("replica %d: %v", i, err)
		}
	}()
	c.mu.Lock()
	c.nodes[i] = nd
	c.ever = append(c.ever, r)
	c.mu.Unlock()
	return r
}

func (c *testCl) stop(i int) {
	c.mu.Lock()
	nd := c.nodes[i]
	delete(c.nodes, i)
	c.mu.Unlock()
	if nd != nil {
		nd.cancel()
		<-nd.done
	}
}

func (c *testCl) running() []*Replica {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*Replica
	for _, nd := range c.nodes {
		out = append(out, nd.r)
	}
	return out
}

// waitConverged waits until every running replica serves the given epoch
// with one key fingerprint, and returns that fingerprint.
func (c *testCl) waitConverged(epoch uint64, within time.Duration) string {
	c.t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		fps := map[string]bool{}
		ok := true
		for _, r := range c.running() {
			hb := r.Heartbeat()
			if !hb.Serving || hb.Epoch != epoch {
				ok = false
				break
			}
			fps[hb.KeyFingerprint] = true
		}
		if ok && len(fps) == 1 {
			for fp := range fps {
				return fp
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, r := range c.running() {
		c.t.Logf("replica %s: %+v", r.cfg.Identity, r.Heartbeat())
	}
	c.t.Fatalf("replicas did not converge on epoch %d", epoch)
	return ""
}

// startCluster submits a Genesis decree signed with opKey.
func (c *testCl) startCluster(opKey *ecdsa.PrivateKey) SignedDecree {
	c.t.Helper()
	sd, err := SignDecree(Decree{ClusterID: testCluster, IntentID: "genesis", ExpiresAt: time.Now().Add(time.Minute), Kind: Genesis}, opKey)
	if err != nil {
		c.t.Fatal(err)
	}
	c.submit(sd)
	return sd
}

func (c *testCl) submit(sd SignedDecree) {
	c.t.Helper()
	cm, err := DecreeConfigMap("c8s-system", sd)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.kube.CoreV1().ConfigMaps("c8s-system").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testCl) decreeStatus(sd SignedDecree) string {
	cm, err := c.kube.CoreV1().ConfigMaps("c8s-system").Get(context.Background(), DecreeName(sd.Decree.ClusterID, sd.Decree.IntentID), metav1.GetOptions{})
	if err != nil {
		return ""
	}
	return cm.Data[keyStatus]
}

func TestClusterLifecycle(t *testing.T) {
	opKey, opPub := operatorKey(t)
	c := newTestCluster(t, 3, opPub)
	for i := range 3 {
		c.start(i, testCluster, "cds-v1")
	}
	// Nothing is minted without an operator Genesis decree.
	time.Sleep(10 * fastTiming.Heartbeat)
	if countGenesis(c) != 0 {
		t.Fatal("a key was minted without a Genesis decree")
	}
	g := c.startCluster(opKey)

	// Genesis: one key, every replica serves it (CI4, L5).
	fp0 := c.waitConverged(0, 10*time.Second)
	waitFor(t, func() bool { return c.decreeStatus(g) == `{"applied_epoch":0}` })
	if n := countGenesis(c); n != 1 {
		t.Fatalf("%d replicas minted a key, want 1", n)
	}
	if n := writerCount(c); n > 1 {
		t.Fatalf("%d simultaneous writers", n)
	}
	for _, r := range c.running() {
		ca, err := r.CA()
		if err != nil || heartbeatOf(State{Chain: Chain{{Record: Record{RootCert: ca.Cert.Raw}}}}, true, "").KeyFingerprint != fp0 {
			t.Fatalf("replica %s CA: %v", r.cfg.Identity, err)
		}
	}

	// UpdateMeasurements admits cds-v2: epoch 1, same key (D7).
	decree := func(id string, base uint64, kind DecreeKind, pins ...string) SignedDecree {
		sd, err := SignDecree(Decree{ClusterID: testCluster, IntentID: id, BaseEpoch: base, ExpiresAt: time.Now().Add(time.Minute), Kind: kind, Measurements: pins}, opKey)
		if err != nil {
			t.Fatal(err)
		}
		return sd
	}
	c.submit(decree("add-v2", 0, UpdateMeasurements, "cds-v1", "cds-v2"))
	if fp := c.waitConverged(1, 10*time.Second); fp != fp0 {
		t.Fatal("UpdateMeasurements changed the key")
	}

	// A replayed decree is rejected (D3).
	c.submit(decree("stale", 0, UpdateMeasurements, "evil"))
	waitFor(t, func() bool { return c.decreeStatus(decree("stale", 0, UpdateMeasurements)) != "" })

	// Kill the writer: a new writer takes over and applies the next decree.
	w := writerIndex(c)
	c.stop(w)
	c.submit(decree("add-v3", 1, UpdateMeasurements, "cds-v1", "cds-v2", "cds-v3"))
	c.waitConverged(2, 15*time.Second)

	// The old writer restarts empty and syncs the chain and key from peers (L1, K4).
	c.start(w, testCluster, "cds-v1")
	if fp := c.waitConverged(2, 10*time.Second); fp != fp0 {
		t.Fatal("restarted replica serves a different key")
	}

	// D13: add a cds-v2 replica, remove cds-v1 from the pins, then rotate.
	c.mu.Lock()
	c.all = append(c.all, 3)
	c.mu.Unlock()
	v2 := c.start(3, testCluster, "cds-v2")
	c.waitConverged(2, 10*time.Second)
	// A RotateKey bundling a set that excludes a cds-v1 writer is refused.
	bundled := decree("rotate-bundled", 2, RotateKey, "cds-v2")
	if writerMeasurement(c) == "cds-v1" {
		c.submit(bundled)
		waitFor(t, func() bool { return c.decreeStatus(bundled) != "" })
	}
	dropV1 := decree("drop-v1", 2, UpdateMeasurements, "cds-v2", "cds-v3")
	c.submit(dropV1)
	waitFor(t, func() bool { hb := v2.Heartbeat(); return hb.Epoch == 3 && hb.Serving })
	waitFor(t, func() bool { return c.decreeStatus(dropV1) != "" })
	if got := c.decreeStatus(dropV1); got != `{"applied_epoch":3}` {
		t.Fatalf("drop-v1 status %q", got)
	}
	waitFor(t, func() bool { return onlyV2Serves(c, v2) })
	waitFor(t, func() bool { return writerMeasurement(c) == "cds-v2" })
	c.submit(decree("rotate", 3, RotateKey))
	waitFor(t, func() bool { hb := v2.Heartbeat(); return hb.Epoch == 4 && hb.KeyFingerprint != fp0 && hb.Serving })
	time.Sleep(10 * fastTiming.Heartbeat)
	if n := countGenesis(c); n != 1 {
		t.Fatalf("%d genesis mints over the test, want 1", n)
	}
	for _, r := range c.running() {
		if st, _ := r.snapshot(); r != v2 && st.Key != nil {
			t.Fatalf("retired cds-v1 replica %s still holds a key at epoch %d", r.cfg.Identity, st.Chain.Tail().Epoch)
		}
	}
}

func onlyV2Serves(c *testCl, v2 *Replica) bool {
	for _, r := range c.running() {
		if r != v2 && r.Heartbeat().Serving {
			return false
		}
	}
	return true
}

func writerMeasurement(c *testCl) string {
	for _, r := range c.running() {
		if _, ok := r.writer(); ok {
			return r.measurement
		}
	}
	return ""
}

// TestCrossClusterAndRollback checks cluster separation (CI2) and that a
// rolled-back CDSEpoch is ignored (E5).
func TestCrossClusterAndRollback(t *testing.T) {
	opKey, opPub := operatorKey(t)
	c := newTestCluster(t, 3, opPub)
	a := c.start(0, testCluster, "cds-v1")
	c.start(1, testCluster, "cds-v1")
	c.startCluster(opKey)
	c.waitConverged(0, 10*time.Second)
	// A replica with the same image but another cluster_id never joins (CI2).
	b := c.start(2, "tenant-b", "cds-v1")
	time.Sleep(20 * fastTiming.Heartbeat)
	if hb := b.Heartbeat(); hb.Joined && hb.KeyFingerprint == a.Heartbeat().KeyFingerprint {
		t.Fatal("replica of another cluster received tenant-a's key")
	}
	// Roll CDSEpoch back to garbage: replicas ignore it (O6, E5).
	st := Store{Client: c.kube, Namespace: "c8s-system", ClusterID: testCluster}
	old := genesisState(t, 0, opPub)
	_, v, _ := st.GetEpoch(context.Background())
	if err := st.PutEpoch(context.Background(), old.Chain[0], v); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * fastTiming.Heartbeat)
	if hb := a.Heartbeat(); !hb.Serving {
		t.Fatal("rolled-back CDSEpoch stopped the replica")
	}
}

// countGenesis counts mints by every replica ever started, so a second
// genesis is caught even if its key was later abandoned.
func countGenesis(c *testCl) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.ever {
		r.mu.Lock()
		n += r.minted
		r.mu.Unlock()
	}
	return n
}

// writerCount is the number of running replicas that believe they are writer.
func writerCount(c *testCl) int {
	n := 0
	for _, r := range c.running() {
		if _, ok := r.writer(); ok {
			n++
		}
	}
	return n
}

func writerIndex(c *testCl) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, nd := range c.nodes {
		if _, ok := nd.r.writer(); ok {
			return i
		}
	}
	c.t.Fatal("no writer")
	return -1
}

func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition not reached")
}

// TestSplitDNSNoSecondGenesis (review F3): the host hides every peer from a
// replica and hands it the Lease. Without a Genesis decree it cannot mint;
// with the cluster's single Genesis decree already applied, it cannot either.
func TestSplitDNSNoSecondGenesis(t *testing.T) {
	opKey, opPub := operatorKey(t)
	c := newTestCluster(t, 3, opPub)
	c.start(0, testCluster, "cds-v1")
	c.start(1, testCluster, "cds-v1")
	g := c.startCluster(opKey)
	c.waitConverged(0, 10*time.Second)
	// Replica 2 sees no peers (hostile DNS) and has its own Lease (hostile
	// control plane), but shares the decree store, where genesis is applied.
	isolated := c.startIsolated(2, testCluster, "cds-v1")
	time.Sleep(20 * fastTiming.Heartbeat)
	if hb := isolated.Heartbeat(); hb.Joined {
		t.Fatalf("isolated replica minted a second key: %+v", hb)
	}
	if st := c.decreeStatus(g); st != `{"applied_epoch":0}` {
		t.Fatalf("genesis status %q", st)
	}
	if countGenesis(c) != 1 {
		t.Fatalf("%d mints", countGenesis(c))
	}
}

// TestUnpinnedReplicaNeverHoldsLease: a keyless replica that the cluster
// does not pin must not take the Lease from the key holders, or no decree
// is applied while it holds it (observed in kind before W1 was enforced).
func TestUnpinnedReplicaNeverHoldsLease(t *testing.T) {
	opKey, opPub := operatorKey(t)
	c := newTestCluster(t, 3, opPub)
	c.start(0, testCluster, "cds-v1")
	c.start(1, testCluster, "cds-v1")
	c.startCluster(opKey)
	c.waitConverged(0, 10*time.Second)
	evil := c.startWith(2, testCluster, "cds-unpinned", c.kube, []string{"cds-v1", "cds-unpinned"})
	for range 3 {
		c.stop(writerIndex(c))
		restarted := c.start(writerIndexOrRestart(c), testCluster, "cds-v1")
		waitFor(t, func() bool { return restarted.Heartbeat().Serving }) // never kill the last key holder
		waitFor(t, func() bool { _, ok := evil.writer(); return !ok && writerCount(c) == 1 })
	}
	sd, err := SignDecree(Decree{ClusterID: testCluster, IntentID: "after", BaseEpoch: 0, ExpiresAt: time.Now().Add(time.Minute), Kind: UpdateMeasurements, Measurements: []string{"cds-v1"}}, opKey)
	if err != nil {
		t.Fatal(err)
	}
	c.submit(sd)
	waitFor(t, func() bool { return c.decreeStatus(sd) == `{"applied_epoch":1}` })
}

// writerIndexOrRestart returns the index of a stopped pinned replica.
func writerIndexOrRestart(c *testCl) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, i := range []int{0, 1} {
		if _, ok := c.nodes[i]; !ok {
			return i
		}
	}
	c.t.Fatal("no stopped replica")
	return -1
}

// TestPartitionedReplicaStopsAfterRotation reproduces what the real-TDX test
// found: a replica cut off from its peers but not from the API server kept
// serving the rotated-away key. It must stop once CDSEpoch shows a verified
// rotation it holds no key for, and resume after it syncs.
func TestPartitionedReplicaStopsAfterRotation(t *testing.T) {
	opKey, opPub := operatorKey(t)
	c := newTestCluster(t, 3, opPub)
	c.start(0, testCluster, "cds-v1")
	c.start(1, testCluster, "cds-v1")
	c.startCluster(opKey)
	c.waitConverged(0, 10*time.Second)
	// Joins after the Lease is held, so it stays a follower.
	var cut atomic.Bool
	isolated := c.startPeers(2, testCluster, "cds-v1", c.kube, []string{"cds-v1"}, func(ctx context.Context) ([]string, error) {
		if cut.Load() {
			// Like DNS whose servers sit behind the partition: block until
			// the caller gives up.
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []string{c.addr(0), c.addr(1)}, nil
	})
	c.waitConverged(0, 10*time.Second)
	if _, ok := isolated.writer(); ok {
		t.Fatal("isolated replica became writer")
	}
	cut.Store(true)
	sd, err := SignDecree(Decree{ClusterID: testCluster, IntentID: "rot", BaseEpoch: 0, ExpiresAt: time.Now().Add(time.Minute), Kind: RotateKey}, opKey)
	if err != nil {
		t.Fatal(err)
	}
	c.submit(sd)
	// Within a few heartbeats, not after discovery timeouts pile up.
	deadline := time.Now().Add(10 * fastTiming.Heartbeat)
	for isolated.Heartbeat().Serving && time.Now().Before(deadline) {
		time.Sleep(fastTiming.Heartbeat / 4)
	}
	if _, err := isolated.CA(); err == nil {
		t.Fatal("partitioned replica still issues under the rotated-away key")
	}
	cut.Store(false)
	waitFor(t, func() bool { hb := isolated.Heartbeat(); return hb.Serving && hb.Epoch == 1 })
}

// TestNewImageReplicaJoinsAfterUpdateMeasurements: a replica on a new node
// image bakes only its own pin. It must not take the key before the operator
// pins it, and must join from the old-image replicas once UpdateMeasurements
// pins both images (a CDS node image upgrade without losing the key).
func TestNewImageReplicaJoinsAfterUpdateMeasurements(t *testing.T) {
	opKey, opPub := operatorKey(t)
	c := newTestCluster(t, 3, opPub)
	c.start(0, testCluster, "cds-v1")
	c.start(1, testCluster, "cds-v1")
	c.startCluster(opKey)
	fp0 := c.waitConverged(0, 10*time.Second)
	v2 := c.startWith(2, testCluster, "cds-v2", c.kube, []string{"cds-v2"})
	time.Sleep(10 * fastTiming.Heartbeat)
	if st, _ := v2.snapshot(); st.Key != nil || v2.Heartbeat().Serving {
		t.Fatal("a replica on an image no epoch pins took the key")
	}
	sd, err := SignDecree(Decree{ClusterID: testCluster, IntentID: "add-v2", BaseEpoch: 0, ExpiresAt: time.Now().Add(time.Minute), Kind: UpdateMeasurements, Measurements: []string{"cds-v1", "cds-v2"}}, opKey)
	if err != nil {
		t.Fatal(err)
	}
	c.submit(sd)
	waitFor(t, func() bool { hb := v2.Heartbeat(); return hb.Serving && hb.Epoch == 1 })
	if v2.Heartbeat().KeyFingerprint != fp0 {
		t.Fatal("the new-image replica serves a different key")
	}
}

// TestForgedEpochRecordIsReplaced (found on TDX): a CDSEpoch record that
// claims the next epoch but does not verify must not stay published; the
// writer replaces it with its real tail (otherwise replicas that learn
// rotations through CDSEpoch never see the real one).
func TestForgedEpochRecordIsReplaced(t *testing.T) {
	opKey, opPub := operatorKey(t)
	c := newTestCluster(t, 3, opPub)
	for i := range 3 {
		c.start(i, testCluster, "cds-v1")
	}
	c.startCluster(opKey)
	c.waitConverged(0, 10*time.Second)
	st := Store{Client: c.kube, Namespace: "c8s-system", ClusterID: testCluster}
	ctx := context.Background()
	var real *SignedRecord
	var v Version
	waitFor(t, func() bool {
		var err error
		real, v, err = st.GetEpoch(ctx)
		return err == nil && real != nil
	})
	forged := *real
	forged.Record.Epoch++
	forged.Record.Measurements = []string{"evil"}
	if err := st.PutEpoch(ctx, forged, v); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		got, _, err := st.GetEpoch(ctx)
		return err == nil && got != nil && got.Record.Epoch == 0 && bytes.Equal(got.Hash(), real.Hash())
	})
	for _, r := range c.running() {
		if !r.Heartbeat().Serving {
			t.Fatalf("forged CDSEpoch stopped replica %s", r.cfg.Identity)
		}
	}
}
