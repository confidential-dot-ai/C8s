package cdsha

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

const testCluster = "c1"

var testTiming = Timing{
	Heartbeat: 150 * time.Millisecond, Election: 150 * time.Millisecond, Lease: time.Second,
	DeadAfter: 1500 * time.Millisecond, Stabilize: 200 * time.Millisecond, Apply: 3 * time.Second, Tick: 50 * time.Millisecond,
}

func operatorKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return k, pub
}

// memDecrees stands in for the decree ConfigMaps.
type memDecrees struct {
	mu     sync.Mutex
	items  map[string]SignedDecree
	status map[string]DecreeStatus
}

func (m *memDecrees) PendingDecrees(context.Context) ([]PendingDecree, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PendingDecree
	for name, sd := range m.items {
		if _, done := m.status[name]; !done {
			out = append(out, PendingDecree{Name: name, Decree: sd})
		}
	}
	return out, nil
}

func (m *memDecrees) SetDecreeStatus(_ context.Context, name string, st DecreeStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status[name] = st
	return nil
}

func (m *memDecrees) get(name string) (DecreeStatus, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.status[name]
	return st, ok
}

// replica is one test node and its local stores.
type replica struct {
	name   string
	ip     string
	node   *Node
	al     *allowlist.Store
	sec    secrets.ReplicatedStore
	led    *sandboxledger.Ledger
	cancel context.CancelFunc
	done   chan struct{}
}

type cluster struct {
	t       *testing.T
	opKey   *ecdsa.PrivateKey
	opPub   []byte
	decrees *memDecrees
	seats   int
	port    int
	block   int32

	mu     sync.Mutex
	nodes  map[string]*replica // by node name: the live replica on that node
	meas   map[string]string   // node name -> measurement
	cut    map[string]bool     // partitioned IPs
	nextIP int
	ipOf   map[string]string
}

// clusterSeq gives every test cluster its own loopback range, so one
// cluster's lingering sockets never collide with the next one's.
var clusterSeq atomic.Int32

func newCluster(t *testing.T, seats int) *cluster {
	t.Helper()
	k, pub := operatorKey(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	c := &cluster{t: t, opKey: k, opPub: pub, seats: seats, port: port,
		decrees: &memDecrees{items: map[string]SignedDecree{}, status: map[string]DecreeStatus{}},
		nodes:   map[string]*replica{}, meas: map[string]string{}, cut: map[string]bool{}, nextIP: 2, ipOf: map[string]string{},
		block: 1 + clusterSeq.Add(1)%250}
	t.Cleanup(func() {
		c.mu.Lock()
		rs := make([]*replica, 0, len(c.nodes))
		for _, r := range c.nodes {
			rs = append(rs, r)
		}
		c.mu.Unlock()
		for _, r := range rs {
			c.stopReplica(r)
		}
	})
	return c
}

func (c *cluster) blocked(self string) func(string) bool {
	return func(addr string) bool {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.cut[host] != c.cut[self] // either side cut off from the rest
	}
}

func (c *cluster) peers(self string) func(context.Context) ([]string, error) {
	return func(context.Context) ([]string, error) {
		c.mu.Lock()
		defer c.mu.Unlock()
		var out []string
		for _, r := range c.nodes {
			if r.ip != self {
				out = append(out, fmt.Sprintf("%s:%d", r.ip, c.port))
			}
		}
		return out, nil
	}
}

// start runs a fresh replica on node name (a restart if one ran there).
func (c *cluster) start(name, measurement string) *replica {
	c.t.Helper()
	c.mu.Lock()
	ip, ok := c.ipOf[name]
	if !ok {
		ip = fmt.Sprintf("127.%d.0.%d", c.block, c.nextIP)
		c.nextIP++
		c.ipOf[name] = ip
	}
	c.meas[name] = measurement
	c.mu.Unlock()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		c.t.Fatal(err)
	}
	mem := secrets.NewMemoryStore(64, 8, 4096)
	led := sandboxledger.New(time.Hour, 100)
	n, err := NewNode(Config{
		ClusterID: testCluster, NodeName: name, Bind: fmt.Sprintf("%s:%d", ip, c.port), Advertise: fmt.Sprintf("%s:%d", ip, c.port),
		Attestor: testAttestor{measurement}, BakedPins: []string{measurement}, OperatorPubKey: c.opPub,
		Seats: c.seats, MaxNonVoters: 8, Peers: c.peers(ip), Decrees: c.decrees, Timing: testTiming,
		Allowlist: &al, Secrets: mem, Ledger: led,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	n.blocked = c.blocked(ip)
	al.SetReplicator(n)
	led.SetReplicator(n)
	if err := n.Start(); err != nil {
		c.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &replica{name: name, ip: ip, node: n, al: &al, sec: secrets.ReplicatedStore{MemoryStore: mem, Repl: n}, led: led, cancel: cancel, done: make(chan struct{})}
	go func() { defer close(r.done); _ = n.Run(ctx) }()
	c.mu.Lock()
	c.nodes[name] = r
	c.mu.Unlock()
	return r
}

// stopReplica is a crash: the process and its memory are gone.
func (c *cluster) stopReplica(r *replica) {
	r.cancel()
	<-r.done
	c.mu.Lock()
	if c.nodes[r.name] == r {
		delete(c.nodes, r.name)
	}
	c.mu.Unlock()
	r.al.Close()
}

func (c *cluster) partition(name string, on bool) {
	c.mu.Lock()
	c.cut[c.ipOf[name]] = on
	c.mu.Unlock()
	for _, r := range c.live() {
		r.node.mux.recheck() // cut the connections that are open now
	}
}

func (c *cluster) decree(d Decree) string {
	c.t.Helper()
	d.ClusterID = testCluster
	if d.IntentID == "" {
		d.IntentID = fmt.Sprintf("i%d", time.Now().UnixNano())
	}
	if d.ExpiresAt.IsZero() {
		d.ExpiresAt = time.Now().Add(time.Hour)
	}
	sd, err := SignDecree(d, c.opKey)
	if err != nil {
		c.t.Fatal(err)
	}
	name := DecreeName(testCluster, d.IntentID)
	c.decrees.mu.Lock()
	c.decrees.items[name] = sd
	c.decrees.mu.Unlock()
	return name
}

func (c *cluster) live() []*replica {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*replica, 0, len(c.nodes))
	for _, r := range c.nodes {
		out = append(out, r)
	}
	return out
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (c *cluster) leader() *replica {
	for _, r := range c.live() {
		if r.node.raft.State() == raft.Leader {
			return r
		}
	}
	return nil
}

// settled: every live replica serves the same CA and the voters fill the
// seats (or every live replica, if fewer).
func (c *cluster) settled(within time.Duration) {
	c.t.Helper()
	eventually(c.t, within, "cluster settled", func() bool {
		rs := c.live()
		fp := ""
		for _, r := range rs {
			st := r.node.Status()
			if !st.Serving || (fp != "" && st.CAFingerprint != fp) {
				return false
			}
			fp = st.CAFingerprint
		}
		l := c.leader()
		if l == nil {
			return false
		}
		st := l.node.Status()
		want := min(c.seats, len(rs))
		return len(st.Voters) == want && len(st.Voters)+len(st.NonVoters) == len(rs)
	})
}

func (c *cluster) genesis(names ...string) {
	c.t.Helper()
	for _, n := range names {
		c.start(n, "m1")
	}
	g := c.decree(Decree{Kind: Genesis, BootstrapNode: names[0]})
	eventually(c.t, 10*time.Second, "genesis applied", func() bool { st, ok := c.decrees.get(g); return ok && st.AppliedEpoch != nil })
	c.settled(15 * time.Second)
}

func TestGenesisJoinAndReplicatedState(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	rs := c.live()
	ca := rs[0].node.Core().RootCert
	for _, r := range rs {
		if string(r.node.Core().RootCert) != string(ca) {
			t.Fatal("replicas hold different mesh CAs")
		}
	}
	// Allowlist written at one replica is served by all, with one version.
	w := mkWorkload(t)
	if err := c.nodes["n1"].al.PutWorkload("web", w); err != nil {
		t.Fatal(err)
	}
	v1, _ := c.nodes["n1"].al.Version()
	for _, r := range c.live() {
		eventually(t, 3*time.Second, "allowlist replicated to "+r.name, func() bool { v, _ := r.al.Version(); return v == v1 })
	}
	// A token spent at one replica cannot be spent at another.
	if err := c.nodes["n2"].al.ConsumeToken("h.p.s1"); err != nil {
		t.Fatal(err)
	}
	if err := c.nodes["n0"].al.ConsumeToken("h.p.s2"); !errors.Is(err, allowlist.ErrTokenReused) {
		t.Fatalf("token replayed at another replica: %v", err)
	}
	// Two replicas generating one secret path agree on its value.
	ctx := context.Background()
	got1, _, err := c.nodes["n0"].sec.PutIfAbsent(ctx, "/s", []byte("from-n0"), secrets.WorkloadHolder("web"))
	if err != nil {
		t.Fatal(err)
	}
	got2, held, err := c.nodes["n2"].sec.PutIfAbsent(ctx, "/s", []byte("from-n2"), secrets.WorkloadHolder("web"))
	if err != nil || !held.Exists || string(got1) != string(got2) {
		t.Fatalf("replicas disagree on a generated secret: %q %q %v", got1, got2, err)
	}
	for _, r := range c.live() {
		v, err := r.sec.Get(ctx, "/s")
		if err != nil || string(v) != "from-n0" {
			t.Fatalf("%s holds %q: %v", r.name, v, err)
		}
	}
	// A sandbox bound at one replica is bound at all.
	if !c.nodes["n1"].led.Record("sb1", "10.0.0.1") {
		t.Fatal("binding refused")
	}
	// Lookup right after: a replica that has not applied it yet catches up.
	for _, r := range c.live() {
		if h, ok := r.led.Lookup("sb1"); !ok || h != "10.0.0.1" {
			t.Fatalf("%s lacks the sandbox binding", r.name)
		}
	}
}

// Killing the leader: a new one is elected, writes continue, and the killed
// node's restarted replica joins as a new member and takes its seat back.
func TestLeaderKillAndRestartAsNewMember(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	old := c.leader()
	oldID := old.node.ID()
	c.stopReplica(old)
	eventually(t, 5*time.Second, "new leader", func() bool { l := c.leader(); return l != nil && l != old })
	for _, r := range c.live() {
		if err := r.al.PutWorkload("after-"+r.name, mkWorkload(t)); err != nil {
			t.Fatalf("write at %s with one replica down: %v", r.name, err)
		}
	}
	back := c.start(old.name, "m1")
	c.settled(10 * time.Second)
	st := c.leader().node.Status()
	for _, id := range append(st.Voters, st.NonVoters...) {
		if id == oldID {
			t.Fatal("the dead member was not replaced")
		}
	}
	if !contains(st.Voters, back.node.ID()) {
		t.Fatalf("restarted replica did not take its seat: %+v", st)
	}
	// It holds what was written while it was gone.
	for _, r := range c.live() {
		if r == back {
			continue
		}
		v, _ := r.al.Version()
		eventually(t, 3*time.Second, "restarted replica caught up", func() bool { bv, _ := back.al.Version(); return bv == v })
	}
	if string(back.node.Core().RootCert) != string(c.leader().node.Core().RootCert) {
		t.Fatal("restarted replica has another mesh CA")
	}
}

// An isolated replica stops serving within the lease, the majority keeps
// writing, and after the partition heals the replica is current and serves.
func TestPartitionedReplicaStopsServingThenRecovers(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	var victim *replica
	for _, r := range c.live() {
		if r != c.leader() {
			victim = r
			break
		}
	}
	c.partition(victim.name, true)
	eventually(t, 3*time.Second, "isolated replica stops serving", func() bool { return !victim.node.Serving() })
	if _, err := victim.node.CA(); err == nil {
		t.Fatal("isolated replica still hands out the CA")
	}
	if err := victim.al.PutWorkload("x", mkWorkload(t)); err == nil {
		t.Fatal("isolated replica accepted a write")
	}
	var other *replica
	for _, r := range c.live() {
		if r != victim {
			other = r
		}
	}
	if err := other.al.PutWorkload("during", mkWorkload(t)); err != nil {
		t.Fatalf("majority write: %v", err)
	}
	c.partition(victim.name, false)
	eventually(t, 5*time.Second, "healed replica serves again", victim.node.Serving)
	v, _ := other.al.Version()
	eventually(t, 3*time.Second, "healed replica caught up", func() bool { vv, _ := victim.al.Version(); return vv == v })
}

// With two of three replicas gone, the survivor stops serving and refuses
// writes; nothing it does can fork the cluster.
func TestTwoOfThreeDownFailsClosed(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	rs := c.live()
	c.partition(rs[0].name, true)
	c.partition(rs[1].name, true)
	surv := rs[2]
	eventually(t, 4*time.Second, "survivor stops serving", func() bool { return !surv.node.Serving() })
	if err := surv.al.PutWorkload("x", mkWorkload(t)); err == nil {
		t.Fatal("a lone replica accepted a write")
	}
	c.partition(rs[0].name, false)
	c.partition(rs[1].name, false)
	c.settled(10 * time.Second)
}

// More replicas than seats: the extra ones are non-voters that serve and
// write through the leader, and one takes a seat when a voter dies.
func TestNonVotersServeAndFillAFreeSeat(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2", "n3", "n4")
	st := c.leader().node.Status()
	if len(st.Voters) != 3 || len(st.NonVoters) != 2 {
		t.Fatalf("seats not respected: %+v", st)
	}
	var nv *replica
	for _, r := range c.live() {
		if contains(st.NonVoters, r.node.ID()) {
			nv = r
		}
	}
	if !nv.node.Serving() {
		t.Fatal("non-voter does not serve")
	}
	if err := nv.al.PutWorkload("from-nonvoter", mkWorkload(t)); err != nil {
		t.Fatalf("non-voter write: %v", err)
	}
	var voter *replica
	for _, r := range c.live() {
		if contains(st.Voters, r.node.ID()) && r != c.leader() {
			voter = r
		}
	}
	c.stopReplica(voter)
	eventually(t, 8*time.Second, "a non-voter took the free seat", func() bool {
		l := c.leader()
		if l == nil {
			return false
		}
		s := l.node.Status()
		return len(s.Voters) == 3 && len(s.NonVoters) == 1
	})
}

// UpdateMeasurements that drops an image cuts its replica off: it stops
// serving, is removed, and cannot join again.
func TestEvictedImageIsCutOff(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	c.start("n3", "m2") // a new image, not yet pinned: refused
	time.Sleep(time.Second)
	if c.nodes["n3"].node.Serving() || c.nodes["n3"].node.member() {
		t.Fatal("an unpinned image joined")
	}
	up := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: []string{"m1", "m2"}})
	eventually(t, 5*time.Second, "pin set updated", func() bool { st, ok := c.decrees.get(up); return ok && st.AppliedEpoch != nil })
	eventually(t, 8*time.Second, "new image joined", func() bool { return c.nodes["n3"].node.Serving() })
	// Now evict m1 except... evict m2 again: n3 is cut off.
	ev := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 2, Measurements: []string{"m1"}})
	eventually(t, 5*time.Second, "eviction applied", func() bool { st, ok := c.decrees.get(ev); return ok && st.AppliedEpoch != nil })
	n3 := c.nodes["n3"]
	eventually(t, 5*time.Second, "evicted replica stops serving", func() bool { return !n3.node.Serving() })
	eventually(t, 8*time.Second, "evicted replica removed", func() bool {
		s := c.leader().node.Status()
		return !contains(append(s.Voters, s.NonVoters...), n3.node.ID())
	})
}

// RotateKey: every replica moves to the one new mesh CA.
func TestRotateKey(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	before := c.leader().node.Status().CAFingerprint
	rot := c.decree(Decree{Kind: RotateKey, BaseEpoch: 1})
	eventually(t, 5*time.Second, "rotation applied", func() bool { st, ok := c.decrees.get(rot); return ok && st.AppliedEpoch != nil })
	c.settled(5 * time.Second)
	after := c.leader().node.Status().CAFingerprint
	if after == before {
		t.Fatal("mesh CA did not change")
	}
	for _, r := range c.live() {
		ca, err := r.node.CA()
		if err != nil || string(ca.Cert.Raw) != string(r.node.Core().RootCert) {
			t.Fatalf("%s serves a stale CA: %v", r.name, err)
		}
	}
}

// The Genesis decree starts exactly one cluster: a restart of the bootstrap
// node while the decree is still valid joins the existing cluster.
func TestGenesisStartsOneCluster(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	fp := c.leader().node.Status().CAFingerprint
	// Make the decree look pending again, as a host could.
	c.decrees.mu.Lock()
	c.decrees.status = map[string]DecreeStatus{}
	c.decrees.mu.Unlock()
	c.stopReplica(c.nodes["n0"])
	c.start("n0", "m1")
	c.settled(10 * time.Second)
	for _, r := range c.live() {
		if r.node.Status().CAFingerprint != fp {
			t.Fatalf("%s is in a second cluster", r.name)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
