package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

const testCluster = "c1"

var testTiming = Timing{
	Heartbeat: 150 * time.Millisecond, Election: 150 * time.Millisecond, Lease: time.Second,
	DeadAfter: 1500 * time.Millisecond, Stabilize: 200 * time.Millisecond, Apply: 3 * time.Second, Tick: 50 * time.Millisecond,
	Backup: 100 * time.Millisecond,
}

// memBackups stands in for the backup ConfigMaps; with err set it refuses
// every backup.
type memBackups struct {
	mu    sync.Mutex
	last  *Backup
	err   error
	calls int
	// hold, if set, keeps every backup waiting until it closes or the
	// caller gives up, as a store on a stalled disk would; held counts them.
	hold chan struct{}
	held int
}

func (m *memBackups) PutBackup(ctx context.Context, b Backup) error {
	m.mu.Lock()
	if hold := m.hold; hold != nil {
		m.held++
		m.mu.Unlock()
		select {
		case <-hold:
		case <-ctx.Done():
			return ctx.Err()
		}
		m.mu.Lock()
	}
	defer m.mu.Unlock()
	m.calls++
	if m.err != nil {
		return m.err
	}
	if m.last != nil && !b.Meta.Newer(m.last.Meta) {
		return ErrBackupNotNewer
	}
	m.last = &b
	return nil
}

func (m *memBackups) attempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

func (m *memBackups) get() (Backup, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return Backup{}, false
	}
	return *m.last, true
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
	backups *memBackups
	recKey  *ecdsa.PrivateKey
	seats   int
	port    int
	block   int32

	mu     sync.Mutex
	nodes  map[string]*replica // by node name: the live replica on that node
	meas   map[string]string   // node name -> measurement
	cut    map[string]bool     // partitioned IPs
	nextIP int
	ipOf   map[string]string
	reads  map[string]uint32 // node name -> newest format its next replica reads (0: Format)

	historyVersions int           // Config.HistoryVersions of every replica started
	historyBytes    int64         // Config.HistoryBytes of every replica started
	caValidity      time.Duration // Config.CAValidity of every replica started
	timing          *Timing       // Config.Timing of every replica started; nil: testTiming
	secretLimits    [3]int        // secrets.NewMemoryStore limits of every replica started; zero: 64, 8, 4096
}

func (c *cluster) timingOr() Timing {
	if c.timing != nil {
		return *c.timing
	}
	return testTiming
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
	rk, _ := operatorKey(t)
	c := &cluster{t: t, opKey: k, opPub: pub, seats: seats, port: port, backups: &memBackups{}, recKey: rk,
		decrees: newMemDecrees(),
		nodes:   map[string]*replica{}, meas: map[string]string{}, cut: map[string]bool{}, nextIP: 2, ipOf: map[string]string{}, reads: map[string]uint32{},
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
	return c.startWithControl(name, measurement, nil)
}

// startWithControl installs a test control wrapper before peers can discover
// the listener. It permits a delayed response without a data race on the mux.
func (c *cluster) startWithControl(name, measurement string, wrap func(controlHandler) controlHandler) *replica {
	c.t.Helper()
	c.mu.Lock()
	ip, ok := c.ipOf[name]
	if !ok {
		ip = fmt.Sprintf("127.%d.0.%d", c.block, c.nextIP)
		c.nextIP++
		c.ipOf[name] = ip
	}
	c.meas[name] = measurement
	reads := c.reads[name]
	c.mu.Unlock()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		c.t.Fatal(err)
	}
	mem := secrets.NewMemoryStore(64, 8, 4096)
	if l := c.secretLimits; l != [3]int{} {
		mem = secrets.NewMemoryStore(l[0], l[1], l[2])
	}
	led := sandboxledger.New(time.Hour, 100)
	n, err := NewNode(Config{
		ClusterID: testCluster, NodeName: name, Bind: fmt.Sprintf("%s:%d", ip, c.port), Advertise: fmt.Sprintf("%s:%d", ip, c.port),
		Attestor: MockAttestor{measurement}, BakedPins: []string{measurement}, OperatorPubKey: c.opPub,
		Seats: c.seats, MaxNonVoters: 8, Peers: c.peers(ip), Decrees: c.decrees, Timing: c.timingOr(),
		RecoveryKey: mustPKIX(c.t, &c.recKey.PublicKey), Backups: c.backups,
		Allowlist: &al, Secrets: mem, Ledger: led, Format: reads, HistoryVersions: c.historyVersions, HistoryBytes: c.historyBytes, CAValidity: c.caValidity,
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
	if wrap != nil {
		n.mux.Load().control = wrap(n.mux.Load().control)
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
		r.node.mux.Load().recheck() // cut the connections that are open now
	}
}

func (c *cluster) decree(d Decree) string {
	c.t.Helper()
	return c.decrees.put(signDecree(c.t, c.opKey, d))
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

func (c *cluster) leader() *replica {
	for _, r := range c.live() {
		if r.node.r().State() == raft.Leader {
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
	w := mkWorkload(t, 0)
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
	if err := c.nodes["n0"].al.ConsumeToken("h.p.s2"); !errors.Is(err, operatorauth.ErrTokenReused) {
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
		// A replica that has not heard from the new leader yet answers
		// "unavailable" (a client's 503 + retry); it must not stay so.
		var err error
		eventually(t, 3*time.Second, "write at "+r.name+" with one replica down", func() bool {
			err = r.al.PutWorkload("after-"+r.name, mkWorkload(t, 0))
			return err == nil
		})
	}
	back := c.start(old.name, "m1")
	eventually(t, 5*time.Second, "restarted replica joined", func() bool {
		l := c.leader()
		return l != nil && slices.Contains(l.node.Status().NonVoters, back.node.ID())
	})
	// The dead member at the joiner's address keeps its vote until the
	// joiner holds one, so the add of the joiner commits with every live
	// voter (F9).
	if st := c.leader().node.Status(); !slices.Contains(st.Voters, oldID) {
		t.Fatalf("the dead voter at the joiner's address lost its vote before the joiner got one: %+v", st)
	}
	// It retires once the joiner has been healthy for Stabilize, the next
	// reconcile (a Tick) has promoted it, and the voters that stay have
	// answered a status probe each (at most Lease/2 apiece): within
	// Stabilize + Lease + 20 Ticks, which leaves the commits room too.
	bound := testTiming.Stabilize + testTiming.Lease + 20*testTiming.Tick
	eventually(t, bound, "the dead voter retired", func() bool {
		l := c.leader()
		if l == nil {
			return false
		}
		st := l.node.Status()
		return !slices.Contains(append(st.Voters, st.NonVoters...), oldID) && slices.Contains(st.Voters, back.node.ID())
	})
	c.settled(10 * time.Second)
	st := c.leader().node.Status()
	for _, id := range append(st.Voters, st.NonVoters...) {
		if id == oldID {
			t.Fatal("the dead member was not replaced")
		}
	}
	if !slices.Contains(st.Voters, back.node.ID()) {
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
	if err := victim.al.PutWorkload("x", mkWorkload(t, 0)); err == nil {
		t.Fatal("isolated replica accepted a write")
	}
	var other *replica
	for _, r := range c.live() {
		if r != victim {
			other = r
		}
	}
	if err := other.al.PutWorkload("during", mkWorkload(t, 0)); err != nil {
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
	if err := surv.al.PutWorkload("x", mkWorkload(t, 0)); err == nil {
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
		if slices.Contains(st.NonVoters, r.node.ID()) {
			nv = r
		}
	}
	if !nv.node.Serving() {
		t.Fatal("non-voter does not serve")
	}
	if err := nv.al.PutWorkload("from-nonvoter", mkWorkload(t, 0)); err != nil {
		t.Fatalf("non-voter write: %v", err)
	}
	var voter *replica
	for _, r := range c.live() {
		if slices.Contains(st.Voters, r.node.ID()) && r != c.leader() {
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
	if _, err := c.nodes["n0"].sec.Put(t.Context(), "/before", []byte("v")); err != nil {
		t.Fatal(err)
	}
	c.start("n3", "m2") // a new image, not yet pinned: refused
	time.Sleep(time.Second)
	if c.nodes["n3"].node.Serving() || c.nodes["n3"].node.member() {
		t.Fatal("an unpinned image joined")
	}
	up := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: []string{"m1", "m2"}})
	eventually(t, 5*time.Second, "pin set updated", func() bool { st, ok := c.decrees.get(up); return ok && st.AppliedEpoch != nil })
	eventually(t, 8*time.Second, "new image joined", func() bool { return c.nodes["n3"].node.Serving() })
	eventually(t, 5*time.Second, "state on the new image", func() bool { v, _ := c.nodes["n3"].sec.Get(t.Context(), "/before"); return string(v) == "v" })
	// Now evict m1 except... evict m2 again: n3 is cut off.
	ev := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 2, Measurements: []string{"m1"}})
	eventually(t, 5*time.Second, "eviction applied", func() bool { st, ok := c.decrees.get(ev); return ok && st.AppliedEpoch != nil })
	n3 := c.nodes["n3"]
	eventually(t, 5*time.Second, "evicted replica stops serving", func() bool { return !n3.node.Serving() })
	eventually(t, 8*time.Second, "evicted replica removed", func() bool {
		s := c.leader().node.Status()
		return !slices.Contains(append(s.Voters, s.NonVoters...), n3.node.ID())
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

// Two of three replicas lost for good: the survivor cannot form a majority.
// A Recover decree naming it makes it the only voter, with its state;
// replacements join, and the decree cannot be replayed.
func TestRecoverAfterLosingTheMajority(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2", "n3") // n3: a non-voter that survives too
	l := c.leader()
	if err := l.al.PutWorkload("kept", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.sec.PutIfAbsent(context.Background(), "/kept", []byte("v"), secrets.WorkloadHolder("w")); err != nil {
		t.Fatal(err)
	}
	fp := l.node.Status().CAFingerprint
	var surv, nonVoter *replica
	st0 := l.node.Status()
	for _, r := range c.live() {
		switch {
		case slices.Contains(st0.NonVoters, r.node.ID()):
			nonVoter = r
		case r != l && surv == nil:
			surv = r
		default:
			c.stopReplica(r)
		}
	}
	eventually(t, 4*time.Second, "survivor stops serving", func() bool { return !surv.node.Serving() })
	epoch := surv.node.Core().Epoch
	rec := c.decree(Decree{Kind: Recover, BootstrapNode: surv.name, BaseEpoch: epoch})
	eventually(t, 10*time.Second, "recover applied", func() bool { st, ok := c.decrees.get(rec); return ok && st.AppliedEpoch != nil })
	eventually(t, 5*time.Second, "survivor serves again", surv.node.Serving)
	if surv.node.Status().CAFingerprint != fp {
		t.Fatal("recovery changed the mesh CA")
	}
	if v, err := surv.sec.Get(context.Background(), "/kept"); err != nil || string(v) != "v" {
		t.Fatalf("recovery lost a secret: %q %v", v, err)
	}
	// The surviving non-voter was in the old configuration only: it asks to
	// be added again and is served the recovered state.
	eventually(t, 15*time.Second, "surviving non-voter rejoined", nonVoter.node.Serving)
	c.start("n8", "m1")
	c.start("n9", "m1")
	c.settled(15 * time.Second)
	for _, r := range c.live() {
		if v, err := r.sec.Get(context.Background(), "/kept"); err != nil || string(v) != "v" {
			t.Fatalf("%s lacks the recovered state: %v", r.name, err)
		}
	}
	// Replayed: the intent is recorded as applied, so nothing happens.
	c.decrees.mu.Lock()
	delete(c.decrees.status, rec)
	c.decrees.mu.Unlock()
	eventually(t, 5*time.Second, "replay recorded as already applied", func() bool { st, ok := c.decrees.get(rec); return ok && st.AppliedEpoch != nil })
	if st := c.leader().node.Status(); len(st.Voters) != 3 {
		t.Fatalf("replayed Recover changed the configuration: %+v", st)
	}
}

// A clock jump stops a replica serving until it has contact made after the
// jump: a follower hears from the leader, a leader confirms its quorum.
func TestClockJump(t *testing.T) {
	ms := time.Millisecond
	for _, r := range []struct {
		wall, mono time.Duration
		want       bool
	}{{200 * ms, 200 * ms, false}, {time.Second, 200 * ms, false}, {3 * time.Second, 200 * ms, true},
		{-3 * time.Second, 200 * ms, true}, {6 * time.Second, 6 * time.Second, true}} {
		if got := clockJumped(r.wall, r.mono); got != r.want {
			t.Errorf("wall %v mono %v: jumped %v", r.wall, r.mono, got)
		}
	}
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	for _, r := range c.live() {
		r.node.jumpAt.Store(time.Now().UnixMilli())
		if r.node.Serving() {
			t.Fatalf("%s serves right after a clock jump", r.name)
		}
	}
	for _, r := range c.live() {
		eventually(t, 5*time.Second, r.name+" serves after fresh contact", r.node.Serving)
	}
	l := c.leader()
	var f *replica
	for _, r := range c.live() {
		if r != l {
			f = r
		}
	}
	// Contact from before the jump does not clear it.
	f.node.jumpAt.Store(time.Now().Add(2 * time.Second).UnixMilli())
	time.Sleep(500 * time.Millisecond)
	if f.node.jumpAt.Load() == 0 {
		t.Fatal("a follower cleared a jump on contact from before it")
	}
	c.partition(l.name, true) // the leader cannot confirm its quorum
	l.node.jumpAt.Store(time.Now().UnixMilli())
	time.Sleep(500 * time.Millisecond)
	if l.node.jumpAt.Load() == 0 {
		t.Fatal("a partitioned leader cleared a jump")
	}
}

// CatchUp waits for the leader's applied index; the control channel answers
// status and refuses unknown requests.
func TestCatchUpAndControl(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if err := l.al.PutWorkload("x", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	for _, r := range c.live() {
		if err := r.node.CatchUp(); err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		if r.node.fsm.AppliedIndex() < l.node.fsm.AppliedIndex() {
			t.Fatalf("%s not caught up", r.name)
		}
	}
	addr := l.node.cfg.Advertise
	var other *replica
	for _, r := range c.live() {
		if r != l {
			other = r
		}
	}
	st, err := other.node.call(addr, time.Second, controlRequest{Op: ctlStatus})
	if err != nil || st.Status == nil || !st.Member || st.Status.State != "Leader" {
		t.Fatalf("status over control: %+v %v", st, err)
	}
	if resp, err := other.node.call(addr, time.Second, controlRequest{Op: "nope"}); err != nil || resp.Err == "" {
		t.Fatalf("unknown control op: %+v %v", resp, err)
	}
	if resp, err := other.node.call(addr, time.Second, controlRequest{Op: ctlJoin, ID: "bad"}); err != nil || resp.Err == "" {
		t.Fatalf("malformed join accepted: %+v %v", resp, err)
	}
	c.partition(other.name, true)
	if err := other.node.CatchUp(); err == nil {
		t.Fatal("a partitioned replica caught up")
	}
}

func mustPKIX(t *testing.T, k *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Total loss: every replica gone. The sealed backup, opened with the
// operator's recovery key, restores the cluster on fresh replicas with the
// same mesh CA, allowlist, spent tokens and secrets; a restore for another
// node, or of another snapshot, is refused.
func TestTotalLossRestoreFromBackup(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	ctx := context.Background()
	if err := l.al.PutWorkload("kept", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	if err := l.al.ConsumeToken("h.p.spent"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := l.sec.PutIfAbsent(ctx, "/kept", []byte("secret-v"), secrets.WorkloadHolder("w")); err != nil {
		t.Fatal(err)
	}
	fp := l.node.Status().CAFingerprint
	want := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "a backup of the latest state", func() bool {
		b, ok := c.backups.get()
		return ok && b.Meta.Index >= want-1 && b.Meta.CAFingerprint == fp
	})
	bk, _ := c.backups.get()
	ver, _ := l.al.Version()
	for _, r := range c.live() {
		c.stopReplica(r)
	}

	snap, err := OpenBackup(c.recKey, bk)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range []string{"n0", "n1", "n2"} {
		c.start(n, "m1")
	}
	eventually(t, 5*time.Second, "fresh replicas await a restore", func() bool {
		for _, r := range c.live() {
			if !r.node.AwaitingRestore() {
				return false
			}
		}
		return true
	})
	sign := func(node string, s []byte) SignedDecree {
		return signDecree(t, c.opKey, Decree{Kind: Restore, BootstrapNode: node, SnapshotSHA256: SnapshotSHA256(s)})
	}
	if _, err := c.nodes["n1"].node.Restore(ctx, sign("n0", snap), snap); !errors.Is(err, ErrNotForThisNode) {
		t.Fatalf("a restore for another node: %v", err)
	}
	if _, err := c.nodes["n0"].node.Restore(ctx, sign("n0", snap), append([]byte(" "), snap...)); err == nil {
		t.Fatal("a snapshot other than the one the decree names was restored")
	}
	res, err := c.nodes["n0"].node.Restore(ctx, sign("n0", snap), snap)
	if err != nil {
		t.Fatalf("restore: %v %+v", err, res)
	}
	c.settled(15 * time.Second)
	for _, r := range c.live() {
		if r.node.AwaitingRestore() {
			t.Fatalf("%s still awaits a restore", r.name)
		}
		if r.node.Status().CAFingerprint != fp {
			t.Fatalf("%s restored another mesh CA", r.name)
		}
		if v, err := r.sec.Get(ctx, "/kept"); err != nil || string(v) != "secret-v" {
			t.Fatalf("%s lost a secret: %v", r.name, err)
		}
		if v, _ := r.al.Version(); v != ver {
			t.Fatalf("%s allowlist version %s, want %s", r.name, v, ver)
		}
	}
	if err := c.nodes["n2"].al.ConsumeToken("h.p.spent-again"); !errors.Is(err, operatorauth.ErrTokenReused) {
		t.Fatalf("restore forgot a spent token: %v", err)
	}
	if err := c.nodes["n1"].al.PutWorkload("after-restore", mkWorkload(t, 0)); err != nil {
		t.Fatalf("write after restore: %v", err)
	}
}

// An expired Genesis does not start a cluster; a replica that has not joined
// refuses writes, and catch-up needs a leader.
func TestUnusableDecreesAndUnjoinedWrites(t *testing.T) {
	c := newCluster(t, 3)
	for _, n := range []string{"n0", "n1", "n2"} {
		c.start(n, "m1")
	}
	old := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0", ExpiresAt: time.Now().Add(-time.Minute)})
	time.Sleep(500 * time.Millisecond)
	if c.nodes["n0"].node.member() {
		t.Fatal("an expired Genesis started a cluster")
	}
	if _, ok := c.decrees.get(old); ok {
		t.Fatal("an expired Genesis was recorded as applied")
	}
	if err := c.nodes["n1"].al.PutWorkload("x", mkWorkload(t, 0)); err == nil {
		t.Fatal("a replica outside any cluster accepted a write")
	}
	if err := c.nodes["n1"].node.CatchUp(); err == nil {
		t.Fatal("caught up without a leader")
	}
	if _, err := c.nodes["n1"].node.CA(); err == nil {
		t.Fatal("a CA before Genesis")
	}
	g := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	eventually(t, 10*time.Second, "genesis", func() bool { st, ok := c.decrees.get(g); return ok && st.AppliedEpoch != nil })
	c.settled(15 * time.Second)
}

// A membership change after the last write must not stall backups: the
// backup catches up with no further write.
func TestBackupAfterMembershipChange(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	if err := c.leader().al.PutWorkload("last", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	c.start("n3", "m1") // joins: configuration entries, no command
	c.settled(10 * time.Second)
	l := c.leader()
	// Read-only barriers advance LastIndex without changing recoverable state.
	// Identify the actual configuration entry that added n3 instead.
	containsN3 := func(cfg raft.Configuration) bool {
		for _, server := range cfg.Servers {
			if server.ID == c.nodes["n3"].node.id {
				return true
			}
		}
		return false
	}
	first, err := l.node.logs.FirstIndex()
	if err != nil {
		t.Fatal(err)
	}
	last, err := l.node.logs.LastIndex()
	if err != nil {
		t.Fatal(err)
	}
	var target uint64
	for i := first; i <= last; i++ {
		var entry raft.Log
		if err := l.node.logs.GetLog(i, &entry); err != nil {
			t.Fatal(err)
		}
		if entry.Type == raft.LogConfiguration && containsN3(raft.DecodeConfiguration(entry.Data)) {
			target = entry.Index
		}
	}
	if target == 0 {
		t.Fatal("no retained configuration entry adding n3")
	}
	eventually(t, 10*time.Second, "a backup past the membership change", func() bool {
		b, ok := c.backups.get()
		return ok && b.Meta.Index >= target
	})
	metas, err := l.node.snaps.List()
	if err != nil || len(metas) == 0 {
		t.Fatalf("local snapshot: %v", err)
	}
	meta := metas[0]
	if meta.ConfigurationIndex < target || !containsN3(meta.Configuration) {
		t.Fatalf("local snapshot lacks n3 configuration: %+v, target %d", meta, target)
	}
	b, _ := c.backups.get()
	t.Logf("indices: raft=%d configuration=%d fsm=%d backup=%d snapshot=%d snapshot-config=%d", last, target, l.node.fsm.AppliedIndex(), b.Meta.Index, meta.Index, meta.ConfigurationIndex)
	// The local Raft snapshot retains membership. Exported application state
	// deliberately reconstructs membership under the operator's Restore decree.
}

// A pin set that unpins a majority of the voters is refused (it would leave no
// leader to apply the decree that undoes it); the upgrade order works: pin the
// new image beside the old, then drop the old once a majority runs the new.
func TestPinsMustKeepAMajority(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	bad := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: []string{"m2"}})
	eventually(t, 5*time.Second, "pin set refused", func() bool {
		st, ok := c.decrees.get(bad)
		return ok && strings.Contains(st.RejectedReason, "fewer than a majority")
	})
	if !c.leader().node.Serving() || c.leader().node.fsm.Core().Epoch != 1 {
		t.Fatal("the refused pin set changed the cluster")
	}
	both := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: []string{"m1", "m2"}})
	eventually(t, 5*time.Second, "both pinned", func() bool { st, ok := c.decrees.get(both); return ok && st.AppliedEpoch != nil })
}

// A Recover decree on a cluster whose leader holds a majority is refused,
// with a reason, even when it names a replica that is cut off; nothing
// changes, and the cut-off replica rejoins after the heal.
func TestRecoverRefusedWithQuorum(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	var cut *replica
	for _, r := range c.live() {
		if r != l {
			cut = r
			break
		}
	}
	c.partition(cut.name, true)
	eventually(t, 4*time.Second, "cut-off replica stops serving", func() bool { return !cut.node.Serving() })
	epoch := l.node.Core().Epoch
	rec := c.decree(Decree{Kind: Recover, BootstrapNode: cut.name, BaseEpoch: epoch})
	eventually(t, 5*time.Second, "recover refused", func() bool { _, ok := c.decrees.get(rec); return ok })
	if st, _ := c.decrees.get(rec); st.AppliedEpoch != nil || st.RejectedReason != ErrRecoverWithQuorum.Error() {
		t.Fatalf("Recover with a quorum: %+v", st)
	}
	// Past dead_after the cut-off replica must not recover itself either.
	time.Sleep(testTiming.DeadAfter + 500*time.Millisecond)
	if cut.node.r().State().String() == "Leader" || l.node.Core().Epoch != epoch {
		t.Fatalf("Recover took effect: cut-off state %s, epoch %d -> %d", cut.node.r().State(), epoch, l.node.Core().Epoch)
	}
	c.partition(cut.name, false)
	c.settled(15 * time.Second)
	if e := c.leader().node.Core().Epoch; e != epoch {
		t.Fatalf("epoch moved %d -> %d", epoch, e)
	}
}

// Ready (what a rolling restart waits for) holds back a restarted voter
// that serves as a new non-voter until the seats are full again; the
// others stay Ready.
func TestReadyWaitsForTheSeats(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2", "n3")
	eventually(t, 10*time.Second, "every replica ready", func() bool {
		for _, r := range c.live() {
			if !r.node.Ready() {
				return false
			}
		}
		return true
	})
	l := c.leader()
	var voter *replica
	for _, r := range c.live() {
		if r != l && r.node.isVoter() {
			voter = r
		}
	}
	c.stopReplica(voter)
	back := c.start(voter.name, "m1")
	early := false
	eventually(t, 15*time.Second, "restarted voter ready", func() bool {
		ready := back.node.Ready()
		if ready && !back.node.isVoter() {
			if st := c.leader().node.Status(); len(st.Voters) < 3 {
				early = true
			}
		}
		return ready
	})
	if early {
		t.Fatal("a restarted voter was Ready as a non-voter while a seat was free")
	}
	if st := c.leader().node.Status(); !st.SeatsFilled || len(st.Voters) != 3 {
		t.Fatalf("leader reports seats filled %v with %d voters", st.SeatsFilled, len(st.Voters))
	}
	// A voter failing heartbeats leaves its seat unfilled.
	l = c.leader()
	other := slices.DeleteFunc(l.node.Status().Voters, func(id string) bool { return id == l.node.ID() })[0]
	l.node.mu.Lock()
	l.node.failing[raft.ServerID(other)] = time.Now()
	l.node.mu.Unlock()
	if l.node.seatsFilled() {
		t.Fatal("seats filled with a failing voter")
	}
}

// The operator changes the voter count with a signed decree: the leader
// promotes healthy non-voters into new seats, and demotes voters (never
// itself) when seats go away; writes keep working throughout. Every replica,
// and a later joiner, holds the same decree record.
func TestSetVotersGrowsAndShrinks(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	c.start("n3", "m1")
	c.start("n4", "m1")
	voters := func() int {
		l := c.leader()
		if l == nil {
			return -1
		}
		return len(l.node.Status().Voters)
	}
	eventually(t, 15*time.Second, "5 members, 3 voters", func() bool {
		l := c.leader()
		return l != nil && len(l.node.Status().Voters) == 3 && len(l.node.Status().NonVoters) == 2
	})
	even := c.decree(Decree{Kind: SetVoters, BaseEpoch: 1, Voters: 4})
	eventually(t, 10*time.Second, "even voter count refused", func() bool { st, ok := c.decrees.get(even); return ok && st.RejectedReason != "" })
	grow := c.decree(Decree{Kind: SetVoters, BaseEpoch: 1, Voters: 5})
	eventually(t, 10*time.Second, "SetVoters 5 applied", func() bool { st, ok := c.decrees.get(grow); return ok && st.AppliedEpoch != nil })
	eventually(t, 15*time.Second, "5 voters", func() bool { return voters() == 5 })
	if s := c.leader().node.Status().Seats; s != 5 {
		t.Fatalf("status seats %d", s)
	}
	if _, err := c.leader().sec.Put(t.Context(), "/five", []byte("v")); err != nil {
		t.Fatal(err)
	}
	shrink := c.decree(Decree{Kind: SetVoters, BaseEpoch: 2, Voters: 3})
	eventually(t, 10*time.Second, "SetVoters 3 applied", func() bool { st, ok := c.decrees.get(shrink); return ok && st.AppliedEpoch != nil })
	eventually(t, 15*time.Second, "3 voters again", func() bool { return voters() == 3 })
	for i, r := range c.live() {
		if _, err := r.sec.Put(t.Context(), fmt.Sprintf("/three/%d", i), []byte("v")); err != nil {
			t.Fatalf("write via %s: %v", r.name, err)
		}
		eventually(t, 5*time.Second, "serving "+r.name, func() bool { return r.node.Status().Serving })
	}
	for _, r := range c.live() {
		eventually(t, 5*time.Second, "decree record on "+r.name, func() bool {
			rec := r.node.Decrees()
			return len(rec) == 3 && rec[1].Epoch == 2 && rec[2].Epoch == 3 && rec[2].Decree.Decree.Voters == 3
		})
	}
	j := c.start("n5", "m1")
	eventually(t, 15*time.Second, "joiner has the record", func() bool { return len(j.node.Decrees()) == 3 })
}

// The leader bounds the allowlist history through the log, so every replica
// keeps the same newest entries; a joiner takes the pruned history.
func TestLeaderPrunesTheHistoryEverywhere(t *testing.T) {
	saved := pruneSlack
	pruneSlack = 2
	t.Cleanup(func() { pruneSlack = saved })
	c := newCluster(t, 3)
	c.historyVersions = 5
	c.genesis("n0", "n1", "n2")
	for i := range 12 {
		if err := c.leader().al.PutWorkload(fmt.Sprintf("w%d", i), mkWorkload(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range c.live() {
		eventually(t, 10*time.Second, "pruned on "+r.name, func() bool { n, _ := r.al.HistoryLen(); return n <= 5+2 && n >= 5 })
	}
	want, _ := c.leader().al.History()
	for _, r := range c.live() {
		eventually(t, 5*time.Second, "same history on "+r.name, func() bool {
			got, _ := r.al.History()
			return fmt.Sprint(got) == fmt.Sprint(want)
		})
	}
}

// A byte budget bounds the history by document size: the leader turns it
// into a count, so every replica keeps the same entries.
func TestLeaderPrunesTheHistoryByBytes(t *testing.T) {
	c := newCluster(t, 3)
	c.historyBytes = 1    // any document exceeds it: only the served one stays
	c.historyVersions = 3 // the tighter bound wins
	c.genesis("n0", "n1", "n2")
	for i := range 5 {
		if err := c.leader().al.PutWorkload(fmt.Sprintf("w%d", i), mkWorkload(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range c.live() {
		eventually(t, 10*time.Second, "pruned to the head on "+r.name, func() bool { n, _ := r.al.HistoryLen(); return n == 1 })
	}
}

// The leader renews the shared mesh CA certificate past half its lifetime,
// through the log: every replica ends up serving the same new certificate,
// under the same key, so workloads keep their trust anchor.
func TestLeaderRenewsTheMeshCACertificate(t *testing.T) {
	c := newCluster(t, 3)
	c.caValidity = 4 * time.Second
	c.genesis("n0", "n1", "n2")
	first := c.leader().node.fsm.CA().Cert
	time.Sleep(time.Until(first.NotBefore.Add(c.caValidity/2 - 500*time.Millisecond)))
	if ca := c.leader().node.fsm.CA(); !bytes.Equal(ca.Cert.Raw, first.Raw) {
		t.Fatal("renewed before half the certificate's life")
	}
	eventually(t, 15*time.Second, "every replica on one renewed certificate", func() bool {
		var seen []byte
		for _, r := range c.live() {
			ca := r.node.fsm.CA()
			if ca == nil || bytes.Equal(ca.Cert.Raw, first.Raw) || (seen != nil && !bytes.Equal(ca.Cert.Raw, seen)) {
				return false
			}
			seen = ca.Cert.Raw
		}
		return seen != nil
	})
	renewed := c.leader().node.fsm.CA().Cert
	if !bytes.Equal(renewed.RawSubjectPublicKeyInfo, first.RawSubjectPublicKeyInfo) || !renewed.NotAfter.After(first.NotAfter) {
		t.Fatal("the renewal changed the key or did not extend the certificate")
	}
	if err := issuer.RenewalOf(first, renewed); err != nil {
		t.Fatal(err)
	}
	// The served status names the new certificate on every replica.
	fp := c.leader().node.Status().CAFingerprint
	for _, r := range c.live() {
		if r.node.Status().CAFingerprint != fp {
			t.Fatalf("%s reports another CA", r.name)
		}
	}
}

// A rollout: old and new replicas share the group in the old format; the
// format rises only once the last old replica is gone, and from then on a
// replica of the old release cannot join.
func TestFormatRisesOnlyWhenEveryMemberReadsIt(t *testing.T) {
	c := newCluster(t, 3)
	next := Format + 1
	c.reads["n0"], c.reads["n1"] = next, next
	c.genesis("n0", "n1", "n2")
	if _, err := c.nodes["n0"].sec.Put(t.Context(), "/before", []byte("v")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * testTiming.Tick)
	for _, r := range c.live() {
		if f := r.node.Core().format(); f != Format {
			t.Fatalf("%s: format %d with an old replica in the group", r.name, f)
		}
	}
	// Roll the old replica to the new release.
	c.stopReplica(c.nodes["n2"])
	c.reads["n2"] = next
	c.start("n2", "m1")
	c.settled(15 * time.Second)
	eventually(t, 10*time.Second, "format raised everywhere", func() bool {
		for _, r := range c.live() {
			if r.node.Core().format() != next {
				return false
			}
		}
		return true
	})
	for _, r := range c.live() {
		if st := r.node.Status(); !st.Serving || st.Stuck != "" {
			t.Fatalf("%s after the raise: %+v", r.name, st)
		}
		eventually(t, 3*time.Second, "secret on "+r.name, func() bool { v, _ := r.sec.Get(t.Context(), "/before"); return string(v) == "v" })
	}
	// Replicas of the old release are refused and never serve. Each hears
	// the other as a loner but the cluster as a member, so neither offers to
	// take a restore.
	c.reads["n3"], c.reads["n4"] = Format, Format
	olds := []*replica{c.start("n3", "m1"), c.start("n4", "m1")}
	time.Sleep(2 * time.Second)
	for _, old := range olds {
		if st := old.node.Status(); st.Joined || st.Serving || old.node.AwaitingRestore() {
			t.Fatalf("old release after the raise: %+v, awaits a restore %v", st, old.node.AwaitingRestore())
		}
	}
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	if st := l.node.Status(); len(st.Voters)+len(st.NonVoters) != 3 {
		t.Fatalf("membership changed: %+v", st)
	}
}
