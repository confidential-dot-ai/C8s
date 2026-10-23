package cdsha

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// heldReadFSM blocks only command application. Raft continues to receive log
// entries and independent heartbeats. No FSM/store mutex is held by the hook.
type heldReadFSM struct {
	raft.FSM
	hold    atomic.Bool
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

// Preserve configuration-index tracking implemented by the embedded FSM.
// Embedding raft.FSM alone hides this optional interface from Raft.
func (f *heldReadFSM) StoreConfiguration(index uint64, configuration raft.Configuration) {
	f.FSM.(raft.ConfigurationStore).StoreConfiguration(index, configuration)
}

func (f *heldReadFSM) Apply(log *raft.Log) interface{} {
	if f.hold.Load() {
		f.once.Do(func() { close(f.entered) })
		<-f.release
	}
	return f.FSM.Apply(log)
}

func TestReadCertificateRejectsHeldFollowerApply(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	leader := c.leader()
	if err := leader.al.PutWorkload("revoked", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	if !leader.led.Record("cached-binding", "host") {
		t.Fatal("binding failed")
	}

	// Add a non-voter whose FSM can be paused without stopping its transport.
	cfg := soloConfig(t, "held", freeAddr(t), c.opPub, c.decrees)
	cfg.Seats = 3
	cfg.Peers = func(context.Context) ([]string, error) {
		var peers []string
		for _, r := range c.live() {
			peers = append(peers, r.node.cfg.Advertise)
		}
		return peers, nil
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	n.shutdown() // empty, unbootstrapped Raft; install the test-only FSM wrapper
	held := &heldReadFSM{FSM: n.fsm, entered: make(chan struct{}), release: make(chan struct{})}
	trans, err := n.transport()
	if err != nil {
		t.Fatal(err)
	}
	r, err := raft.NewRaft(n.rcfg, held, n.logs, n.stable, n.snaps, trans)
	if err != nil {
		t.Fatal(err)
	}
	n.rft.Store(r)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = n.Run(ctx) }()
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(held.release) }); cancel(); <-done })
	eventually(t, 10*time.Second, "wrapped follower serves", n.Serving)
	if err := n.CatchUp(); err != nil {
		t.Fatal(err)
	}
	before, err := cfg.Allowlist.Version()
	if err != nil {
		t.Fatal(err)
	}
	if host, ok := cfg.Ledger.Lookup("cached-binding"); !ok || host != "host" {
		t.Fatal("missing local binding")
	}
	held.hold.Store(true)
	if _, err := leader.al.DeleteWorkload("revoked"); err != nil {
		t.Fatal(err)
	}
	revokedIndex := leader.node.fsm.AppliedIndex()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("follower application did not stop")
	}
	// Observe more than a lease of live heartbeats while the state stays stale.
	deadline := time.Now().Add(2 * cfg.Timing.Lease)
	for time.Now().Before(deadline) {
		if lc := n.r().LastContact(); lc.IsZero() || time.Since(lc) >= cfg.Timing.Lease {
			t.Fatal("heartbeats stopped")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if n.fsm.AppliedIndex() >= revokedIndex {
		t.Fatal("held follower applied revocation")
	}
	if version, _ := cfg.Allowlist.Version(); version != before {
		t.Fatal("held policy changed")
	}
	if host, ok := cfg.Ledger.Lookup("cached-binding"); !ok || host != "host" {
		t.Fatal("cached binding unexpectedly disappeared")
	}
	if n.Serving() || n.Ready() {
		t.Fatal("stale follower admits reads or rollout")
	}
	if _, err := n.CA(); err == nil {
		t.Fatal("stale follower releases issuing CA")
	}
	if err := n.CatchUp(); err == nil {
		t.Fatal("held follower passed a read barrier")
	}
	release.Do(func() { close(held.release) })
	eventually(t, 5*time.Second, "applied follower serves again", n.Serving)
	if n.fsm.AppliedIndex() < revokedIndex {
		t.Fatal("serving before revocation applied")
	}
}

func TestReadBarrierLeaderWithoutQuorumFails(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	leader := c.leader()
	c.partition(leader.name, true)
	// Immediately after isolation it may still believe it leads. CatchUp must
	// not accept that state as proof of a fresh read.
	if err := leader.node.CatchUp(); err == nil {
		t.Fatal("isolated leader passed CatchUp without a quorum")
	}
	eventually(t, 3*time.Second, "isolated leader certificate expires", func() bool { return !leader.node.Serving() })
}

// A delayed reply keeps the request-start timestamp. Identity and age checks
// also apply at admission, not only when a worker receives the certificate.
func TestReadCertificateIdentityAndExpiry(t *testing.T) {
	n := newSolo(t, nil).node
	cert, err := n.confirmRead(n.cfg.Timing.Apply)
	if err != nil {
		t.Fatal(err)
	}
	if !n.validReadCertificate(cert) {
		t.Fatal("healthy certificate refused")
	}
	for name, mutate := range map[string]func(*readCertificate){
		"delayed response": func(c *readCertificate) { c.at = time.Now().Add(-n.cfg.Timing.Lease) },
		"old leader":       func(c *readCertificate) { c.leaderID = "old/leader" },
		"old address":      func(c *readCertificate) { c.leader = "old:1" },
		"old term":         func(c *readCertificate) { c.term++ },
		"old epoch":        func(c *readCertificate) { c.epoch++ },
		"old raft":         func(c *readCertificate) { c.raft = nil },
	} {
		t.Run(name, func(t *testing.T) {
			stale := *cert
			mutate(&stale)
			if n.validReadCertificate(&stale) {
				t.Fatal("obsolete certificate admitted")
			}
		})
	}
}

func TestReadCertificateInvalidAfterLeaderChange(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	old := c.leader()
	var follower *Node
	for _, r := range c.live() {
		if r != old {
			follower = r.node
			break
		}
	}
	cert, err := follower.confirmRead(follower.cfg.Timing.Apply)
	if err != nil {
		t.Fatal(err)
	}
	c.partition(old.name, true)
	eventually(t, 5*time.Second, "new leader identity", func() bool {
		addr, id := follower.r().LeaderWithID()
		return addr != "" && id != cert.leaderID
	})
	// Keep its age young to show identity invalidation, not lease expiration.
	cert.at = time.Now()
	if follower.validReadCertificate(cert) {
		t.Fatal("old leader certificate revived")
	}
	eventually(t, 5*time.Second, "new leader certificate serves", follower.Serving)
}

func TestReadCertificateRejectsDelayedOldLeaderResponse(t *testing.T) {
	c := newCluster(t, 3)
	var hold atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	var enteredOnce, releaseOnce sync.Once
	c.startWithControl("n0", "m1", func(next controlHandler) controlHandler {
		return func(peer Claims, req controlRequest) controlResponse {
			resp := next(peer, req)
			if req.Op == ctlReadBarrier && resp.Err == "" && hold.Load() {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}
			return resp
		}
	})
	c.start("n1", "m1")
	c.start("n2", "m1")
	g := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	eventually(t, 10*time.Second, "genesis applied", func() bool { st, ok := c.decrees.get(g); return ok && st.AppliedEpoch != nil })
	c.settled(15 * time.Second)
	// Release blocked handlers before cluster cleanup shuts down Raft.
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	old := c.nodes["n0"]
	if !old.node.leading() {
		t.Fatal("bootstrap leader unexpectedly changed")
	}
	follower := c.nodes["n1"].node
	hold.Store(true)
	result := make(chan error, 1)
	go func() { _, err := follower.confirmRead(5 * time.Second); result <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read response was not held")
	}
	if err := old.node.r().LeadershipTransferToServer(follower.id, follower.raftAddress()).Error(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 3*time.Second, "transferred leader", follower.leading)
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("delayed old leader response revived freshness")
		}
	case <-time.After(6 * time.Second):
		t.Fatal("read confirmation did not finish")
	}
	eventually(t, 5*time.Second, "fresh new-term certificate", follower.Serving)
}

// Timed-out reads must leave only one pending Barrier future, even when the
// leader FSM cannot finish applying a command. Releasing it must allow clean
// cancellation and shutdown (including the periodic read worker).
func TestReadBarrierStalledFSMBoundsWaitersAndShutsDown(t *testing.T) {
	key, pub := operatorKey(t)
	ds := newMemDecrees()
	cfg := soloConfig(t, "stalled", freeAddr(t), pub, ds)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	n.shutdown()
	held := &heldReadFSM{FSM: n.fsm, entered: make(chan struct{}), release: make(chan struct{})}
	trans, err := n.transport()
	if err != nil {
		t.Fatal(err)
	}
	r, err := raft.NewRaft(n.rcfg, held, n.logs, n.stable, n.snaps, trans)
	if err != nil {
		t.Fatal(err)
	}
	n.rft.Store(r)
	var release sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = n.Run(ctx) }()
	t.Cleanup(func() { release.Do(func() { close(held.release) }); cancel(); <-done })
	ds.put(signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "stalled"}))
	eventually(t, 10*time.Second, "stalled test leader serves", n.Serving)
	held.hold.Store(true)
	applied := make(chan error, 1)
	go func() { applied <- r.Apply([]byte(`{}`), time.Second).Error() }()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("FSM not held")
	}
	if _, err := n.readBarrier(r, 20*time.Millisecond); err == nil {
		t.Fatal("blocked Barrier succeeded")
	}
	baseline := runtime.NumGoroutine()
	lastIndex := r.LastIndex()
	for i := 0; i < 20; i++ {
		if _, err := n.readBarrier(r, 10*time.Millisecond); err == nil {
			t.Fatal("blocked Barrier succeeded")
		}
		if len(n.barrierGate) != 1 {
			t.Fatal("pending future lost its single-flight token")
		}
	}
	if got := r.LastIndex(); got != lastIndex {
		t.Fatalf("timed-out reads queued more barriers: before=%d after=%d", lastIndex, got)
	}
	if got := runtime.NumGoroutine(); got > baseline+4 {
		t.Fatalf("timed-out barriers accumulated goroutines: before=%d after=%d", baseline, got)
	}
	cancel()
	release.Do(func() { close(held.release) })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("read worker or Raft shutdown did not finish")
	}
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("command future did not finish")
	}
	eventually(t, time.Second, "pending barrier releases token", func() bool { return len(n.barrierGate) == 0 })
}
