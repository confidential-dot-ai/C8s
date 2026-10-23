package cdsha

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// solo is a one-seat cluster built without the cluster helper, so a test
// can choose the replica's configuration.
type solo struct {
	t       *testing.T
	opKey   *ecdsa.PrivateKey
	decrees *memDecrees
	node    *Node
	addr    string
}

func soloConfig(t *testing.T, name, addr string, opPub []byte, ds DecreeSource) Config {
	t.Helper()
	al, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	return Config{ClusterID: testCluster, NodeName: name, Bind: addr, Advertise: addr, Attestor: MockAttestor{"m1"},
		BakedPins: []string{"m1"}, OperatorPubKey: opPub, Seats: 1, MaxNonVoters: 8, Decrees: ds, Timing: testTiming,
		Peers:     func(context.Context) ([]string, error) { return nil, nil },
		Allowlist: &al, Secrets: secrets.NewMemoryStore(64, 8, 4096), Ledger: sandboxledger.New(time.Hour, 100), Logger: slog.New(slog.DiscardHandler)}
}

func runNode(t *testing.T, n *Node) {
	t.Helper()
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = n.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

func newSolo(t *testing.T, mutate func(*Config)) *solo {
	t.Helper()
	k, pub := operatorKey(t)
	s := &solo{t: t, opKey: k, decrees: newMemDecrees(), addr: freeAddr(t)}
	cfg := soloConfig(t, "n0", s.addr, pub, s.decrees)
	if mutate != nil {
		mutate(&cfg)
	}
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.node = n
	cfg.Allowlist.SetReplicator(n)
	runNode(t, n)
	g := s.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	s.applied(g, 1)
	eventually(t, 10*time.Second, "solo serving", n.Serving)
	return s
}

func (s *solo) decree(d Decree) string { return s.decrees.put(signDecree(s.t, s.opKey, d)) }

func (s *solo) applied(name string, epoch uint64) {
	s.t.Helper()
	eventually(s.t, 10*time.Second, name+" applied", func() bool {
		st, ok := s.decrees.get(name)
		return ok && st.AppliedEpoch != nil && *st.AppliedEpoch == epoch
	})
}

// A decree whose status cannot be written is applied once: the leader keeps
// trying to record it, and records the epoch it applied at.
func TestDecreeStatusWriteFailureIsRetriedNotReapplied(t *testing.T) {
	s := newSolo(t, nil)
	s.decrees.failList.Store(true)
	name := s.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: []string{"m1", "m2"}})
	time.Sleep(5 * testTiming.Tick)
	if s.node.Core().Epoch != 1 {
		t.Fatal("a decree applied while the decree source could not be read")
	}
	s.decrees.failStatus.Store(true)
	s.decrees.failList.Store(false)
	eventually(t, 5*time.Second, "decree applied", func() bool { return s.node.Core().Epoch == 2 })
	eventually(t, 5*time.Second, "status retried", func() bool { return s.decrees.statusErrs.Load() >= 2 })
	if _, ok := s.decrees.get(name); ok {
		t.Fatal("status recorded through a failing API")
	}
	s.decrees.failStatus.Store(false)
	s.applied(name, 2)
	if e := s.node.Core().Epoch; e != 2 {
		t.Fatalf("the decree applied again: epoch %d", e)
	}
}

// A RotateKey whose bundled pins drop the leader is refused before any key is minted.
func TestRotateKeyExcludingTheLeaderIsRefused(t *testing.T) {
	s := newSolo(t, nil)
	ca := s.node.Core().RootCert
	name := s.decree(Decree{Kind: RotateKey, BaseEpoch: 1, Measurements: []string{"m9"}})
	eventually(t, 5*time.Second, "decree rejected", func() bool { st, ok := s.decrees.get(name); return ok && st.RejectedReason != "" })
	st, _ := s.decrees.get(name)
	if !strings.Contains(st.RejectedReason, "excludes the leader") || string(s.node.Core().RootCert) != string(ca) {
		t.Fatalf("rejection %q, or the key changed", st.RejectedReason)
	}
}

// A store that refuses a backup for good stops the leader retrying it until
// the state changes; any other failure is retried.
func TestBackupFailuresAndRetries(t *testing.T) {
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, c := range map[string]struct {
		err   error
		retry bool
	}{
		"not newer":   {fmt.Errorf("wrapped: %w", ErrBackupNotNewer), false},
		"store fails": {errors.New("api down"), true},
	} {
		t.Run(name, func(t *testing.T) {
			b := &memBackups{err: c.err}
			s := newSolo(t, func(cfg *Config) { cfg.RecoveryKey, cfg.Backups = mustPKIX(t, &rk.PublicKey), b })
			eventually(t, 5*time.Second, "a backup attempt", func() bool { return b.attempts() > 0 })
			time.Sleep(10 * testTiming.Backup)
			if got := b.attempts(); (got > 1) != c.retry {
				t.Fatalf("%d attempts, retry %v", got, c.retry)
			}
			if c.retry {
				return
			}
			before := b.attempts()
			if err := s.node.cfg.Allowlist.PutWorkload("w", mkWorkload(t, 0)); err != nil {
				t.Fatal(err)
			}
			eventually(t, 5*time.Second, "a backup of the new state", func() bool { return b.attempts() > before })
		})
	}
}

// The leader refuses control requests from unpinned peers, malformed
// entries, and joins past the non-voter limit.
func TestLeaderControlRefusals(t *testing.T) {
	s := newSolo(t, func(cfg *Config) { cfg.MaxNonVoters = 1 })
	n := s.node
	pinned := Claims{Measurement: "m1"}
	if resp := n.handleControl(Claims{Measurement: "m9"}, controlRequest{Op: ctlJoin}); !strings.Contains(resp.Err, "not pinned") {
		t.Fatalf("unpinned peer: %+v", resp)
	}
	if resp := n.handleControl(pinned, controlRequest{Op: ctlApply, Entry: []byte(`{"kind":"nope"}`)}); resp.Err == "" {
		t.Fatalf("a malformed entry applied: %+v", resp)
	}
	if resp := n.handleControl(pinned, controlRequest{Op: ctlJoin, ID: n.ID(), Address: string(n.raftAddress()), Reads: Format}); resp.Err != "" || !resp.Member {
		t.Fatalf("a member asking to join again: %+v", resp)
	}
	join := func(node, hostport string) controlResponse {
		id := node + "/1-aa"
		return n.handleControl(pinned, controlRequest{Op: ctlJoin, ID: id, Address: hostport + "#" + id, Reads: Format})
	}
	if resp := join("x", "127.0.0.1:1"); resp.Err != "" {
		t.Fatalf("first non-voter: %+v", resp)
	}
	if resp := join("y", "127.0.0.1:2"); !strings.Contains(resp.Err, "no room") {
		t.Fatalf("a non-voter past the limit: %+v", resp)
	}
	// A new process at a member's address takes its place.
	if resp := join("z", "127.0.0.1:1"); resp.Err != "" {
		t.Fatalf("replacement at the same address: %+v", resp)
	}
	st := n.Status()
	if len(st.NonVoters) != 1 || st.NonVoters[0] != "z/1-aa" {
		t.Fatalf("non-voters %v", st.NonVoters)
	}
}

// Restore refuses a replica that is not started, a decree that is not a
// Restore, a replica in a cluster, and a reachable peer in one.
func TestRestoreRefusals(t *testing.T) {
	s := newSolo(t, nil)
	ctx := context.Background()
	snap := []byte("{}")
	restore := func(node string) SignedDecree {
		return signDecree(t, s.opKey, Decree{Kind: Restore, BootstrapNode: node, SnapshotSHA256: SnapshotSHA256(snap)})
	}
	_, pub := operatorKey(t)
	cold, err := NewNode(soloConfig(t, "n1", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cold.Restore(ctx, restore("n1"), snap); err == nil || !strings.Contains(err.Error(), "not started") {
		t.Fatalf("unstarted replica: %v", err)
	}
	if _, err := s.node.Restore(ctx, signDecree(t, s.opKey, Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: []string{"m1"}}), snap); err == nil ||
		!strings.Contains(err.Error(), "not a Restore") {
		t.Fatalf("not a Restore decree: %v", err)
	}
	if _, err := s.node.Restore(ctx, restore("n0"), snap); err == nil || !strings.Contains(err.Error(), "already belongs") {
		t.Fatalf("a member restoring: %v", err)
	}
	cfg := soloConfig(t, "n1", freeAddr(t), s.node.cfg.OperatorPubKey, nil)
	cfg.Peers = func(context.Context) ([]string, error) { return []string{s.addr}, nil }
	fresh, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.shutdown)
	if _, err := fresh.Restore(ctx, restore("n1"), snap); err == nil || !strings.Contains(err.Error(), "belongs to a cluster") {
		t.Fatalf("restore beside a live cluster: %v", err)
	}
	if fresh.member() {
		t.Fatal("the refused restore bootstrapped a cluster")
	}
}

// Recover and Genesis decrees a replica cannot use, or cannot read, do not start it.
func TestPendingBootstrapDecreesUnusable(t *testing.T) {
	k, pub := operatorKey(t)
	ds := newMemDecrees()
	expired := signDecree(t, k, Decree{IntentID: "r", Kind: Recover, BootstrapNode: "n0", ExpiresAt: time.Now().Add(-time.Minute)})
	ds.items["r"] = expired
	gen := signDecree(t, k, Decree{IntentID: "g", Kind: Genesis, BootstrapNode: "n0", ExpiresAt: time.Now().Add(-time.Minute)})
	ds.items["g"] = gen
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, ds))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, ok := n.pendingDecree(ctx, Recover); ok {
		t.Fatal("an expired Recover decree used")
	}
	if _, ok := n.pendingDecree(ctx, Genesis); ok {
		t.Fatal("an expired Genesis decree used")
	}
	ds.failList.Store(true)
	if _, ok := n.pendingDecree(ctx, Recover); ok {
		t.Fatal("a Recover decree from a failing source")
	}
	if _, ok := n.pendingDecree(ctx, Genesis); ok {
		t.Fatal("a Genesis decree from a failing source")
	}
	nodecrees, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := nodecrees.pendingDecree(ctx, Recover); ok {
		t.Fatal("a Recover decree without a decree source")
	}
}

func TestNewNodeAndStartErrors(t *testing.T) {
	_, pub := operatorKey(t)
	cfg := soloConfig(t, "n0", freeAddr(t), pub, nil)
	cfg.Timing = Timing{Heartbeat: 2 * time.Second}
	want := DefaultTiming
	want.Heartbeat = 2 * time.Second
	n, err := NewNode(cfg)
	if err != nil || n.cfg.Timing != want {
		t.Fatalf("unset timers not defaulted: %+v, %v", n.cfg.Timing, err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	bad := soloConfig(t, "n0", freeAddr(t), pub, nil)
	bad.RecoveryKey = mustPKIX(t, &p384.PublicKey)
	if _, err := NewNode(bad); err == nil {
		t.Fatal("a P-384 recovery key")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	busy := soloConfig(t, "n0", l.Addr().String(), pub, nil)
	n, err = NewNode(busy)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Run(context.Background()); err == nil {
		t.Fatal("ran on a port in use")
	}
	noAdv := soloConfig(t, "n0", "127.0.0.1:0", pub, nil)
	noAdv.Advertise = "not-an-address"
	n, err = NewNode(noAdv)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err == nil || !strings.Contains(err.Error(), "advertise") {
		t.Fatalf("an advertise address that does not resolve: %v", err)
	}
}

// Heartbeat failures from the replication stream of a member's earlier
// membership (last contact before it was added again) do not count; a
// member is dead only after dead_after from its last successful contact.
func TestNoteFailureIgnoresStaleStreams(t *testing.T) {
	n := &Node{failing: map[raft.ServerID]time.Time{}, addedAt: map[raft.ServerID]time.Time{}}
	id := raft.ServerID("n4/1-a")
	t0 := time.Now()
	n.addedAt[id] = t0
	n.noteFailure(id, t0.Add(-10*time.Second), t0.Add(time.Second))
	if _, bad := n.failing[id]; bad {
		t.Fatal("a failure from before the member joined counted")
	}
	// The current stream fails: measured from its last contact.
	n.noteFailure(id, t0.Add(2*time.Second), t0.Add(5*time.Second))
	if got := n.failing[id]; !got.Equal(t0.Add(2 * time.Second)) {
		t.Fatalf("failing since %v, want the last contact", got)
	}
	// A stream that never reached it: from the join, not earlier.
	other := raft.ServerID("n5/1-b")
	n.addedAt[other] = t0
	n.noteFailure(other, time.Time{}, t0.Add(3*time.Second))
	if got := n.failing[other]; !got.Equal(t0.Add(3 * time.Second)) {
		t.Fatalf("never contacted: failing since %v", got)
	}
	unknown := raft.ServerID("n6/1-c")
	n.noteFailure(unknown, t0.Add(-time.Minute), t0)
	if got := n.failing[unknown]; !got.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("member without a join time: %v", got)
	}
}

// A write that does not commit (here: a replica that has not joined) is
// reported as unavailable to both stores, so their handlers answer 503.
func TestReplicateFailureIsUnavailable(t *testing.T) {
	al, sec, led := testStores(t)
	n, err := NewNode(Config{ClusterID: testCluster, NodeName: "n0", Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1", Attestor: MockAttestor{"m1"},
		Seats: 3, Allowlist: al, Secrets: sec, Ledger: led})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.Replicate(allowlist.Command{Op: allowlist.OpConsumeToken, Token: "t"}); !errors.Is(err, allowlist.ErrUnavailable) {
		t.Errorf("allowlist: %v", err)
	}
	if _, err := n.ReplicateSecret(secrets.Command{Op: secrets.OpPut, Path: "/p", Value: []byte("v")}); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("secrets: %v", err)
	}
}

// A replica that reaches no peer (its node's pod network still coming up)
// does not offer to take a restore: that would route clients to its
// pre-join server.
func TestLonerDoesNotAwaitRestore(t *testing.T) {
	_, pub := operatorKey(t)
	cfg := soloConfig(t, "n0", freeAddr(t), pub, nil)
	cfg.Timing.DeadAfter = 300 * time.Millisecond
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runNode(t, n)
	time.Sleep(3 * cfg.Timing.DeadAfter)
	if n.AwaitingRestore() {
		t.Fatal("a replica that reached no peer reports it awaits a restore")
	}
}
