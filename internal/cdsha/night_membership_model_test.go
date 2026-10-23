package cdsha

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// No Run loop: the test schedules exactly one reconcile and one ctlJoin.
// Real Raft commits configuration changes; the existing control-call fault
// callback fences reconcile after its initial configuration capture.
func TestNightReconcileDoesNotResurrectReplacedIncarnation(t *testing.T) {
	key, pub := operatorKey(t)
	cfg := soloConfig(t, "n0", freeAddr(t), pub, nil)
	cfg.Seats = 3
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.shutdown()
	if err := n.r().BootstrapCluster(n.solo()).Error(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "leader", n.leading)
	ca := mustCA(t)
	der, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	genesis := DecreeEntry{Policy: n.fsm.LocalPolicy(), Decree: signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "n0"}), AtMS: time.Now().UnixMilli(), Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: der}
	resp, err := n.applyEntry(Entry{Kind: KindDecree, Decree: &genesis})
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resp.(DecreeResult); !ok || res.Err != "" {
		t.Fatalf("genesis: %#v", resp)
	}
	if _, err := n.readBarrier(n.r(), time.Second); err != nil {
		t.Fatalf("healthy initial quorum barrier: %v", err)
	}

	// Freeze only observer failure input. The schedule models an incarnation
	// healthy when captured, then replaced before promotion; failure detection
	// need not have fired yet in production either.
	worker := n.observer
	n.r().DeregisterObserver(worker.observer)
	worker.cancel()
	<-worker.done
	n.observer = nil
	old, replacement, suspect := raft.ServerID("x/1-old"), raft.ServerID("x/2-new"), raft.ServerID("suspect/1-old")
	oldHP, suspectHP := freeAddr(t), freeAddr(t)
	oldAddr := raft.ServerAddress(oldHP + "#" + string(old))
	for _, s := range []raft.Server{{ID: old, Address: oldAddr}, {ID: suspect, Address: raft.ServerAddress(suspectHP + "#" + string(suspect))}} {
		if err := n.r().AddNonvoter(s.ID, s.Address, 0, time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	n.mu.Lock()
	n.joinedAt[old] = time.Now().Add(-2 * n.cfg.Timing.Stabilize)
	n.addedAt[old] = n.joinedAt[old]
	n.failing[suspect] = time.Now().Add(-2 * n.cfg.Timing.DeadAfter)
	n.mu.Unlock()

	captured, release := make(chan struct{}), make(chan struct{})
	var capturedOnce, releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	defer unblock()
	// Start's transport captured nil; only the scheduled peerStatus call
	// reads this test callback. There is no Run loop or concurrent setter.
	n.blocked = func(addr string) bool {
		if addr == suspectHP {
			capturedOnce.Do(func() { close(captured) })
			<-release
		}
		return true
	}
	reconciled := make(chan struct{})
	go func() { defer close(reconciled); n.reconcile() }()
	defer func() {
		unblock()
		select {
		case <-reconciled:
		case <-time.After(5 * time.Second):
			t.Error("reconcile cleanup timed out")
		}
	}()
	select {
	case <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile did not capture configuration")
	}
	replacementNode, err := NewNode(soloConfig(t, "x", oldHP, pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	replacementNode.id = replacement
	if err := replacementNode.Start(); err != nil {
		t.Fatal(err)
	}
	defer replacementNode.shutdown()
	policy, err := json.Marshal(n.fsm.Core().Policy)
	if err != nil {
		t.Fatal(err)
	}
	joined := n.handleControl(Claims{Measurement: "m1"}, controlRequest{Op: ctlJoin, ID: string(replacement), Address: oldHP + "#" + string(replacement), Reads: Format, Entry: policy})
	if joined.Err != "" {
		t.Fatalf("replacement join: %s", joined.Err)
	}
	t.Logf("after successful replacement: %+v", n.servers())
	if slices.ContainsFunc(n.servers(), func(s raft.Server) bool { return s.ID == old }) {
		t.Fatal("join did not remove old incarnation")
	}
	if !slices.ContainsFunc(n.servers(), func(s raft.Server) bool { return s.ID == replacement }) {
		t.Fatal("join did not add replacement")
	}
	unblock()
	select {
	case <-reconciled:
	case <-time.After(5 * time.Second):
		t.Fatal("reconcile did not finish")
	}
	servers := n.servers()
	voters := 0
	for _, s := range servers {
		if s.Suffrage == raft.Voter {
			voters++
		}
	}
	t.Logf("after reconcile: %+v; voters=%d quorum=%d locallyLeading=%v", servers, voters, voters/2+1, n.leading())
	if slices.ContainsFunc(servers, func(s raft.Server) bool { return s.ID == old }) {
		_, barrierErr := n.readBarrier(n.r(), 250*time.Millisecond)
		t.Logf("after stale voter promotion: bounded quorum barrier error=%v; locallyLeading=%v", barrierErr, n.leading())
		t.Fatalf("reconcile resurrected removed incarnation: %+v", servers)
	}
	if _, err := n.readBarrier(n.r(), time.Second); err != nil {
		t.Fatalf("quorum lost after replacement: %v", err)
	}
	eventually(t, 5*time.Second, "replacement applied genesis", func() bool { return replacementNode.Core().Joined() })
	// Advance only the synthetic stabilization timestamp, not a timeout or
	// safety assertion. The replacement now runs a real reachable Raft node.
	n.mu.Lock()
	n.joinedAt[replacement] = time.Now().Add(-2 * n.cfg.Timing.Stabilize)
	n.mu.Unlock()
	n.reconcile()
	if !slices.ContainsFunc(n.servers(), func(s raft.Server) bool { return s.ID == replacement && s.Suffrage == raft.Voter }) {
		t.Fatalf("replacement did not become voter: %+v", n.servers())
	}
	if _, err := n.readBarrier(n.r(), time.Second); err != nil {
		t.Fatalf("replacement quorum cannot commit barrier: %v", err)
	}
}

// A real single-voter leader without a Run loop, for controlled concurrency.
func nightMembershipLeader(t *testing.T) (*Node, *ecdsa.PrivateKey) {
	t.Helper()
	key, pub := operatorKey(t)
	cfg := soloConfig(t, "n0", freeAddr(t), pub, newMemDecrees())
	cfg.Logger = slog.Default()
	cfg.Seats = 3
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(n.shutdown)
	if err := n.r().BootstrapCluster(n.solo()).Error(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "leader", n.leading)
	ca := mustCA(t)
	der, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	genesis := DecreeEntry{Policy: n.fsm.LocalPolicy(), Decree: signDecree(t, key, Decree{Kind: Genesis, BootstrapNode: "n0"}), AtMS: time.Now().UnixMilli(), Pins: []string{"m1"}, RootCert: ca.Cert.Raw, Key: der}
	resp, err := n.applyEntry(Entry{Kind: KindDecree, Decree: &genesis})
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := resp.(DecreeResult); !ok || res.Err != "" {
		t.Fatalf("genesis: %#v", resp)
	}
	return n, key
}

func TestNightConcurrentIncarnationJoinsKeepOneAddress(t *testing.T) {
	n, _ := nightMembershipLeader(t)
	policy, err := json.Marshal(n.fsm.Core().Policy)
	if err != nil {
		t.Fatal(err)
	}
	hp := freeAddr(t)
	const callers = 6
	start := make(chan struct{})
	replies := make(chan controlResponse, callers)
	for i := 0; i < callers; i++ {
		id := fmt.Sprintf("x/%d-new", i+1)
		go func() {
			<-start
			replies <- n.handleControl(Claims{Measurement: "m1"}, controlRequest{Op: ctlJoin, ID: id, Address: hp + "#" + id, Reads: Format, Entry: policy})
		}()
	}
	close(start)
	for i := 0; i < callers; i++ {
		select {
		case res := <-replies:
			if res.Err != "" {
				t.Fatalf("join: %s", res.Err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent joins did not complete")
		}
	}
	count := 0
	for _, s := range n.servers() {
		if addr, _ := splitRaftAddr(string(s.Address)); addr == hp {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("concurrent joins left %d incarnations at one address: %+v", count, n.servers())
	}
	if _, err := n.readBarrier(n.r(), time.Second); err != nil {
		t.Fatalf("quorum after concurrent joins: %v", err)
	}
}

func TestNightReconcileSnapshotCannotCrossRecovery(t *testing.T) {
	n, key := nightMembershipLeader(t)
	suspect := raft.ServerID("suspect/1-old")
	hp := freeAddr(t)
	if err := n.r().AddNonvoter(suspect, raft.ServerAddress(hp+"#"+string(suspect)), 0, time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	// RecoverCluster does not replay ConfigurationStore callbacks. A trailing
	// configuration alone exposes a separate replay-watermark bug (preserved
	// in recovery-fixture-debug.log). End this concurrency fixture with an
	// actual application entry; do not relax the post-recovery assertions.
	if _, err := n.applyEntry(Entry{Kind: KindFormat, SetFormat: Format}); err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	n.failing[suspect] = time.Now().Add(-2 * n.cfg.Timing.DeadAfter)
	n.mu.Unlock()
	captured, release := make(chan struct{}), make(chan struct{})
	var seen, once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	n.blocked = func(addr string) bool {
		if addr == hp {
			seen.Do(func() { close(captured) })
			<-release
		}
		return true
	}
	done := make(chan struct{})
	go func() { defer close(done); n.reconcile() }()
	defer func() {
		unblock()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("reconcile cleanup")
		}
	}()
	select {
	case <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("no captured snapshot")
	}
	old := n.r()
	sd := signDecree(t, key, Decree{Kind: Recover, BootstrapNode: "n0", BaseEpoch: n.Core().Epoch})
	// Direct invocation isolates the authorized recovery operation; normal Run
	// rejects Recover while quorum exists. This is a generation-race fixture,
	// not a claim that the leader normally performs break-glass recovery.
	n.recover(context.Background(), PendingDecree{Name: "controlled-recover", Decree: sd})
	if n.r() == old {
		t.Fatal("recovery did not replace generation")
	}
	if n.Core().Epoch != 2 {
		t.Fatalf("recovery epoch %d", n.Core().Epoch)
	}
	before := n.r().GetConfiguration().Configuration()
	unblock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stale reconcile did not finish")
	}
	after := n.r().GetConfiguration().Configuration()
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("old reconcile changed recovered config: before=%+v after=%+v", before, after)
	}
	if _, err := n.readBarrier(n.r(), time.Second); err != nil {
		t.Fatalf("recovered quorum: %v", err)
	}
}
