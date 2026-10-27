package cdsha

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// A kube API server that accepts and never answers must not stall the
// leader's membership, prune and stuck-exit duties (they used to share a
// loop with the decree List and the backup writes).

func TestHungDecreeListDoesNotStallLeaderTick(t *testing.T) {
	old := pruneSlack
	pruneSlack = 0
	t.Cleanup(func() { pruneSlack = old })
	c := newCluster(t, 3)
	c.historyVersions = 5
	c.genesis("n0", "n1", "n2", "n3") // n3 a non-voter, ready to take a seat
	l := c.leader()
	hang := make(chan struct{})
	c.decrees.hang.Store(&hang)
	t.Cleanup(func() { c.decrees.hang.Store(nil); close(hang) })
	eventually(t, 5*time.Second, "leader blocked in List", func() bool { return c.decrees.hung.Load() > 0 })
	st := l.node.Status()
	var victim *replica
	for _, r := range c.live() {
		if r != l && slices.Contains(st.Voters, r.node.ID()) {
			victim = r
			break
		}
	}
	deadID := victim.node.ID()
	c.stopReplica(victim)
	for i := 0; i < 20; i++ {
		if err := l.al.PutWorkload(fmt.Sprintf("w%d", i%3), mkWorkload(t, i)); err != nil {
			t.Fatalf("write during the hang: %v", err)
		}
	}
	// The bounds without any hang: seat repair within DeadAfter +
	// Stabilize + Lease + some Ticks, prune within a Tick.
	bound := testTiming.DeadAfter + testTiming.Stabilize + testTiming.Lease + 20*testTiming.Tick
	eventually(t, 2*bound, "seat repaired and history pruned while List hangs", func() bool {
		s := l.node.Status()
		hist, _ := l.al.HistoryLen()
		return !slices.Contains(s.Voters, deadID) && len(s.Voters) == 3 && hist <= c.historyVersions
	})
	if c.decrees.hung.Load() == 0 {
		t.Fatal("List never hung")
	}
}

func TestHungDecreeListDoesNotBlockStuckLeaderExit(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	hang := make(chan struct{})
	c.decrees.hang.Store(&hang)
	t.Cleanup(func() { c.decrees.hang.Store(nil); close(hang) })
	eventually(t, 5*time.Second, "leader blocked in List", func() bool { return c.decrees.hung.Load() > 0 })
	l.node.fsm.stopLocal(fmt.Errorf("test: local store fault"))
	select {
	case <-l.done:
	case <-time.After(testTiming.DeadAfter + 5*testTiming.Tick + 2*time.Second):
		t.Fatal("stuck leader kept running while the decree List hung")
	}
}

// The production client (client-go with rest.InClusterConfig's fields: no
// Timeout) and Run's context (no deadline), against an API server that
// accepts and never answers: every request ends at KubeDecrees.Timeout
// (unset here: DefaultTiming.Apply).
func TestKubeDecreesRequestsHaveDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { close(block); srv.Close() })
	kc, err := kubernetes.NewForConfig(&rest.Config{Host: "http://" + ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	kd := KubeDecrees{Client: kc, Namespace: "ns", ClusterID: "c1"} // Timeout unset: DefaultTiming.Apply
	bound := DefaultTiming.Apply
	calls := map[string]func(context.Context) error{
		"PendingDecrees":  func(ctx context.Context) error { _, err := kd.PendingDecrees(ctx); return err },
		"SetDecreeStatus": func(ctx context.Context) error { return kd.SetDecreeStatus(ctx, "x", DecreeStatus{}) },
		"PutBackup":       func(ctx context.Context) error { return kd.PutBackup(ctx, Backup{Meta: BackupMeta{ClusterID: "c1"}}) },
	}
	var wg sync.WaitGroup
	for name, call := range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			done := make(chan error, 1)
			go func() { done <- call(context.Background()) }() // Run's context: no deadline
			select {
			case err := <-done:
				if err == nil {
					t.Errorf("%s: no error from a server that never answers", name)
				}
				if took := time.Since(start); took > bound+2*time.Second {
					t.Errorf("%s returned after %v (bound %v)", name, took, bound)
				}
			case <-time.After(bound + 5*time.Second):
				t.Errorf("%s still blocked after %v", name, bound+5*time.Second)
			}
		}()
	}
	wg.Wait()
}

// Decrees now apply on their own goroutine; one never commits in the
// middle of a membership pass (reconcile holds membershipMu throughout).
func TestDecreeWaitsForMembershipPass(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	l.node.membershipMu.Lock()
	grow := c.decree(Decree{Kind: SetVoters, BaseEpoch: 1, Voters: 5})
	time.Sleep(20 * testTiming.Tick)
	applied := l.node.Core().Epoch != 1
	l.node.membershipMu.Unlock()
	if applied {
		t.Fatal("decree committed while a membership pass held membershipMu")
	}
	eventually(t, 10*time.Second, "SetVoters applied after the pass", func() bool {
		st, ok := c.decrees.get(grow)
		return ok && st.AppliedEpoch != nil
	})
}

// SetVoters decrees land while reconcile repairs a seat: the seat count in
// force wins, the decree statuses are right, and the cluster serves.
func TestSetVotersDuringSeatRepair(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	c.start("n3", "m1")
	c.start("n4", "m1")
	c.start("n5", "m1")
	eventually(t, 15*time.Second, "6 members, 3 voters", func() bool {
		l := c.leader()
		return l != nil && len(l.node.Status().Voters) == 3 && len(l.node.Status().NonVoters) == 3
	})
	l := c.leader()
	var victim *replica
	for _, r := range c.live() {
		if r != l && slices.Contains(l.node.Status().Voters, r.node.ID()) {
			victim = r
			break
		}
	}
	deadID := victim.node.ID()
	c.stopReplica(victim)
	// Mid-repair: the dead voter is failing, reconcile is about to retire
	// it and promote a replacement.
	time.Sleep(testTiming.DeadAfter / 2)
	grow := c.decree(Decree{Kind: SetVoters, BaseEpoch: 1, Voters: 5})
	eventually(t, 15*time.Second, "SetVoters 5 applied", func() bool { st, ok := c.decrees.get(grow); return ok && st.AppliedEpoch != nil })
	shrink := c.decree(Decree{Kind: SetVoters, BaseEpoch: 2, Voters: 3})
	eventually(t, 15*time.Second, "SetVoters 3 applied", func() bool { st, ok := c.decrees.get(shrink); return ok && st.AppliedEpoch != nil })
	eventually(t, 20*time.Second, "3 live voters, the dead one gone", func() bool {
		l := c.leader()
		if l == nil {
			return false
		}
		s := l.node.Status()
		return len(s.Voters) == 3 && !slices.Contains(s.Voters, deadID) && len(s.Voters)+len(s.NonVoters) == 5 && s.SeatsFilled
	})
	for _, r := range c.live() {
		eventually(t, 5*time.Second, "serving "+r.name, func() bool { return r.node.Serving() })
	}
	for _, name := range []string{grow, shrink} {
		if st, _ := c.decrees.get(name); st.RejectedReason != "" {
			t.Fatalf("decree %s rejected: %s", name, st.RejectedReason)
		}
	}
}
