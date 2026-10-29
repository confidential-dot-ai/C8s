package cdsha

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// runEnded reports whether r's Run has returned.
func runEnded(r *replica) bool {
	select {
	case <-r.done:
		return true
	default:
		return false
	}
}

// noRunEnds fails if any of rs ends Run within d.
func noRunEnds(t *testing.T, d time.Duration, rs ...*replica) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, r := range rs {
			if runEnded(r) {
				t.Fatalf("%s: Run ended (stuck %q): a deterministic stop must keep the process and its log", r.name, r.node.fsm.Stuck())
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func secretPut(path, value string) *secrets.Command {
	return &secrets.Command{Op: secrets.OpPut, Path: path, Value: []byte(value)}
}

// A committed entry that every replica rejects halts the cluster but does not wipe
// it: no replica exits, each keeps its log and membership, serves nothing,
// refuses writes and reports the stop as not local. An operator can still
// give up the tail and Restore the last backup.
func TestPoisonEntryHaltsWithoutWipingTheCluster(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2", "n3") // n3: a non-voter
	l := c.leader()
	if err := l.al.PutWorkload("before", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	want := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "backup of the pre-poison state", func() bool { b, ok := c.backups.get(); return ok && b.Meta.Index >= want })
	_, err := l.node.applyEntry(Entry{Kind: EntryKind("poison")})
	t.Logf("leader Apply of the poison entry returned: %v", err)
	poisonAt := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "every replica stopped", func() bool {
		for _, r := range c.live() {
			if r.node.fsm.Stuck() == "" {
				return false
			}
		}
		return true
	})
	noRunEnds(t, testTiming.DeadAfter+testTiming.Lease+2*time.Second, c.live()...)
	for _, r := range c.live() {
		st := r.node.Status()
		if st.StuckLocal || st.Serving || !strings.Contains(st.Stuck, "poison") {
			t.Fatalf("%s: %+v", r.name, st)
		}
		if !r.node.member() || r.node.r().LastIndex() < poisonAt {
			t.Fatalf("%s: member %v, last log index %d < poison %d", r.name, r.node.member(), r.node.r().LastIndex(), poisonAt)
		}
		if reason := r.node.StuckOverdue(); reason != "" {
			t.Fatalf("%s: watchdog would exit: %q", r.name, reason)
		}
		if err := r.al.PutWorkload("after-"+r.name, mkWorkload(t, 1)); err == nil {
			t.Fatalf("%s: a halted replica took a write", r.name)
		}
	}
	h := c.leader()
	if h == nil {
		t.Fatal("no leader: a halted cluster keeps one, so its membership and log stay")
	}
	eventually(t, 5*time.Second, "the halted leader reports failing backups", func() bool {
		l := c.leader()
		return l != nil && strings.Contains(l.node.Status().BackupError, "snapshot")
	})
	// The operator gives up the tail: restart every replica and Restore.
	b, _ := c.backups.get()
	for _, r := range c.live() {
		c.stopReplica(r)
		c.start(r.name, "m1")
	}
	eventually(t, 10*time.Second, "replicas await a restore", func() bool {
		for _, r := range c.live() {
			if !r.node.AwaitingRestore() {
				return false
			}
		}
		return true
	})
	snap, err := OpenBackup(c.recKey, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.nodes["n0"].node.Restore(context.Background(), signDecree(t, c.opKey, Decree{Kind: Restore, BootstrapNode: "n0", TargetMember: c.nodes["n0"].node.ID(), SnapshotSHA256: SnapshotSHA256(snap)}), snap); err != nil {
		t.Fatalf("restore: %v", err)
	}
	c.settled(20 * time.Second)
}

// A deterministic stop while the replica cannot reach the leader: nothing
// shows the cluster past its entry, so it must not exit. Once the leader
// answers past the entry, the stop was this replica's own and it exits.
func TestDeterministicStopDuringPartitionDoesNotExit(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	var f *replica
	for _, r := range c.live() {
		if r != l {
			f = r
			break
		}
	}
	c.partition(f.name, true)
	f.node.fsm.stop(errors.New("test: deterministic stop"))
	if err := l.al.PutWorkload("w", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	noRunEnds(t, testTiming.DeadAfter+testTiming.Lease+2*time.Second, f)
	if f.node.StuckOverdue() != "" {
		t.Fatal("watchdog would exit a deterministic stop")
	}
	c.partition(f.name, false)
	select {
	case <-f.done:
	case <-time.After(testTiming.DeadAfter + 10*time.Second):
		t.Fatal("the leader is past the entry, yet the stopped replica kept running")
	}
}

// Version skew: a replica of an older image cannot read an entry the
// cluster applies (here an entry needing Format+1, written without the
// format gate). The serving leader is past it, so the old replica exits
// (it rejoins, or crash-loops visibly until it runs the newer image) and
// the others serve on.
func TestOlderReplicaExitsWhenTheClusterPassesTheEntry(t *testing.T) {
	c := newCluster(t, 3)
	c.reads["n0"], c.reads["n1"] = Format+1, Format+1
	c.genesis("n0", "n1", "n2")
	old := c.nodes["n2"]
	eventually(t, 10*time.Second, "a new-image leader", func() bool {
		l := c.leader()
		if l == old {
			_ = l.node.r().LeadershipTransfer().Error()
			return false
		}
		return l != nil
	})
	l := c.leader()
	if _, err := l.node.applyEntry(Entry{Kind: KindSecret, Format: Format + 1, Secret: secretPut("/skew", "v")}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.done:
	case <-time.After(testTiming.DeadAfter + 10*time.Second):
		t.Fatalf("the old replica kept running: %+v", old.node.Status())
	}
	if old.node.fsm.StuckLocal() {
		t.Fatal("an unreadable entry was taken for a local fault")
	}
	for _, name := range []string{"n0", "n1"} {
		r := c.nodes[name]
		eventually(t, 5*time.Second, name+" serves the entry", func() bool {
			v, _ := r.sec.Get(t.Context(), "/skew")
			return r.node.Serving() && string(v) == "v"
		})
	}
}

// The no-loss recovery of a halted cluster: an image that applies the
// entry is rolled out one replica at a time. The halted leader admits and
// promotes the new replicas and hands them the lead; the writes after the
// last backup and the entry itself survive.
func TestNewerImageRecoversAHaltedCluster(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if err := l.al.PutWorkload("before", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	want := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "backup", func() bool { b, ok := c.backups.get(); return ok && b.Meta.Index >= want })
	c.backups.mu.Lock()
	c.backups.err = errors.New("test: backups paused") // the tail since the last backup
	c.backups.mu.Unlock()
	if _, err := l.sec.Put(t.Context(), "/tail", []byte("v")); err != nil {
		t.Fatal(err)
	}
	if _, err := l.node.applyEntry(Entry{Kind: KindSecret, Format: Format + 1, Secret: secretPut("/poison", "p")}); err == nil {
		t.Fatal("old replicas applied an entry in a newer format")
	}
	eventually(t, 5*time.Second, "every replica stopped", func() bool {
		for _, r := range c.live() {
			if r.node.fsm.Stuck() == "" {
				return false
			}
		}
		return true
	})
	noRunEnds(t, testTiming.DeadAfter+testTiming.Lease+time.Second, c.live()...)
	for _, name := range []string{"n0", "n1", "n2"} {
		c.stopReplica(c.nodes[name]) // a crash if Run already ended
		c.reads[name] = Format + 1
		nr := c.start(name, "m1")
		eventually(t, 30*time.Second, name+" of the new image holds a seat", func() bool {
			l := c.leader()
			if l == nil {
				return false
			}
			st := l.node.Status()
			return len(st.Voters) == 3 && func() bool {
				for _, v := range st.Voters {
					if v == nr.node.ID() {
						return true
					}
				}
				return false
			}()
		})
	}
	c.settled(30 * time.Second)
	for _, r := range c.live() {
		for path, v := range map[string]string{"/tail": "v", "/poison": "p"} {
			if got, _ := r.sec.Get(t.Context(), path); string(got) != v {
				t.Fatalf("%s: %s = %q after the recovery", r.name, path, got)
			}
		}
		if r.node.r().State() == raft.Leader && r.node.fsm.Stuck() != "" {
			t.Fatalf("%s: a stuck leader", r.name)
		}
	}
}

// A panic while applying an entry is a deterministic stop, not a crash:
// every replica would panic on the same entry.
func TestPanicInApplyStopsTheReplica(t *testing.T) {
	_, opPub := operatorKey(t)
	f := newTestFSM(t, opPub)
	f.ledger = nil // panics on use
	res := applyAt(f, 5, Entry{Kind: KindBinding, Binding: &sandboxledger.Command{SandboxID: "s", Host: "h"}})
	if _, ok := res.(error); !ok || !strings.Contains(f.Stuck(), "panic") || f.StuckLocal() {
		t.Fatalf("result %v, stuck %q, local %v", res, f.Stuck(), f.StuckLocal())
	}
	if f.AppliedIndex() != 5 {
		t.Fatalf("applied index %d", f.AppliedIndex())
	}
}
