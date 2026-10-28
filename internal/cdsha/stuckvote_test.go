package cdsha

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// stuckEveryReplica stops every replica of a settled 3-replica cluster on
// its own store at the same entry (a store lock each one hits), keeps them
// stuck past every exit timer, then frees the stores. It returns the
// cluster, its leader and the index of the refused entry.
func stuckEveryReplica(t *testing.T) (*cluster, *replica, uint64) {
	t.Helper()
	c := newCluster(t, 3)
	c.fileStores = true
	c.genesis("n0", "n1", "n2")
	c.settled(30 * time.Second)
	l := c.leader()
	var locks []*sql.DB
	for _, r := range c.live() {
		lock, err := sql.Open("sqlite", r.alPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { lock.Close() })
		lock.SetMaxOpenConns(1)
		if _, err := lock.Exec(`BEGIN EXCLUSIVE`); err != nil {
			t.Fatal(err)
		}
		locks = append(locks, lock)
	}
	_ = l.al.PutWorkload("w", mkWorkload(t, 1)) // committed; every replica's store refuses it
	stop := l.node.r().LastIndex()
	eventually(t, 10*time.Second, "every replica stopped on its store", func() bool {
		for _, r := range c.live() {
			if !r.node.fsm.StuckLocal() {
				return false
			}
		}
		return true
	})
	time.Sleep(testTiming.DeadAfter + 2*testTiming.Lease)
	for _, lock := range locks {
		if _, err := lock.Exec(`ROLLBACK`); err != nil {
			t.Fatal(err)
		}
	}
	return c, l, stop
}

// replaceReplica restarts r (reading format reads) and waits until the
// leader lists the restarted replica as a voter and no longer the old one.
func replaceReplica(t *testing.T, c *cluster, r *replica) *replica {
	t.Helper()
	old := r.node.ID()
	c.stopReplica(r)
	again := c.start(r.name, "m1")
	eventually(t, 30*time.Second, r.name+" replaced as a voter", func() bool {
		ld := c.leader()
		if ld == nil {
			return false
		}
		st := ld.node.Status()
		return slices.Contains(st.Voters, again.node.ID()) && !slices.Contains(st.Voters, old)
	})
	return again
}

// checkpointJudged waits, at an operator's pace, until a leader that follows
// the log has a checkpoint past index stop that every live replica applied,
// and a round of digest reports has reached it (a replica that ended Run
// applies nothing more). Every replica in healthy
// must stay unstopped meanwhile.
func checkpointJudged(t *testing.T, c *cluster, stop uint64, healthy []*replica) {
	t.Helper()
	notStuck := func() {
		for _, h := range healthy {
			if s := h.node.fsm.Stuck(); s != "" {
				t.Fatalf("%s, which follows the log, stopped: %s", h.name, s)
			}
		}
	}
	eventually(t, 30*time.Second, "a checkpoint past the stop applied by every replica", func() bool {
		notStuck()
		ld := c.leader()
		if ld == nil || ld.node.fsm.Stuck() != "" {
			return false
		}
		cps := ld.node.fsm.dig.checkpointsCopy()
		if len(cps) == 0 || cps[len(cps)-1].Index <= stop {
			return false
		}
		for _, r := range c.live() {
			if !runEnded(r) && r.node.fsm.dig.latest().Index < cps[len(cps)-1].Index {
				return false
			}
		}
		return true
	})
	time.Sleep(2*testTiming.Lease + 2*testTiming.Tick) // reports go every Lease/3
	notStuck()
}

// After a store fault on every replica, the first restarted replica follows
// the log and leads; the two stuck voters, stopped at the same entry, hold
// the same wrong state. They must not outvote it at a checkpoint.
func TestHealthyReplacementNotOutvotedByStuckVoters(t *testing.T) {
	c, l, stop := stuckEveryReplica(t)
	var f *replica
	for _, r := range c.live() {
		if r != l {
			f = r
			break
		}
	}
	again := replaceReplica(t, c, f)
	eventually(t, 30*time.Second, "the replacement leads", func() bool { return c.leader() == again })
	checkpointJudged(t, c, stop, []*replica{again})
	for _, r := range c.live() {
		if r != again && (r.node.fsm.Stuck() == "" || r.node.Serving()) {
			t.Fatalf("%s: stuck %q, serving %v; want it stopped", r.name, r.node.fsm.Stuck(), r.node.Serving())
		}
	}
}

// A deterministic halt (an entry this image cannot read) on every replica;
// runbook 6's way out without loss: replace the replicas one at a time with
// an image that applies the entry. The fixed replicas must not be outvoted
// by the halted ones, and the last halted one leaves once they lead.
func TestDeterministicHaltRecoversWithFixedImageOneAtATime(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	c.settled(30 * time.Second)
	l := c.leader()
	if _, err := l.node.applyEntry(Entry{Kind: KindSecret, Format: Format + 1, Secret: secretPut("/fixed", "v")}); err != nil {
		t.Logf("apply of the unreadable entry: %v", err)
	}
	stop := l.node.r().LastIndex()
	eventually(t, 10*time.Second, "every replica halted", func() bool {
		for _, r := range c.live() {
			if r.node.fsm.Stuck() == "" || r.node.fsm.StuckLocal() {
				return false
			}
		}
		return true
	})
	var fixed []*replica
	for _, r := range c.live() {
		if r == l {
			continue
		}
		c.reads[r.name] = Format + 1
		fixed = append(fixed, replaceReplica(t, c, r))
		checkpointJudged(t, c, stop, fixed)
	}
	select {
	case <-l.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("the last halted replica did not leave once the fixed ones followed the log: %q", l.node.fsm.Stuck())
	}
	for _, r := range fixed {
		eventually(t, 10*time.Second, r.name+" serves the entry", func() bool {
			v, _ := r.sec.Get(t.Context(), "/fixed")
			return r.node.Serving() && string(v) == "v"
		})
	}
}

// A stopped replica records no state at later checkpoints; that must not
// hide a real divergence: a follower that diverged and then stopped is still
// named by the leader of a majority.
func TestStoppedDivergentFollowerIsStillJudged(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	bad := followers(c)[0]
	injectApplied(t, bad, "X")
	bad.node.fsm.stop(errors.New("test: deterministic stop after diverging"))
	if err := l.al.PutWorkload("after", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the leader names the stopped divergent follower", func() bool {
		return strings.Contains(l.node.Status().Divergence, bad.node.ID())
	})
	if bad.node.Serving() || l.node.fsm.Stuck() != "" {
		t.Fatalf("divergent follower serving %v; leader stuck %q", bad.node.Serving(), l.node.fsm.Stuck())
	}
}
