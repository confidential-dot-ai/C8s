package cdsha

import (
	"database/sql"
	"slices"
	"testing"
	"time"
)

// A fault every replica's store raises at the same entry (the same state
// over the same size limit, a host-wide memory or disk shortage) is labelled
// local, but it is not one replica's own: were each to exit and rejoin, the
// cluster would lose its in-memory log. A stuck replica leaves only while
// the others that follow the log keep a majority; here none do, so every
// replica keeps running with its log.
func TestLocalStopOnEveryReplicaKeepsTheLog(t *testing.T) {
	c := newCluster(t, 3)
	c.fileStores = true
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
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
	last := l.node.r().LastIndex()
	eventually(t, 10*time.Second, "every replica stopped on its store", func() bool {
		for _, r := range c.live() {
			if !r.node.fsm.StuckLocal() {
				return false
			}
		}
		return true
	})
	time.Sleep(testTiming.DeadAfter + 2*testTiming.Lease + 10*testTiming.Tick)
	running := 0
	for _, r := range c.live() {
		select {
		case <-r.done:
			t.Logf("%s ended Run: %v", r.name, r.err)
		default:
			running++
			if got := r.node.r().LastIndex(); got < last {
				t.Errorf("%s holds the log up to %d, want %d", r.name, got, last)
			}
		}
		if why := r.node.StuckOverdue(); why != "" {
			t.Errorf("%s: watchdog would end it: %s", r.name, why)
		}
	}
	if running < 2 {
		t.Fatalf("%d of 3 replicas still run with the log; want a majority", running)
	}

	// The documented way out: restart the stuck replicas one at a time,
	// each once its predecessor's replacement is a voter. The stuck ones
	// keep voting, so the majority holds; the last stuck one, once the
	// others follow the log, hands off and leaves by itself.
	for _, lock := range locks {
		if _, err := lock.Exec(`ROLLBACK`); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range c.live() {
		if r == l {
			continue
		}
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
	}
	select {
	case <-l.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the last stuck replica did not leave once the others followed the log")
	}
	c.stopReplica(l)
	c.start(l.name, "m1")
	c.settled(30 * time.Second)
}
