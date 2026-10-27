package cdsha

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// A Recover decree naming a replica that is only cut off from a live
// majority must never leave two clusters serving at once (fence.go).

// splitWatch samples, every 20 ms, whether the named replica leads a
// one-voter cluster and serves while a replica of the old majority serves.
type splitWatch struct {
	mu       sync.Mutex
	both     []string
	recover  time.Time // first sample of s leading alone
	fencedAt time.Time // first sample of the majority leader fenced
	stop     chan struct{}
	done     chan struct{}
}

func watchSplit(c *cluster, s *replica) *splitWatch {
	w := &splitWatch{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(w.done)
		for {
			select {
			case <-w.stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			alone := recoveredAlone(s)
			var serving []string
			for _, r := range c.live() {
				if r == s {
					continue
				}
				if r.node.Serving() {
					serving = append(serving, r.name)
				}
				if r.node.leading() && r.node.Status().Fenced != nil {
					w.mu.Lock()
					if w.fencedAt.IsZero() {
						w.fencedAt = time.Now()
					}
					w.mu.Unlock()
				}
			}
			w.mu.Lock()
			if alone && w.recover.IsZero() {
				w.recover = time.Now()
			}
			if alone && s.node.Serving() && len(serving) > 0 {
				w.both = append(w.both, fmt.Sprintf("%s: %s serves alone while %v serve", time.Now().Format("15:04:05.000"), s.name, serving))
			}
			w.mu.Unlock()
		}
	}()
	return w
}

func (w *splitWatch) finish(t *testing.T) {
	t.Helper()
	close(w.stop)
	<-w.done
	if len(w.both) > 0 {
		t.Fatalf("two clusters served at once (%d samples), first: %s", len(w.both), w.both[0])
	}
}

// check fails the test if two clusters served at once so far.
func (w *splitWatch) check(t *testing.T) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.both) > 0 {
		t.Fatalf("two clusters served at once (%d samples), first: %s", len(w.both), w.both[0])
	}
}

func (w *splitWatch) recovered() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.recover.IsZero()
}

// recoveredAlone: s leads a configuration of only itself.
func recoveredAlone(s *replica) bool {
	st := s.node.Status()
	return st.State == raft.Leader.String() && len(st.Voters) == 1 && st.Voters[0] == s.node.ID() && len(st.NonVoters) == 0
}

// cutOff partitions one follower of a three-replica cluster for longer than
// DeadAfter, as the operator's Recover target.
func cutOff(t *testing.T) (c *cluster, l, s *replica, majority []string) {
	c = newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l = c.leader()
	for _, r := range c.live() {
		if r != l && s == nil {
			s = r
		} else {
			majority = append(majority, r.name)
		}
	}
	c.partition(s.name, true)
	time.Sleep(testTiming.DeadAfter + 500*time.Millisecond)
	return c, l, s, majority
}

// reachableMember reports that l's configuration holds s at an address
// Raft reaches (not cut out, see dropSuspects).
func reachableMember(l, s *replica) bool {
	return slices.ContainsFunc(l.node.servers(), func(m raft.Server) bool {
		return m.ID == raft.ServerID(s.node.ID()) && m.Address != excludedAddress
	})
}

func majorityLeader(c *cluster, s *replica) *replica {
	for _, r := range c.live() {
		if r != s && r.node.leading() {
			return r
		}
	}
	return nil
}

// The majority cannot reach the API server and never sees the decree. It
// fences itself before the named replica acts, refuses to merge with it once it
// sees the decree applied, and stays fenced after the partition heals.
func TestRecoverSplitBrainLeaderAPIDownRefused(t *testing.T) {
	c, l, s, majority := cutOff(t)
	c.setListDown(true, majority...)
	w := watchSplit(c, s)
	name := c.decree(Decree{Kind: Recover, BaseEpoch: l.node.Core().Epoch, BootstrapNode: s.name})
	written := time.Now()
	eventually(t, testTiming.DeadAfter+testTiming.recoverHold()+5*time.Second, "the named replica recovers (the majority is fenced)", w.recovered)
	time.Sleep(testTiming.Lease) // read certificates issued before a fence expire
	w.check(t)
	if w.fencedAt.IsZero() || !w.fencedAt.Before(w.recover) {
		t.Fatalf("majority fenced at %v, replica recovered at %v", w.fencedAt, w.recover)
	}
	if held := w.recover.Sub(written); held < testTiming.recoverHold() {
		t.Fatalf("recovered %v after the decree, hold is %v", held, testTiming.recoverHold())
	}
	ml := majorityLeader(c, s)
	f := ml.node.Status().Fenced
	if f == nil || !slices.Contains(f.CutOffVoters, s.node.ID()) || f.SinceMS == 0 {
		t.Fatalf("majority leader fence: %+v", f)
	}
	if err := ml.al.PutWorkload("majority", mkWorkload(t, 2)); err == nil {
		t.Fatal("a fenced majority took a write")
	}
	if err := s.al.PutWorkload("minority", mkWorkload(t, 1)); err != nil {
		t.Fatalf("the recovered replica refused a write: %v", err)
	}
	// The API comes back: the majority sees the decree applied by s.
	c.setListDown(false, majority...)
	eventually(t, 5*time.Second, "the majority sees the fork", func() bool {
		ml := majorityLeader(c, s)
		if ml == nil {
			return false
		}
		f := ml.node.Status().Fenced
		return f != nil && f.Decree == name && f.Member == s.node.ID() && !reachableMember(ml, s)
	})
	// The network heals: no merge, the fork keeps its write, and the
	// majority stays fenced.
	c.partition(s.name, false)
	time.Sleep(3 * time.Second)
	if !recoveredAlone(s) || !s.node.Serving() {
		t.Fatalf("the recovered replica was merged back: %+v", s.node.Status())
	}
	if al, _, err := s.al.LoadAll(); err != nil || len(al.Workloads["minority"].Containers) != 1 {
		t.Fatalf("the recovered replica lost its write: %v", err)
	}
	if ml := majorityLeader(c, s); ml == nil || ml.node.Status().Fenced == nil {
		t.Fatal("the old majority serves again beside the recovered cluster")
	}
	w.finish(t)
}

// The majority's API is down for less than the decree lease: it rejects
// the decree in time when it comes back; it is never fenced and the named
// replica never recovers.
func TestRecoverShortAPIOutageRejectedInTime(t *testing.T) {
	c, l, s, majority := cutOff(t)
	c.setListDown(true, majority...)
	w := watchSplit(c, s)
	name := c.decree(Decree{Kind: Recover, BaseEpoch: l.node.Core().Epoch, BootstrapNode: s.name})
	time.Sleep(testTiming.decreeLease() / 3)
	c.setListDown(false, majority...)
	eventually(t, 5*time.Second, "decree rejected", func() bool { _, ok := c.decrees.get(name); return ok })
	if st, _ := c.decrees.get(name); st.RejectedReason != ErrRecoverWithQuorum.Error() {
		t.Fatalf("status %+v", st)
	}
	time.Sleep(testTiming.DeadAfter + testTiming.recoverHold())
	if w.recovered() || !w.fencedAt.IsZero() {
		t.Fatalf("recovered=%v fenced at %v", w.recovered(), w.fencedAt)
	}
	if !majorityLeader(c, s).node.Serving() {
		t.Fatal("the majority stopped serving")
	}
	w.finish(t)
}

// The majority's API is down for longer than the decree lease, and back
// before the hold ends: the majority fences itself, rejects the decree late
// and drops the named replica; the replica does not recover, rejoins after
// the partition heals, and the majority serves again.
func TestRecoverLongAPIOutageRejectedLateThenRejoin(t *testing.T) {
	c, l, s, majority := cutOff(t)
	c.setListDown(true, majority...)
	w := watchSplit(c, s)
	name := c.decree(Decree{Kind: Recover, BaseEpoch: l.node.Core().Epoch, BootstrapNode: s.name})
	eventually(t, testTiming.decreeLease()+2*time.Second, "majority fenced", func() bool {
		ml := majorityLeader(c, s)
		return ml != nil && ml.node.Status().Fenced != nil
	})
	time.Sleep(500 * time.Millisecond)
	c.setListDown(false, majority...)
	eventually(t, 5*time.Second, "decree rejected late", func() bool {
		st, ok := c.decrees.get(name)
		return ok && st.RejectedReason == ErrRecoverLate.Error()
	})
	if f := majorityLeader(c, s).node.Status().Fenced; f == nil || f.Decree != name {
		t.Fatalf("fence after a late rejection: %+v", f)
	}
	time.Sleep(testTiming.recoverHold())
	if w.recovered() {
		t.Fatal("the named replica recovered after a rejection")
	}
	c.partition(s.name, false)
	eventually(t, 20*time.Second, "the named replica rejoins and the majority serves again", func() bool {
		ml := majorityLeader(c, s)
		return ml != nil && ml.node.Status().Fenced == nil && ml.node.Serving() && s.node.Serving()
	})
	if w.recovered() {
		t.Fatal("the named replica recovered")
	}
	w.finish(t)
}

// The decree lands after the named replica's DeadAfter and both sides can list it.
func TestRecoverRaceRefused(t *testing.T) {
	for i := range 3 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c, l, s, _ := cutOff(t)
			w := watchSplit(c, s)
			name := c.decree(Decree{Kind: Recover, BaseEpoch: l.node.Core().Epoch, BootstrapNode: s.name})
			time.Sleep(testTiming.recoverHold() + time.Second)
			if st, _ := c.decrees.get(name); w.recovered() || st.RejectedReason != ErrRecoverWithQuorum.Error() {
				t.Fatalf("recovered=%v status %+v", w.recovered(), st)
			}
			w.finish(t)
		})
	}
}

// A plain API outage with every member healthy fences nothing.
func TestAPIOutageWithHealthyMembersKeepsServing(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	c.setListDown(true, "n0", "n1", "n2")
	time.Sleep(2 * testTiming.decreeLease())
	l := c.leader()
	if f := l.node.Status().Fenced; f != nil {
		t.Fatalf("fenced: %+v", f)
	}
	if err := l.al.PutWorkload("w", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
	for _, r := range c.live() {
		if !r.node.Serving() {
			t.Fatalf("%s stopped serving", r.name)
		}
	}
}

// An election during an API outage with every member healthy: the new
// leader has no decree view in its term, but every member reports it as
// their leader, so it serves.
func TestElectionDuringAPIOutageKeepsServing(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	c.settled(15 * time.Second)
	c.setListDown(true, "n0", "n1", "n2")
	old := c.leader()
	if err := old.node.r().LeadershipTransfer().Error(); err != nil {
		t.Fatal(err)
	}
	var nl *replica
	eventually(t, 5*time.Second, "a new leader", func() bool {
		nl = c.leader()
		return nl != nil && nl != old
	})
	eventually(t, 5*time.Second, "the new leader serves without a decree view", func() bool {
		v := nl.node.decreeView.Load()
		return nl.node.leading() && (v == nil || v.term != nl.node.r().CurrentTerm()) && nl.node.Status().Fenced == nil && nl.node.Serving()
	})
	if err := nl.al.PutWorkload("w", mkWorkload(t, 1)); err != nil {
		t.Fatalf("write after the election: %v", err)
	}
	for _, r := range c.live() {
		eventually(t, 5*time.Second, r.name+" serves", r.node.Serving)
	}
}

// The same election with a member cut off: the new leader is fenced at
// once, as the cut-off member may be holding a Recover.
func TestElectionDuringAPIOutageWithCutOffMemberFences(t *testing.T) {
	c, l, s, majority := cutOff(t)
	c.setListDown(true, majority...)
	if err := l.node.r().LeadershipTransfer().Error(); err != nil {
		t.Fatal(err)
	}
	var nl *replica
	eventually(t, 5*time.Second, "a new majority leader", func() bool {
		nl = majorityLeader(c, s)
		return nl != nil && nl != l
	})
	eventually(t, 5*time.Second, "the new leader is fenced", func() bool { return nl.node.Status().Fenced != nil })
	eventually(t, testTiming.Lease+time.Second, "the majority stops serving", func() bool {
		for _, r := range c.live() {
			if r != s && r.node.Serving() {
				return false
			}
		}
		return true
	})
}

// The operator deletes the decree a fenced majority doubts: it serves again.
func TestDeletingTheDoubtedDecreeUnfences(t *testing.T) {
	c, l, s, majority := cutOff(t)
	c.setListDown(true, majority...)
	name := c.decree(Decree{Kind: Recover, BaseEpoch: l.node.Core().Epoch, BootstrapNode: s.name})
	time.Sleep(testTiming.decreeLease() + time.Second)
	c.setListDown(false, majority...)
	eventually(t, 5*time.Second, "late rejection", func() bool { st, _ := c.decrees.get(name); return st.RejectedReason == ErrRecoverLate.Error() })
	c.decrees.del(name)
	eventually(t, 5*time.Second, "majority serves again", func() bool {
		ml := majorityLeader(c, s)
		return ml != nil && ml.node.Status().Fenced == nil && ml.node.Serving()
	})
	if err := majorityLeader(c, s).al.PutWorkload("w", mkWorkload(t, 1)); err != nil {
		t.Fatal(err)
	}
}

// The production figures: F = 40 s, H = 57 s.
func TestRecoverFenceProductionTiming(t *testing.T) {
	if f, h := DefaultTiming.decreeLease(), DefaultTiming.recoverHold(); f != 40*time.Second || h != 57*time.Second {
		t.Fatalf("decree lease %v, recover hold %v", f, h)
	}
	if !errors.Is(fmt.Errorf("%w: x", ErrFenced), ErrFenced) {
		t.Fatal("ErrFenced does not wrap")
	}
}
