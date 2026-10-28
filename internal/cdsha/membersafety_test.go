package cdsha

import (
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

func hasWorkload(r *replica, name string) bool {
	al, _, err := r.al.LoadAll()
	if err != nil || al == nil {
		return false
	}
	_, ok := al.Workloads[name]
	return ok
}

// A voter cut out by dropSuspects that then applied the Recover decree
// naming it holds a fork: entries at the same index and term as the
// majority's, with other content. Once its fork has no leader it asks the
// majority to add it again. The majority leader must refuse that member ID
// (it would count acks for entries the fork does not hold); the process
// ends Run, so that only a restart with an empty log rejoins.
func TestExcludedVoterWithForkedLogNotReadmitted(t *testing.T) {
	c, s, majority := cutOutVoter(t)
	name := c.decree(Decree{Kind: Recover, BaseEpoch: s.node.Core().Epoch, BootstrapNode: s.name})
	eventually(t, 60*time.Second, "the cut-out voter recovered alone (fork)", func() bool { return recoveredAlone(s) })
	for i := 0; i < 30; i++ {
		if err := s.al.PutWorkload(fmt.Sprintf("fork-%d", i), mkWorkload(t, 0)); err != nil {
			t.Fatalf("fork write %d: %v", i, err)
		}
	}
	t.Logf("fork: term %d last index %d", s.node.r().CurrentTerm(), s.node.r().LastIndex())
	// The decree object is gone from the majority's view.
	c.decrees.del(name)
	c.setListDown(false, majority...)
	var ml *replica
	eventually(t, 30*time.Second, "majority unfenced", func() bool {
		ml = majorityLeader(c, s)
		return ml != nil && ml.node.Status().Fenced == nil && ml.al.PutWorkload("majority-marker", mkWorkload(t, 0)) == nil
	})
	t.Logf("majority: leader %s term %d last index %d", ml.name, ml.node.r().CurrentTerm(), ml.node.r().LastIndex())
	// The fork loses its leader: a second voter it cannot reach.
	_ = s.node.r().AddVoter("ghost/1-ghost", raft.ServerAddress(fmt.Sprintf("127.%d.0.250:%d#ghost/1-ghost", c.block, c.port)), 0, time.Second).Error()
	c.partition(s.name, false)
	readded, sLed := false, false
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		for _, r := range c.live() {
			if r == s {
				if s.node.leading() && len(s.node.servers()) > 2 {
					sLed = true
				}
				continue
			}
			if r.node.leading() {
				for _, m := range r.node.servers() {
					if m.ID == raft.ServerID(s.node.ID()) && m.Address != excludedAddress {
						readded = true
					}
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	var lost, forked []string
	for _, r := range c.live() {
		if r == s {
			continue
		}
		if !hasWorkload(r, "majority-marker") {
			lost = append(lost, r.name)
		}
		if hasWorkload(r, "fork-0") {
			forked = append(forked, r.name)
		}
	}
	if readded {
		t.Errorf("the forked member ID was re-admitted with its forked log")
	}
	if len(lost) > 0 || len(forked) > 0 || sLed {
		t.Errorf("fork merged: majority write lost on %v, fork state on %v, forked voter led the merged cluster: %v", lost, forked, sLed)
	}
	select {
	case <-s.done:
		if !errors.Is(s.err, ErrExcluded) {
			t.Errorf("the forked member ended Run with %v, want ErrExcluded", s.err)
		}
	default:
		t.Errorf("the forked member still runs with its forked log")
	}
}

// A stuck voter may exit only on its leader's authority: the leader and
// the voters it hears that follow it must be a majority without it. Here
// the leader and the third voter cannot reach each other; both answer the
// stuck voter, which must stay (its exit would leave no majority). Once the
// cut heals, the others follow one leader, and it leaves.
func TestStuckVoterStaysUnderAsymmetricPartition(t *testing.T) {
	c := newCluster(t, 3)
	c.fileStores = true
	c.genesis("n0", "n1", "n2")
	c.settled(30 * time.Second)
	l := c.leader()
	var others []*replica
	for _, r := range c.live() {
		if r != l {
			others = append(others, r)
		}
	}
	b, cc := others[0], others[1]
	c.cutPair(l, cc, true)
	lock, err := sql.Open("sqlite", b.alPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lock.Close() })
	lock.SetMaxOpenConns(1)
	if _, err := lock.Exec(`BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	if err := l.al.PutWorkload("w", mkWorkload(t, 1)); err != nil {
		t.Logf("write: %v", err)
	}
	eventually(t, 10*time.Second, "b stopped on its store", b.node.fsm.StuckLocal)
	select {
	case <-b.done:
		t.Fatalf("stuck voter %s exited (%v) while the other two cannot reach each other", b.name, b.err)
	case <-time.After(testTiming.DeadAfter + 4*testTiming.Lease):
	}
	if why := b.node.StuckOverdue(); why != "" {
		t.Fatalf("watchdog would end %s under the cut: %s", b.name, why)
	}
	c.cutPair(l, cc, false)
	select {
	case <-b.done:
		if !errors.Is(b.err, ErrStuck) {
			t.Fatalf("%s ended Run with %v, want ErrStuck", b.name, b.err)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("stuck voter %s did not leave once the others followed one leader", b.name)
	}
}

// recover stops Raft for its whole-log replay. A stuck survivor must not be
// ended by the watchdog then: its log is the only copy. Only a Raft gone for
// good (Run ended, TestStuckOverdueWithoutRun) lets it leave.
func TestStuckSurvivorNotOverdueWhileRecoverStopsRaft(t *testing.T) {
	c := newCluster(t, 1)
	c.genesis("n0")
	s := c.leader()
	if s == nil {
		t.Fatal("no leader")
	}
	s.node.fsm.stopLocal(errors.New("test: local store fault"))
	time.Sleep(testTiming.DeadAfter + 2*testTiming.Lease)
	if why := s.node.StuckOverdue(); why != "" {
		t.Fatalf("the only voter is overdue: %s", why)
	}
	s.node.membershipMu.Lock() // as recover holds it
	err := s.node.stopRaft(s.node.r())
	s.node.membershipMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if why := s.node.StuckOverdue(); why != "" {
		t.Fatalf("Raft stopped for a recover replay, the watchdog would end the survivor: %s", why)
	}
	select {
	case <-s.done:
		t.Fatalf("Run ended the survivor while Raft was stopped for recover: %v", s.err)
	case <-time.After(testTiming.DeadAfter + 2*testTiming.Lease):
	}
}

