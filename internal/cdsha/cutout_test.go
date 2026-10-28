package cdsha

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// cutOutVoter cuts one voter off while the majority cannot list decrees, and
// moves the lead so that the new leader's decree view is stale: it cuts the
// member out (dropSuspects). It returns once the majority leader no longer
// replicates to it.
func cutOutVoter(t *testing.T) (c *cluster, s *replica, majority []string) {
	t.Helper()
	c, l, s, majority := cutOff(t)
	c.setListDown(true, majority...)
	if err := l.node.r().LeadershipTransfer().Error(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 10*time.Second, "the majority leader cut the member out", func() bool {
		ml := majorityLeader(c, s)
		if ml == nil {
			return false
		}
		for _, m := range ml.node.servers() {
			if m.ID == raft.ServerID(s.node.ID()) {
				return m.Address == excludedAddress
			}
		}
		return true // removed
	})
	return c, s, majority
}

// A voter cut out while the decree view is stale keeps its vote until its
// replacement votes. The configuration never drops below the seats: a
// promotion into a free seat could commit on the leader and the new member
// alone, and a staying voter that missed it would then refuse the new
// voter's votes once the leader is lost (soak F9).
func TestCutOutVoterKeepsItsSeatUntilReplaced(t *testing.T) {
	c, s, majority := cutOutVoter(t)
	old := raft.ServerID(s.node.ID())
	var below atomic.Int32
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			ml := majorityLeader(c, s)
			if ml == nil {
				continue
			}
			if v := ml.node.voterCount(); v < c.seats {
				below.Store(int32(v))
			}
		}
	}()
	c.stopReplica(s)
	c.partition(s.name, false)
	again := c.start(s.name, "m1")
	c.setListDown(false, majority...)
	eventually(t, 30*time.Second, "the replacement votes and the old member retired", func() bool {
		ml := c.leader()
		if ml == nil {
			return false
		}
		voter, oldThere := false, false
		for _, m := range ml.node.servers() {
			voter = voter || m.ID == raft.ServerID(again.node.ID()) && m.Suffrage == raft.Voter
			oldThere = oldThere || m.ID == old
		}
		return voter && !oldThere
	})
	close(stop)
	wg.Wait()
	if v := below.Load(); v != 0 {
		t.Fatalf("the leader's configuration fell to %d voters for %d seats", v, c.seats)
	}
	c.settled(30 * time.Second)
}

// A cut-out voter that did not recover asks to join again once the
// partition heals. The leader refuses its member ID: an excluded process may
// hold a recovered cluster's log, which Raft cannot tell apart from its own.
// The process ends Run (ErrExcluded); its restart, a new member with a new ID
// and an empty log, joins, is promoted, and only then does the excluded ID
// retire. The old ID is never re-addressed, and never reused.
func TestCutOutVoterRestartsToRejoin(t *testing.T) {
	c, s, majority := cutOutVoter(t)
	old := raft.ServerID(s.node.ID())
	readdressed := func() bool {
		for _, r := range c.live() {
			if r == s || !r.node.leading() {
				continue
			}
			for _, m := range r.node.servers() {
				if m.ID == old && m.Address != excludedAddress {
					return true
				}
			}
		}
		return false
	}
	c.setListDown(false, majority...)
	c.partition(s.name, false)
	deadline := time.After(30 * time.Second)
	for ended := false; !ended; {
		select {
		case <-s.done:
			ended = true
		case <-deadline:
			t.Fatal("the excluded member did not end Run")
		case <-time.After(10 * time.Millisecond):
		}
		if readdressed() {
			t.Fatal("the excluded member ID was re-admitted at its address")
		}
	}
	if !errors.Is(s.err, ErrExcluded) {
		t.Fatalf("Run returned %v, want ErrExcluded", s.err)
	}
	c.stopReplica(s)
	again := c.start(s.name, "m1")
	if raft.ServerID(again.node.ID()) == old {
		t.Fatal("the restart reused the excluded member ID")
	}
	eventually(t, 30*time.Second, "the restart votes and the excluded ID retired", func() bool {
		if readdressed() {
			t.Fatal("the excluded member ID was re-admitted at its address")
		}
		ml := c.leader()
		if ml == nil {
			return false
		}
		voter, oldThere := false, false
		for _, m := range ml.node.servers() {
			voter = voter || m.ID == raft.ServerID(again.node.ID()) && m.Suffrage == raft.Voter
			oldThere = oldThere || m.ID == old
		}
		if !oldThere && !voter {
			t.Fatal("the excluded ID retired before its replacement votes")
		}
		return voter && !oldThere
	})
	c.settled(30 * time.Second)
}
