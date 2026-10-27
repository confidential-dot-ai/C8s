package cdsha

import (
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
// partition heals: it votes again at its own address, with its log.
func TestCutOutVoterRejoinsAtItsAddress(t *testing.T) {
	c, s, majority := cutOutVoter(t)
	c.setListDown(false, majority...)
	c.partition(s.name, false)
	eventually(t, 30*time.Second, "the member votes at its address again", func() bool {
		ml := majorityLeader(c, s)
		if ml == nil {
			return false
		}
		for _, m := range ml.node.servers() {
			if m.ID == raft.ServerID(s.node.ID()) {
				return m.Suffrage == raft.Voter && m.Address == s.node.raftAddress()
			}
		}
		return false
	})
	c.settled(30 * time.Second)
}
