package cdsha

import (
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"
)

// F9 family: a voter superseded by a newer member of its node leaves
// through the gated retire, whichever voter leads; the seat trim never
// takes a live voter's seat instead. Leadership moves while the old leader
// still waits to retire the superseded voter, to its replacement or to a
// voter that stays. The new leader has seen no heartbeat failure yet (its
// observer is held off: failure detection need not have fired), so only
// the configuration tells which voter is surplus.
func TestNewLeaderRetiresTheSupersededVoterNotALiveOne(t *testing.T) {
	t.Run("to the replacement", func(t *testing.T) { supersededVoterAfterLeaderChange(t, true) })
	t.Run("to a staying voter", func(t *testing.T) { supersededVoterAfterLeaderChange(t, false) })
}

func supersededVoterAfterLeaderChange(t *testing.T, toReplacement bool) {
	c := newCluster(t, 3)
	var mute atomic.Value // the nodes whose status replies fail
	mute.Store([]string(nil))
	gate := func(name string) func(controlHandler) controlHandler {
		return func(next controlHandler) controlHandler {
			return func(peer Claims, req controlRequest) controlResponse {
				if req.Op == ctlStatus && slices.Contains(mute.Load().([]string), name) {
					return controlResponse{Err: "test: status unavailable"}
				}
				return next(peer, req)
			}
		}
	}
	for _, name := range []string{"n0", "n1", "n2"} {
		c.startWithControl(name, "m1", gate(name))
	}
	gd := c.decree(Decree{Kind: Genesis, BootstrapNode: "n0"})
	eventually(t, 10*time.Second, "genesis applied", func() bool { st, ok := c.decrees.get(gd); return ok && st.AppliedEpoch != nil })
	c.settled(15 * time.Second)
	l := c.nodes["n0"]
	if !l.node.leading() {
		t.Fatal("bootstrap leader changed")
	}
	// The bootstrap leader is first in the configuration. v is the voter
	// after g, so a live voter precedes it in configuration order.
	var order []*replica
	for _, s := range l.node.servers() {
		for _, r := range c.others(l) {
			if r.node.id == s.ID {
				order = append(order, r)
			}
		}
	}
	if len(order) != 2 {
		t.Fatalf("configuration %+v", l.node.servers())
	}
	g, v := order[0], order[1]
	oldID := string(v.node.id)

	// l and g do not answer status: no leader can meet the retire gate of
	// v's old member, so the cluster must keep the extra voter and wait.
	mute.Store([]string{l.name, g.name})
	c.stopReplica(v)
	nv := c.startWithControl(v.name, "m1", gate(v.name))
	newID := string(nv.node.id)
	eventually(t, 15*time.Second, "the new member votes and the old one still does", func() bool {
		vs := voterIDs(l)
		return slices.Contains(vs, newID) && slices.Contains(vs, oldID)
	})
	target := g
	if toReplacement {
		target = nv
	}
	obs := target.node.observer
	target.node.r().DeregisterObserver(obs.observer)
	if err := l.node.r().LeadershipTransferToServer(target.node.id, target.node.raftAddress()).Error(); err != nil {
		t.Fatalf("leadership transfer: %v", err)
	}
	eventually(t, 5*time.Second, "the target leads", target.node.leading)
	live := []string{string(l.node.id), string(g.node.id), newID}
	var lost atomic.Value // the first sample without a live voter
	lost.Store("")
	stop, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		for {
			vs := voterIDs(target)
			for _, id := range live {
				if !slices.Contains(vs, id) && lost.Load().(string) == "" {
					lost.Store(fmt.Sprintf("%s lost its vote: voters %v", id, vs))
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	// The gate is not met: well past Stabilize, the extra voter stays.
	time.Sleep(testTiming.Stabilize + 20*testTiming.Tick)
	if vs := voterIDs(target); len(vs) != 4 || !slices.Contains(vs, oldID) {
		t.Errorf("while the retire gate is unmet: voters %v, want the four with %s", vs, oldID)
	}
	mute.Store([]string(nil))
	eventually(t, 10*time.Second, "the extra voter left", func() bool { return len(voterIDs(target)) == 3 })
	close(stop)
	<-sampled
	if s := lost.Load().(string); s != "" {
		t.Fatal(s)
	}
	got := voterIDs(target)
	want := slices.Clone(live)
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("voters %v, want %v: a live voter lost its seat instead of the superseded %s", got, want, oldID)
	}
	target.node.r().RegisterObserver(obs.observer)
	// The rollout's next restart.
	c.stopReplica(l)
	eventually(t, 15*time.Second, "the survivors elect a leader and serve", c.servesWithALeader)
}
