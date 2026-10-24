package cdsha

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// others are the live replicas other than skip.
func (c *cluster) others(skip ...*replica) []*replica {
	var out []*replica
	for _, r := range c.live() {
		if !slices.Contains(skip, r) {
			out = append(out, r)
		}
	}
	return out
}

// voterIDs is the leader's latest configuration's voters.
func voterIDs(l *replica) []string { return l.node.Status().Voters }

// servesWithALeader: some live replica leads and every live one serves.
func (c *cluster) servesWithALeader() bool {
	if c.leader() == nil {
		return false
	}
	for _, r := range c.live() {
		if !r.node.Serving() {
			return false
		}
	}
	return true
}

// restartLagged is the F9 sequence (rolling restart under loss): the
// restarted voters' new members join, the lagging voters lose most of their
// traffic, the rollout restarts the leader the moment the new members are
// Ready, and the loss ends. The survivors must elect a leader.
func restartLagged(t *testing.T, c *cluster, lag []*replica, restart []*replica) {
	t.Helper()
	l := c.leader()
	var news []*replica
	for _, v := range restart {
		c.stopReplica(v)
	}
	for _, v := range restart {
		news = append(news, c.start(v.name, "m1"))
	}
	eventually(t, 20*time.Second, "the restarted members joined", func() bool {
		for _, v := range news {
			if !v.node.member() {
				return false
			}
		}
		return true
	})
	ready := func() bool {
		for _, v := range news {
			if !v.node.Ready() {
				return false
			}
		}
		return true
	}
	// The lagging voters lose most of their traffic (F9 ran under packet
	// loss): cut off, with short gaps that keep the leader's lease.
	lossy := make(chan struct{})
	lossDone := make(chan struct{})
	go func() {
		defer close(lossDone)
		for {
			for _, g := range lag {
				c.partition(g.name, true)
			}
			select {
			case <-lossy:
				return
			case <-time.After(40 * time.Millisecond):
			}
			for _, g := range lag {
				c.partition(g.name, false)
			}
			select {
			case <-lossy:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}()
	heal := func() {
		close(lossy)
		<-lossDone
		for _, g := range lag {
			c.partition(g.name, false)
		}
	}
	// The rollout restarts the leader as soon as the new members are Ready
	// (F9: 7 ms later), whether or not the lagging voters caught up. The
	// loss lasts a few seconds; a member that is not Ready by then is
	// waited for after it.
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end) && !ready(); {
		time.Sleep(5 * time.Millisecond)
	}
	if ready() {
		c.stopReplica(l)
		heal()
	} else {
		heal()
		eventually(t, 20*time.Second, "the restarted members are Ready", ready)
		c.stopReplica(l)
	}
	eventually(t, 15*time.Second, "the survivors elect a leader and serve", c.servesWithALeader)
}

// F9: the add of a restarted voter's new member must not commit without a
// live voter. Then the leader is the next to restart, and the voter that
// missed the add would refuse the new member's votes for good.
func TestRestartedVoterReplacementSurvivesTheNextRestart(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	o := c.others(l)
	restartLagged(t, c, o[:1], o[1:])
}

// The same with five seats: two voters restart together while another is
// cut off.
func TestTwoRestartedVotersOfFiveSurviveTheNextRestart(t *testing.T) {
	c := newCluster(t, 5)
	c.genesis("n0", "n1", "n2", "n3", "n4")
	l := c.leader()
	o := c.others(l)
	restartLagged(t, c, o[:1], o[1:3])
}

// A restarted voter's old member keeps its vote until the new member holds
// one: the voters never drop below the seats, and exceed them by at most
// the one retiring.
func TestVoterReplacedAddThenRemove(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	v := c.others(l)[0]
	oldID := string(v.node.id)
	var mu sync.Mutex
	var bad []string
	stop := make(chan struct{})
	watched := make(chan struct{})
	var nv *replica
	go func() {
		defer close(watched)
		for {
			select {
			case <-stop:
				return
			case <-time.After(5 * time.Millisecond):
			}
			vs := voterIDs(l)
			mu.Lock()
			if len(vs) < 3 || len(vs) > 4 {
				bad = append(bad, fmt.Sprintf("voters %v", vs))
			}
			if nv != nil && !slices.Contains(vs, string(nv.node.id)) && !slices.Contains(vs, oldID) {
				bad = append(bad, fmt.Sprintf("neither the old nor the new member votes: %v", vs))
			}
			if nv != nil && len(vs) > 3 && nv.node.Ready() && nv.node.voterCount() > 3 {
				bad = append(bad, fmt.Sprintf("new member Ready with a voter still to retire: %v", vs))
			}
			mu.Unlock()
		}
	}()
	c.stopReplica(v)
	n := c.start(v.name, "m1")
	mu.Lock()
	nv = n
	mu.Unlock()
	eventually(t, 20*time.Second, "the new member votes and the old one retired", func() bool {
		vs := voterIDs(l)
		return len(vs) == 3 && slices.Contains(vs, string(n.node.id)) && !slices.Contains(vs, oldID)
	})
	eventually(t, 10*time.Second, "seats filled and the new member Ready", func() bool {
		return l.node.Status().SeatsFilled && n.node.Ready() && len(l.node.Status().RetiringVoters) == 0
	})
	close(stop)
	<-watched
	mu.Lock()
	defer mu.Unlock()
	if len(bad) > 0 {
		t.Fatalf("%d bad samples, first: %s", len(bad), bad[0])
	}
}

// A rolling restart of every voter, each one after the previous one is
// Ready, with writes: the cluster always comes back with a leader and keeps
// every acknowledged write.
func TestRollingRestartOfEveryVoter(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	done := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	acked := map[string]int{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			rs := c.live()
			if len(rs) == 0 {
				continue
			}
			name := fmt.Sprintf("it-roll%d", i%5)
			if rs[i%len(rs)].al.PutWorkload(name, mkWorkload(t, i)) == nil {
				mu.Lock()
				acked[name] = i
				mu.Unlock()
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	for _, name := range []string{"n0", "n1", "n2"} {
		var r *replica
		for _, x := range c.live() {
			if x.name == name {
				r = x
			}
		}
		c.stopReplica(r)
		n := c.start(name, "m1")
		eventually(t, 30*time.Second, name+" Ready again", n.node.Ready)
	}
	eventually(t, 15*time.Second, "a leader and every replica serving", c.servesWithALeader)
	close(done)
	wg.Wait()
	l := c.leader()
	doc, _, err := l.al.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for name, want := range acked {
		wl, ok := doc.Workloads[name]
		if !ok || len(wl.Containers) == 0 {
			t.Errorf("acked %s missing", name)
			continue
		}
		// A later write that failed may still have committed; an older
		// value than the last acknowledged one never may show.
		got, err := strconv.ParseInt(strings.TrimPrefix(wl.Containers[0].Digest.String(), "sha256:"), 16, 64)
		if err != nil || int(got)-1 < want {
			t.Errorf("%s = %d, acked %d", name, got-1, want)
		}
	}
}

// One seat: a non-voter restarts and is Ready again once the leader
// reports the seat filled; the single voter is Ready.
func TestOneSeatReplacementAndReadiness(t *testing.T) {
	c := newCluster(t, 1)
	c.genesis("n0", "n1")
	l := c.leader()
	nv := c.others(l)[0]
	eventually(t, 10*time.Second, "both Ready", func() bool { return l.node.Ready() && nv.node.Ready() })
	c.stopReplica(nv)
	n := c.start(nv.name, "m1")
	eventually(t, 15*time.Second, "the restarted non-voter Ready", n.node.Ready)
	if vs := voterIDs(l); len(vs) != 1 || vs[0] != string(l.node.id) {
		t.Fatalf("voters %v", vs)
	}
}

// A voter cut off past DeadAfter, with no non-voter to replace it, waits to
// retire; once its heartbeats come back it keeps its seat (same member) and
// no longer counts as retiring (A3: a minority-side voter after the heal).
func TestRetiringVoterThatComesBackKeepsItsSeat(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	v := c.others(l)[0]
	id := string(v.node.id)
	c.partition(v.name, true)
	eventually(t, testTiming.DeadAfter+5*time.Second, "the cut-off voter waits to retire", func() bool {
		return slices.Contains(l.node.Status().RetiringVoters, id)
	})
	c.partition(v.name, false)
	eventually(t, 10*time.Second, "no voter retiring after the heal", func() bool {
		return len(l.node.Status().RetiringVoters) == 0
	})
	// And it stays so: the voter keeps its seat under the same member ID.
	for end := time.Now().Add(testTiming.DeadAfter); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		st := l.node.Status()
		if !slices.Contains(st.Voters, id) || len(st.RetiringVoters) > 0 {
			t.Fatalf("after the heal: voters %v, retiring %v", st.Voters, st.RetiringVoters)
		}
	}
	eventually(t, 10*time.Second, "the voter serves and the seats are filled", func() bool {
		return v.node.Serving() && l.node.Status().SeatsFilled
	})
}
