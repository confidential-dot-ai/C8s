package cdsha

import (
	"fmt"
	"testing"
	"time"
)

// The operator changes the voter count with a signed decree: the leader
// promotes healthy non-voters into new seats, and demotes voters (never
// itself) when seats go away; writes keep working throughout.
func TestSetVotersGrowsAndShrinks(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	c.start("n3", "m1")
	c.start("n4", "m1")
	voters := func() int {
		l := c.leader()
		if l == nil {
			return -1
		}
		return len(l.node.Status().Voters)
	}
	eventually(t, 15*time.Second, "5 members, 3 voters", func() bool {
		l := c.leader()
		return l != nil && len(l.node.Status().Voters) == 3 && len(l.node.Status().NonVoters) == 2
	})
	even := c.decree(Decree{Kind: SetVoters, BaseEpoch: 1, Voters: 4})
	eventually(t, 10*time.Second, "even voter count refused", func() bool { st, ok := c.decrees.get(even); return ok && st.RejectedReason != "" })
	grow := c.decree(Decree{Kind: SetVoters, BaseEpoch: 1, Voters: 5})
	eventually(t, 10*time.Second, "SetVoters 5 applied", func() bool { st, ok := c.decrees.get(grow); return ok && st.AppliedEpoch != nil })
	eventually(t, 15*time.Second, "5 voters", func() bool { return voters() == 5 })
	if s := c.leader().node.Status().Seats; s != 5 {
		t.Fatalf("status seats %d", s)
	}
	if _, err := c.leader().sec.Put(t.Context(), "/five", []byte("v")); err != nil {
		t.Fatal(err)
	}
	shrink := c.decree(Decree{Kind: SetVoters, BaseEpoch: 2, Voters: 3})
	eventually(t, 10*time.Second, "SetVoters 3 applied", func() bool { st, ok := c.decrees.get(shrink); return ok && st.AppliedEpoch != nil })
	eventually(t, 15*time.Second, "3 voters again", func() bool { return voters() == 3 })
	for i, r := range c.live() {
		if _, err := r.sec.Put(t.Context(), fmt.Sprintf("/three/%d", i), []byte("v")); err != nil {
			t.Fatalf("write via %s: %v", r.name, err)
		}
		eventually(t, 5*time.Second, "serving "+r.name, func() bool { return r.node.Status().Serving })
	}
}
