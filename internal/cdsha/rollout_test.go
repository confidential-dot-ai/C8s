package cdsha

import (
	"testing"
	"time"
)

// A rollout: a replica on a newly accepted image joins a group running the
// old one, takes the state and serves.
func TestReplicaOnANewImageJoins(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	if _, err := c.nodes["n0"].sec.Put(t.Context(), "/before", []byte("v")); err != nil {
		t.Fatal(err)
	}
	d := c.decree(Decree{Kind: UpdateMeasurements, BaseEpoch: 1, Measurements: normalizePins([]string{"m1", "m2"})})
	eventually(t, 10*time.Second, "m1+m2 applied", func() bool { st, ok := c.decrees.get(d); return ok && st.AppliedEpoch != nil })
	b := c.start("n3", "m2")
	eventually(t, 20*time.Second, "new-image replica serves", func() bool { return b.node.Status().Serving })
	eventually(t, 5*time.Second, "state on the new replica", func() bool { v, _ := b.sec.Get(t.Context(), "/before"); return string(v) == "v" })
}
