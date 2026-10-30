package cdsha

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// A replica reports the cluster it serves: its place in it, the state it has
// applied and the mesh CA it issues under.
func TestAReplicaReportsTheClusterItServes(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)

	leading := c.awaitLeaderReport(3)
	switch {
	case leading.ClusterID != c.launch.ClusterID || !leading.Joined:
		t.Errorf("the leader reports %+v, want it serving this cluster", leading)
	case leading.State != "Leader" || leading.Leader != leading.ID:
		t.Errorf("the leader reports %+v, want itself leading", leading)
	case leading.CAFingerprint == "" || leading.GenesisCA != "":
		t.Errorf("the leader reports %+v, want the cluster's mesh CA", leading)
	case leading.Version != 1 || leading.AppliedIndex == 0 || leading.Stuck != "":
		t.Errorf("the leader reports %+v, want the Genesis decree applied", leading)
	}

	following := c.awaitFollowerReport(leading)
	if !slices.Contains(following.Voters, following.ID) {
		t.Errorf("a follower reports %+v, want its own vote", following)
	}
}

// awaitLeaderReport is the report of a leader answering reads under a lease,
// in a cluster whose configuration seats voters members.
func (c *liveCluster) awaitLeaderReport(voters int) Status {
	c.t.Helper()
	var reported Status
	eventually(c.t, 10*time.Second, fmt.Sprintf("a leader serving a cluster of %d voters", voters), func() bool {
		leader := c.leader()
		if leader == nil {
			return false
		}
		reported = leader.node.Status()
		return reported.Serving && len(reported.Voters) == voters
	})
	return reported
}

// awaitFollowerReport is the report of a replica following the leader, holding
// the mesh CA it serves and the vote the cluster's configuration gives it.
func (c *liveCluster) awaitFollowerReport(leading Status) Status {
	c.t.Helper()
	var reported Status
	eventually(c.t, 10*time.Second, "a follower of member "+leading.ID, func() bool {
		follower := c.follower()
		if follower == nil {
			return false
		}
		reported = follower.node.Status()
		return reported.State == "Follower" &&
			reported.Leader == leading.ID &&
			reported.CAFingerprint == leading.CAFingerprint &&
			slices.Contains(reported.Voters, reported.ID)
	})
	return reported
}

// Before it holds a cluster, a replica reports what a Genesis decree for it
// names: the member id this process minted and the mesh CA it would install.
// It issues under none of its own until that decree applies.
func TestAnUnjoinedReplicaReportsWhatItsGenesisWouldName(t *testing.T) {
	c := newLiveCluster(t)
	r := c.start()

	unjoined := r.node.Status()
	switch {
	case unjoined.Joined || unjoined.Serving:
		t.Errorf("an unjoined replica reports %+v, want it holding no cluster", unjoined)
	case unjoined.ID != string(r.node.member) || unjoined.GenesisCA != c.genesisCAOf(r):
		t.Errorf("an unjoined replica reports %+v, want the member id and mesh CA a Genesis names", unjoined)
	case unjoined.CAFingerprint != "" || unjoined.Version != 0:
		t.Errorf("an unjoined replica reports %+v, want no cluster state", unjoined)
	}
	if _, issuing := r.node.CA(); issuing {
		t.Error("an unjoined replica reports a mesh CA to issue under")
	}
}

// The decrees a replica reports are the ones it applied, as the operator
// signed them.
func TestAReplicaReportsTheDecreesItApplied(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)

	applied := c.replicas[0].node.Decrees()
	if len(applied) != 1 || applied[0].Decree.Decree.Kind != "Genesis" {
		t.Fatalf("the decree record holds %+v, want the Genesis the cluster started on", applied)
	}
	if core := c.replicas[0].node.ClusterState(); core.PinsDecree == nil || core.Version != applied[0].Version {
		t.Errorf("the cluster is at %+v, want the Genesis decree's pins and version", core)
	}
}
