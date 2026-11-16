package cdsha

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestTheMajorityStopsAReplicaThatHoldsAnotherState(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leading := c.leader()
	rest := c.others(leading)
	diverged := rest[0]
	healthy := rest[1]
	diverged.mayLeave()

	c.appliedAlone(diverged, aloneWorkload)
	if err := write(leading, afterWorkload, testWorkload(t, 1)); err != nil {
		t.Fatalf("a write at the leader: %v", err)
	}

	c.stoppedAsDiverged(diverged)
	if leading.node.fsm.Stuck() != "" || !leading.node.leading() {
		t.Fatalf("one replica that holds another state stopped the leader: %q", leading.node.fsm.Stuck())
	}
	if named := leading.node.Status().Divergence; !strings.Contains(named, string(diverged.node.member)) {
		t.Errorf("the leader reports %q, want the replica it stopped named", named)
	}
	eventually(t, 10*time.Second, "the replica that holds the cluster's state serving", serves(healthy.node))
	if err := c.leftWithin(diverged, 10*time.Second); !errors.Is(err, ErrLeftItsCluster) {
		t.Fatalf("the stopped replica ended its loop with %v, want it leaving its cluster", err)
	}

	c.stop(diverged)
	replacement := c.start()
	eventually(t, 20*time.Second, "the replica that replaced it serving", serves(replacement.node))
	if holds(t, replacement, aloneWorkload) || !holds(t, replacement, afterWorkload) {
		t.Fatal("the replica that replaced it does not serve the state the majority holds")
	}
}

func TestAnOutvotedLeaderStopsItself(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	deposed := c.leader()
	deposed.mayLeave()

	c.appliedAlone(deposed, aloneWorkload)
	// Whatever the write answers, the state has moved and the next
	// checkpoint judges it.
	_ = write(deposed, afterWorkload, testWorkload(t, 1))

	c.stoppedAsDiverged(deposed)
	elected := newLeaderBesides(t, c, deposed)
	if holds(t, elected, aloneWorkload) {
		t.Fatal("the replica elected holds the entry the stopped leader applied alone")
	}
	eventually(t, 10*time.Second, "the cluster serving under the replica elected", serves(elected.node))
}

func TestADisagreementWithoutAMajorityOnlyRaisesAnAlarm(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leading := c.leader()
	rest := c.others(leading)
	diverged := rest[0]
	cut := rest[1]
	diverged.mayLeave()

	c.partition(cut, true)
	c.appliedAlone(diverged, aloneWorkload)
	if err := write(leading, afterWorkload, testWorkload(t, 1)); err != nil {
		t.Fatalf("a write at the leader: %v", err)
	}

	eventually(t, 10*time.Second, "the alarm of a disagreement no majority settles", func() bool {
		return strings.HasPrefix(leading.node.Status().Divergence, "no majority")
	})
	if stopped := diverged.node.fsm.Stuck(); stopped != "" {
		t.Fatalf("a replica was stopped without a majority: %q", stopped)
	}
	if stopped := leading.node.fsm.Stuck(); stopped != "" {
		t.Fatalf("the leader was stopped without a majority: %q", stopped)
	}

	c.partition(cut, false)

	c.stoppedAsDiverged(diverged)
	if stopped := leading.node.fsm.Stuck(); stopped != "" {
		t.Fatalf("the leader stopped once the majority decided: %q", stopped)
	}
}

// Tell the state of one replica from the cluster's.
const (
	aloneWorkload = "written-by-one-replica-alone"
	afterWorkload = "written-by-the-cluster"
)

// Waits until a replica stops on the majority's verdict and serves nothing.
func (c *liveCluster) stoppedAsDiverged(r *liveReplica) {
	c.t.Helper()
	eventually(c.t, 15*time.Second, "the replica that holds another state stopping", func() bool {
		return errors.Is(stoppedBy(r), ErrDiverged)
	})
	if r.node.Serving().OK {
		c.t.Fatal("a replica that holds another state than the majority serves reads")
	}
}

// Nothing where the replica stopped on anything else or follows the log.
func stoppedBy(r *liveReplica) error {
	if strings.Contains(r.node.fsm.Stuck(), ErrDiverged.Error()) {
		return ErrDiverged
	}
	return nil
}

// Applies a write no other replica of the cluster has, as a leader that
// appended an uncommitted entry leaves behind.
func (c *liveCluster) appliedAlone(r *liveReplica, workload string) {
	c.t.Helper()
	entry, err := json.Marshal(Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:   allowlist.OpSeed,
			AtMS: time.Now().UnixMilli(),
			Workloads: map[string]pkgallowlist.Workload{
				workload: testWorkload(c.t, 77),
			},
		},
	})
	if err != nil {
		c.t.Fatal(err)
	}
	res := r.node.fsm.Apply(r.node.fsm.AppliedIndex()+1, entry)
	if res.Stop != nil || res.Allowlist == nil || res.Allowlist.Kind != "" {
		c.t.Fatalf("the entry one replica applied alone: %+v", res)
	}
}
