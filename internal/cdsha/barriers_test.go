package cdsha

import (
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// What Raft makes of a leader's barriers, and the leader that ends its Run
// because Raft refuses every one of them.

// A run is as old as the first refusal, however many follow.
func TestEveryRefusedBarrierOfATermExtendsOneRun(t *testing.T) {
	const term = 7
	var refused barrierRefusals
	began := time.Now()

	refused.record(term, raft.ErrLeadershipTransferInProgress)
	first := refused.refusedFor(term, began.Add(time.Minute))
	refused.record(term, raft.ErrLeadershipTransferInProgress)

	if again := refused.refusedFor(term, began.Add(time.Minute)); again != first {
		t.Errorf("a second refusal moved the run from %s to %s old", first, again)
	}
	if later := refused.refusedFor(term, began.Add(2*time.Minute)); later <= first {
		t.Errorf("a run %s old a minute ago is %s old now", first, later)
	}
}

// A leader whose barriers pass again is no leader to exit.
func TestABarrierRaftTookEndsTheRun(t *testing.T) {
	const term = 7
	var refused barrierRefusals
	refused.record(term, raft.ErrLeadershipTransferInProgress)

	refused.record(term, nil)

	if refusedFor := refused.refusedFor(term, time.Now()); refusedFor != 0 {
		t.Errorf("a barrier passed and the run is %s old", refusedFor)
	}
}

// A barrier that did not finish is one Raft took: the state machine is slow
// over it.
func TestABarrierTheStateMachineIsSlowOverIsNoRefusal(t *testing.T) {
	const term = 7
	var refused barrierRefusals

	refused.record(term, errors.New("cds-ha: this leader's barrier did not pass within a read"))

	if refusedFor := refused.refusedFor(term, time.Now()); refusedFor != 0 {
		t.Errorf("a barrier that did not finish counts as refused for %s", refusedFor)
	}
}

func TestOnlyTheRefusalsOfThisTermCount(t *testing.T) {
	const term = 7
	var refused barrierRefusals
	refused.record(term, raft.ErrLeadershipTransferInProgress)

	if other := refused.refusedFor(term+1, time.Now()); other != 0 {
		t.Errorf("the barriers of term %d are refused for %s by a run of term %d",
			term+1, other, term)
	}
}

// No election takes such a leader out, so the restart it exits for leaves the
// cluster an election to make.
func TestALeaderWhoseBarriersRaftRefusesEndsItsRun(t *testing.T) {
	c := newLiveCluster(t)
	c.timing.DeadAfter = shortlyDead
	c.genesis(3)
	leader := c.leader()
	follower := c.follower()
	term := leader.node.following().term
	now := time.Now()

	if err := leader.node.wedged(); err != nil {
		t.Fatalf("a leader whose barriers pass: %v", err)
	}
	leader.node.refusals.run.Store(&barrierRun{
		term:  term,
		since: now.Add(-c.timing.DeadAfter / 2),
	})
	if err := leader.node.wedged(); err != nil {
		t.Fatalf("a leader whose barriers Raft has refused for half a DeadAfter: %v", err)
	}
	leader.node.refusals.run.Store(&barrierRun{
		term:  term,
		since: now.Add(-2 * c.timing.DeadAfter),
	})

	err := leader.node.wedged()
	if !errors.Is(err, ErrLeftItsCluster) {
		t.Errorf("a leader whose every barrier Raft refuses answers %v, want it leaving its cluster", err)
	}
	if err := follower.node.wedged(); err != nil {
		t.Errorf("a replica that leads nothing: %v", err)
	}
}
