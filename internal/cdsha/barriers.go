// Raft refuses every barrier and every write of a leader whose leadership
// transfer stayed queued inside it (hashicorp/raft#696), and nothing takes
// that refusal back. A read is answered under a watermark a barrier confirmed
// (lease.go), so such a leader certifies no read and commits no write for
// anyone, and its heartbeats keep its leadership: it ends its Run, and the
// process that replaces it leaves the cluster an election to make.

package cdsha

import (
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"
)

// The run of refusals Raft has answered the barriers of one term with.
type barrierRefusals struct {
	run atomic.Pointer[barrierRun]
}

type barrierRun struct {
	term  uint64
	since time.Time
}

// The one barrier error no leader recovers from. Every other error is a
// barrier Raft took, however long this replica's state machine is over it.
func wedging(err error) bool {
	return errors.Is(err, raft.ErrLeadershipTransferInProgress)
}

func (b *barrierRefusals) record(term uint64, err error) {
	if !wedging(err) {
		b.run.Store(nil)
		return
	}
	if begun := b.run.Load(); begun != nil && begun.term == term {
		return
	}
	b.run.Store(&barrierRun{
		term:  term,
		since: time.Now(),
	})
}

func (b *barrierRefusals) refusedFor(term uint64, now time.Time) time.Duration {
	run := b.run.Load()
	if run == nil || run.term != term {
		return 0
	}
	return now.Sub(run.since)
}

func (n *Node) wedged() error {
	if !n.leading() {
		return nil
	}
	led := n.following()
	refusedFor := n.refusals.refusedFor(led.term, time.Now())
	if refusedFor <= n.cfg.Timing.DeadAfter {
		return nil
	}
	slog.Error("cds-ha: ALARM: this leader's Raft refuses every barrier of its term although its heartbeats reach a majority; it exits so another replica takes the cluster over",
		"refused_for", refusedFor.Round(time.Millisecond),
		"term", led.term,
		"commit_index", n.raft.CommitIndex(),
		"applied_index", n.fsm.AppliedIndex())
	return fmt.Errorf("%w: its Raft refused every barrier of term %d for %s",
		ErrLeftItsCluster, led.term, refusedFor.Round(time.Millisecond))
}
