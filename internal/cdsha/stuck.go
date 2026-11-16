// A replica that stopped following the log serves nothing. What it does next
// is the kind of the stop (stop.go): a stall may still return, a stop every
// replica reaches at the same entry waits for an operator with the log it
// holds, and a fault of this replica's own store or process is cured by the
// restart that replays the cluster's log into a new member.
//
// Such a replica exits only while the voters that follow the log keep a
// majority without it: the log lives in the replicas' memory, and one fault
// can strike every replica at the same entry. A leader hands the cluster over
// first (handoff.go).

package cdsha

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/hashicorp/raft"
)

// The process exits on it, and the restart rejoins the cluster as a new
// member with the cluster's state (internal/cmds/cds).
var ErrLeftItsCluster = errors.New("cds-ha: this replica left its cluster")

// Often enough that an alarm over a window of time sees it.
const stuckAlarmEvery = time.Minute

func (n *Node) endsAtAFault() error {
	if err := n.wedged(); err != nil {
		return err
	}
	return n.endsStuck()
}

// A leader never passes leaveKeepsQuorum, so it hands the cluster over first
// (handoff.go).
func (n *Node) endsStuck() error {
	if !n.fsm.StuckLocal() || !n.stuckPastItsReads() {
		return nil
	}
	reason := n.fsm.Stuck()
	if !n.leaveKeepsQuorum() {
		n.alarmStuckWithTheLog(reason)
		return nil
	}
	return fmt.Errorf("%w: it stopped following the log: %s", ErrLeftItsCluster, reason)
}

// Past the lease the reads it answered were taken under, none of them is live.
func (n *Node) stuckPastItsReads() bool {
	return n.fsm.stuckFor() >= n.cfg.Timing.Lease
}

// Whoever reads the alarm restarts the stuck replicas one at a time, or
// Restores the cluster.
func (n *Node) alarmStuckWithTheLog(reason string) {
	if time.Since(n.stuckAlarmed) < stuckAlarmEvery {
		return
	}
	n.stuckAlarmed = time.Now()
	slog.Error("cds-ha: ALARM: this replica stopped following the log, and the replicas that follow it are no majority without it; it serves nothing and keeps its log",
		"reason", reason, "for", n.fsm.stuckFor().Round(time.Second))
}

// StuckOverdue is why this replica should have ended its own Run and has not.
// The process exits on it, so a replica whose loop waits behind the fault
// holds no open peer port while it serves nothing.
func (n *Node) StuckOverdue() string {
	if !n.fsm.StuckLocal() || n.fsm.stuckFor() <= n.cfg.Timing.DeadAfter+n.cfg.Timing.Lease {
		return ""
	}
	if !n.leaveKeepsQuorum() {
		return ""
	}
	return n.fsm.Stuck()
}

// A voter leaves only on the word of the leader it follows: that leader and
// the voters answering for it in the same term, each still following the log,
// must be a majority. Stuck voters count for nothing, so several of them
// stopped at one entry do not all leave together.
func (n *Node) leaveKeepsQuorum() bool {
	voters := votersOf(n.configuration())
	if !slices.Contains(voters, raft.ServerID(n.member)) {
		return true
	}
	led := n.following()
	if !led.known() || string(led.member) == string(n.member) {
		return false
	}
	// The voters that answer this replica say nothing about reaching each
	// other, so they count for nothing unless their leader answers itself.
	if !n.followsTheLogUnder(led.member, led) {
		return false
	}
	return moreThanHalf(n.votersFollowing(voters, led), len(voters))
}

// The leader counts, this replica does not.
func (n *Node) votersFollowing(voters []raft.ServerID, led leadership) int {
	following := 0
	for _, voter := range voters {
		if string(voter) == string(n.member) {
			continue
		}
		if n.followsTheLogUnder(voter, led) {
			following++
		}
	}
	return following
}

func (n *Node) followsTheLogUnder(member raft.ServerID, led leadership) bool {
	answer, err := n.askStanding(member)
	if err != nil {
		return false
	}
	return answer.Leader == string(led.member) && answer.Term == led.term && answer.Stuck == ""
}

func votersOf(servers []raft.Server) []raft.ServerID {
	var voters []raft.ServerID
	for _, server := range servers {
		if server.Suffrage == raft.Voter {
			voters = append(voters, server.ID)
		}
	}
	return voters
}

// Since when the voters that follow the log have kept a majority without this
// replica while its state machine is held.
type stallWatch struct {
	majorityWithout time.Time
}

func (w *stallWatch) heldFor(now time.Time, d time.Duration) bool {
	if w.majorityWithout.IsZero() {
		w.majorityWithout = now
	}
	return now.Sub(w.majorityWithout) >= d
}

func (w *stallWatch) ended() {
	w.majorityWithout = time.Time{}
}

// Raft answers heartbeats while a command applies, so a replica whose state
// machine is held would keep a voter seat it carries no log in. A loop of its
// own: the command that holds the state machine cannot hold it up.
func (n *Node) watchStalls(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	var watch stallWatch
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n.stallLongCommand()
		n.hangLastingStall(&watch)
	}
}

// The longest wait for a command: DeadAfter, and the budget of the replicated
// write it may be.
func (n *Node) stallLongCommand() {
	applying := n.fsm.ApplyingFor()
	if applying < n.cfg.Timing.DeadAfter+n.cfg.Timing.Apply {
		return
	}
	n.fsm.Stall(fmt.Errorf("this replica's state machine has been applying one command for %s",
		applying.Round(time.Second)))
}

// A command the cluster outlasted is held for good, and a restart is what
// takes this replica back into its cluster. Replicas stalled at one entry
// whose commands return a moment apart all stay.
func (n *Node) hangLastingStall(watch *stallWatch) {
	stall, stalling := n.fsm.stalling()
	if !stalling || !n.leaveKeepsQuorum() {
		watch.ended()
		return
	}
	if !watch.heldFor(time.Now(), n.cfg.Timing.DeadAfter) {
		return
	}
	n.fsm.hang(stall, "the replicas that follow the log keep a majority without this one")
}
