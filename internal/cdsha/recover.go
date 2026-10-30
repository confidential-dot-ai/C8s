// Recover: the one surviving voter the operator hands the cluster to.
//
// A majority of the voters is gone for good. The log lives in the replicas'
// TEE memory, so what those voters held went with them, and the survivors can
// elect nobody. The operator reads what one survivor holds over the attested
// channel and signs a Recover decree for the member id that survivor minted
// at its start; that member then carries the cluster on alone with the state
// it has applied. Entries the lost voters committed and it never received are
// gone with them.
//
// It is break-glass: the survivor cannot tell a majority that is gone from
// one the host cut it off from. So it holds off for recoverHold, by which
// time a cluster that still has a majority has doubted the same decree and
// stopped serving (fence.go), and it acts only while no member of its cluster
// answers with a leader. Its leader duty then puts the decree on the log it
// carries on, so the decree can never apply again (leader.go).

package cdsha

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// recoverSighting is the Recover decree a replica that follows no leader
// holds off on, and when it first saw it with no leader since.
type recoverSighting struct {
	intent string
	at     time.Time
}

// watchForRecover drives the replica a Recover decree names until ctx ends:
// while it follows no leader it looks for the operator's decree for itself on
// the cluster's board, and acts on it once the hold has passed. The loop is
// its own, so a board read that waits on the network holds up no other duty
// of the replica.
func (n *Node) watchForRecover(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	var sighted recoverSighting
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n.recoverWhenDecreed(ctx, &sighted)
	}
}

// recoverWhenDecreed carries the cluster on alone where the operator decreed
// that this replica does and the hold has passed.
func (n *Node) recoverWhenDecreed(ctx context.Context, sighted *recoverSighting) {
	decreed, ok := n.decreedRecover(ctx)
	if !ok || !n.heldOffLongEnough(decreed, sighted) {
		return
	}
	if n.aMemberAnswersWithALeader() {
		*sighted = recoverSighting{}
		return
	}
	n.carryTheClusterAlone(decreed)
}

// decreedRecover is the operator's Recover decree for this process, where a
// replica this decree could hand the cluster to finds one on the board.
func (n *Node) decreedRecover(ctx context.Context) (cdsdecree.Signed, bool) {
	if !n.awaitsRecovery() {
		return cdsdecree.Signed{}, false
	}
	decrees, _ := n.boardDecrees(ctx)
	for _, signed := range decrees {
		if n.recoversThisProcess(signed) {
			return signed, true
		}
	}
	return cdsdecree.Signed{}, false
}

// awaitsRecovery reports a replica a Recover decree could hand the cluster
// to: a voter that holds the cluster and follows no leader. A non-voter's log
// need not hold every entry the cluster committed, so it carries none on.
func (n *Node) awaitsRecovery() bool {
	if !n.fsm.ClusterState().Joined() || n.following().known() {
		return false
	}
	return slices.Contains(votersOf(n.configuration()), raft.ServerID(n.member))
}

// recoversThisProcess reports a Recover decree this process is the target of:
// the operator signed it for the member id this process minted at its start,
// so neither another replica nor a restart of this one acts on it. One the
// cluster applied or doubts is dealt with: a doubt of it means the cluster
// that holds it is back.
func (n *Node) recoversThisProcess(signed cdsdecree.Signed) bool {
	decree := signed.Decree
	if decree.Kind != cdsdecree.Recover || decree.TargetMember != string(n.member) {
		return false
	}
	if n.fsm.ClusterState().dealtWith(decree.IntentID) {
		return false
	}
	if err := n.operatorSigned(signed); err != nil {
		if n.recoverLog.changed(err.Error()) {
			slog.Warn("cds-ha: a Recover decree names this replica and it is not the operator's", "error", err)
		}
		return false
	}
	return true
}

// heldOffLongEnough reports a Recover decree this replica has held off on for
// recoverHold with no leader since. Any contact from a leader starts the hold
// over: a cluster that has one needs no Recover, and this loop's own ticks can
// miss a short contact.
func (n *Node) heldOffLongEnough(signed cdsdecree.Signed, sighted *recoverSighting) bool {
	intent := signed.Decree.IntentID
	if sighted.intent != intent || n.leaderContactedSince(sighted.at) {
		*sighted = recoverSighting{intent: intent, at: time.Now()}
		if n.recoverLog.changed(intent) {
			slog.Warn("cds-ha: a Recover decree names this replica; it carries the cluster on alone after the hold, unless its cluster answers",
				"intent", intent, "hold", n.cfg.Timing.recoverHold())
		}
		return false
	}
	return time.Since(sighted.at) >= n.cfg.Timing.recoverHold()
}

// leaderContactedSince reports a leader of this cluster having reached this
// replica's Raft since at. A replica no leader has ever reached reports no
// contact at all.
func (n *Node) leaderContactedSince(at time.Time) bool {
	contact := n.raft.Load().LastContact()
	return !contact.IsZero() && contact.After(at)
}

// aMemberAnswersWithALeader reports a member of this cluster's configuration
// that answers with a leader: a majority is carrying the cluster, and this
// replica must not start a second one. A member that answers with no leader
// is no sign of a majority.
func (n *Node) aMemberAnswersWithALeader() bool {
	for _, server := range n.configuration() {
		if string(server.ID) == string(n.member) {
			continue
		}
		answer, err := n.askStanding(server.ID)
		if err != nil || answer.Leader == "" {
			continue
		}
		slog.Warn("cds-ha: a Recover decree names this replica and a member of its cluster answers with a leader; it carries no cluster on",
			"member", server.ID, "leader", answer.Leader)
		return true
	}
	return false
}

// carryTheClusterAlone makes this replica the one voter of its cluster, with
// the state it holds. Its leader duty records the decree on the log it
// carries on (leader.go).
func (n *Node) carryTheClusterAlone(signed cdsdecree.Signed) {
	slog.Warn("cds-ha: this replica carries its cluster on alone with the state it holds; the entries the lost voters committed and it never received are gone", "audit", true,
		"intent", signed.Decree.IntentID, "member", n.member, "applied_index", n.fsm.AppliedIndex())
	if err := n.replayAlone(); err != nil {
		// Raft is down, so this replica serves nothing and takes no write.
		// An operator left without a cluster restores one from a backup.
		_ = n.fsm.stopLocal(fmt.Errorf("carry this cluster on alone: %w", err))
		return
	}
	if !await(bootstrapElections*n.cfg.Timing.Election, n.leading) {
		slog.Error("cds-ha: this replica carries its cluster on alone and does not lead it")
	}
}

// replayAlone replaces this replica's Raft with one whose configuration is
// this member alone. The group it was in can elect no leader, so no entry of
// its log can change that configuration.
func (n *Node) replayAlone() error {
	if err := n.shutDownRaft(); err != nil {
		return err
	}
	if err := n.keepStateAlone(); err != nil {
		return err
	}
	return n.startRaft()
}

// soloConfigurationIndex is the log index the one-voter configuration counts
// as committed at, as raft.RecoverCluster records one: the first index of any
// cluster, which is below every index this one reached.
const soloConfigurationIndex = 1

// keepStateAlone writes the state this replica has applied as the snapshot of
// a one-voter cluster, in the term its stopped Raft reached, and drops the log
// that state was applied from. Raft's stores live in this process's memory
// beside the state machine, so the state a replay of that log would produce is
// here already, and a replay would add the entries the lost voters never
// committed.
func (n *Node) keepStateAlone() error {
	state, err := n.fsm.Snapshot()
	if err != nil {
		return err
	}
	term := n.raft.Load().CurrentTerm()
	sink, err := n.snaps.Create(raft.SnapshotVersionMax, state.Index(), term, n.solo(), soloConfigurationIndex, nil)
	if err != nil {
		return err
	}
	if err := state.Encode(sink); err != nil {
		_ = sink.Cancel()
		return err
	}
	if err := sink.Close(); err != nil {
		return err
	}
	n.logs.dropAll()
	return nil
}
