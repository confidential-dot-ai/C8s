// The decree board: the operator may leave a signed decree on an object store
// outside the trust boundary instead of posting it to a replica, and the
// cluster's leader reads it there for itself. The host can withhold a decree
// or serve an old one and gets nothing else: a decree carries the operator's
// signature over everything it says, and the leader judges and applies it
// exactly as it does one posted to a replica.

package cdsha

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// boardCycle bounds one pass over the board: the store is the host's to serve
// and may stall, and a pass that did not finish inside it is one the next
// tick makes again.
const boardCycle = 30 * time.Second

// applyBoardDecrees applies the decrees of the cluster's board, oldest
// version first, which is the leader's duty alone.
func (n *Node) applyBoardDecrees(ctx context.Context) {
	if !n.leading() {
		return
	}
	decrees := n.boardDecrees(ctx)
	slices.SortStableFunc(decrees, byTheVersionTheyApplyOn)
	for _, signed := range decrees {
		if !n.leading() {
			return
		}
		n.applyFromBoard(signed)
	}
}

// byTheVersionTheyApplyOn orders decrees as they apply: each names the
// version it applies on, which the decree before it produced.
func byTheVersionTheyApplyOn(a, b cdsdecree.Signed) int {
	return cmp.Compare(a.Decree.BaseVersion, b.Decree.BaseVersion)
}

// boardDecrees are the signed decrees on the cluster's board, and none where
// its configuration names no board. A board this replica cannot read says so
// once, not every tick.
func (n *Node) boardDecrees(ctx context.Context) []cdsdecree.Signed {
	if n.cfg.Board == nil {
		return nil
	}
	reading, done := context.WithTimeout(ctx, boardCycle)
	defer done()
	decrees, err := n.cfg.Board(reading)
	if err != nil {
		if n.boardLog.changed(err.Error()) {
			slog.Warn("cds-ha: this replica cannot read the board of its cluster", "error", err)
		}
		return nil
	}
	return decrees
}

// applyFromBoard puts one decree of the board on the log, and passes over
// the ones this leader does nothing with.
func (n *Node) applyFromBoard(signed cdsdecree.Signed) {
	if err := n.operatorSigned(signed); err != nil {
		if n.objectLog.changed(err.Error()) {
			slog.Warn("cds-ha: this cluster's board carries an object that is no decree of its operator", "error", err)
		}
		return
	}
	if n.leftOnTheBoard(signed.Decree) {
		return
	}
	delivered, err := n.applyDecree(signed)
	switch {
	case err != nil:
		slog.Warn("cds-ha: a decree of this cluster's board did not apply", "intent", signed.Decree.IntentID, "error", err)
	case delivered.Refused != "":
		slog.Info("cds-ha: this cluster refused a decree of its board", "intent", signed.Decree.IntentID, "refused", delivered.Refused)
	}
}

// leftOnTheBoard reports a decree of the board this leader does nothing with:
// one the replica it names acts on itself, one the cluster has accounted for,
// and one that applies on another version than the cluster's, which the
// decree before it produces.
func (n *Node) leftOnTheBoard(d cdsdecree.Decree) bool {
	core := n.fsm.ClusterState()
	switch {
	case actedOnByItsTarget(d.Kind):
		return true
	case core.accountedFor(d.IntentID):
		return true
	case d.BaseVersion != core.Version:
		return true
	}
	return false
}
