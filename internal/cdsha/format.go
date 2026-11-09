package cdsha

import (
	"cmp"
	"errors"
	"fmt"
	"log/slog"

	"github.com/hashicorp/raft"
)

// Format numbers the encodings replicas exchange: log entries and snapshots.
// A release that changes either raises it. Old and new replicas share one
// group during a roll, so:
//
//   - every replica writes the cluster's agreed format (ClusterState.Format), never a
//     newer one it happens to know;
//   - the leader raises the agreed format, through the log, only once every
//     seat is filled by a replica that reads the new one, and a replica too
//     old for the agreed format cannot join;
//   - a replica that meets an entry newer than it reads stops serving:
//     skipping one would silently diverge it from the group.
const Format uint32 = 1

// baseFormat is the oldest format this release reads: a new cluster starts at
// it, and a format left unset means it.
const baseFormat uint32 = 1

// ErrNewerFormat is a log entry in a newer format than this replica reads.
var ErrNewerFormat = errors.New("cds-ha: log entry in a newer format than this replica reads")

func (c ClusterState) format() uint32 {
	return cmp.Or(c.Format, baseFormat)
}

// The group writes a new encoding only after the last replica that cannot
// read it has given up its seat.
func (n *Node) raiseFormat() {
	if !n.leading() || n.ClockError() != nil {
		return
	}
	agreed := n.fsm.ClusterState().format()
	if n.fsm.readable <= agreed {
		return
	}
	seen, held := n.seatingNow()
	if !held || !seen.filled() || !n.everyVoterHolds(seen) {
		return
	}
	read, byEverySeat := n.formatEverySeatReads(seen)
	if !byEverySeat || read <= agreed {
		return
	}
	if _, err := n.propose(Entry{Kind: KindFormat, SetFormat: read}); err != nil {
		slog.Warn("cds-ha: the format every seat of this cluster reads did not commit",
			"format", read,
			"error", err)
		return
	}
	slog.Info("cds-ha: this cluster agreed on the format every voter seat reads",
		"audit", true,
		"from", agreed,
		"to", read)
}

// A voter that does not answer holds the agreed format where it is.
func (n *Node) formatEverySeatReads(seen seating) (uint32, bool) {
	read := n.fsm.readable
	for _, server := range seen.voters {
		if string(server.ID) == string(n.member) {
			continue
		}
		answer, err := n.askStanding(server.ID)
		if err != nil {
			n.formatHeldBy(server.ID, err)
			return 0, false
		}
		read = min(read, answer.Reads)
	}
	return read, true
}

// Once per reason, not every pass.
func (n *Node) formatHeldBy(member raft.ServerID, err error) {
	if n.formatLog.changed(string(member) + " " + err.Error()) {
		slog.Info("cds-ha: this cluster holds the format it agreed on: a voter seat did not answer what it reads",
			"member", member, "error", err)
	}
}

// applySetFormat never lowers the agreed format: a replica that joined
// because it reads the current one must keep reading the log.
func (f *FSM) applySetFormat(v uint32) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v > f.readable {
		return Result{Stop: f.stop(fmt.Errorf("%w: the cluster raised its format to %d, and this replica reads up to %d", ErrNewerFormat, v, f.readable))}
	}
	if v > f.core.format() {
		f.core.Format = v
	}
	return Result{}
}
