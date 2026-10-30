package cdsha

import (
	"cmp"
	"errors"
	"fmt"
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
