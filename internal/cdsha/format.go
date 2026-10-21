package cdsha

import (
	"errors"
	"fmt"
)

// Format numbers the encodings replicas exchange: log entries and snapshots.
// A release that changes either raises Format. Old and new replicas share one
// group during a rollout, so:
//
//   - every replica writes in the cluster's agreed format (Core.Format), never
//     in a newer one it happens to know;
//   - the leader raises the agreed format, through the log, only once every
//     member reads the new one, and a replica too old for the agreed format
//     cannot join;
//   - a replica that meets an entry or a snapshot newer than it reads stops
//     serving: skipping an entry would silently diverge from the group.
const Format uint32 = 1

// ErrNewerFormat is a log entry or snapshot this replica cannot read.
var ErrNewerFormat = errors.New("cds-ha: log entry or snapshot in a newer format than this replica reads")

// KindFormat raises the cluster's agreed format.
const KindFormat EntryKind = "format"

// formatOr1 maps the zero value (state from before formats were recorded) to 1.
func formatOr1(f uint32) uint32 {
	if f == 0 {
		return 1
	}
	return f
}

// Format is the agreed encoding format.
func (c Core) format() uint32 { return formatOr1(c.Format) }

// applyFormat raises the agreed format. It never lowers it: a replica that
// joined because it reads the current format must keep reading the log.
func (f *FSM) applyFormat(v uint32) error {
	if v > f.readable {
		return fmt.Errorf("%w: format %d, this replica reads up to %d", ErrNewerFormat, v, f.readable)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if v > f.core.format() {
		f.core.Format = v
	}
	return nil
}
