// One limit bounds the replicated state, and one cap keeps a cluster inside
// it. A replica holds that state in TEE memory and nowhere else: the
// allowlist database on a tmpfs, the secrets and bindings in the process,
// and, while a replica joins, a second copy of the whole state beside them.
// MaxStateBytes is that limit; the snapshot bounds and the admission cap
// derive from it.

package cdsha

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// MaxStateBytes is the most replicated state a replica holds, decoded. A
// replica is sized to hold it twice: its own state, and the copy a joining
// replica takes from it.
const MaxStateBytes int64 = 256 << 20

// headerShare is the part of the state limit that goes to what a replica
// holds in its process: the secrets, the sandbox bindings and the decree
// record. The allowlist database is the state's bulk and gets the rest.
const headerShare = MaxStateBytes / 16

// bounds are the sizes MaxStateBytes sets.
type bounds struct {
	// header bounds a snapshot's header: the core, the decree record, the
	// secrets and the bindings.
	header int64
	// image bounds the allowlist database image.
	image int64
	// stream bounds the compressed snapshot a replica reads, which carries
	// at most the two parts above.
	stream int64
}

// stateBounds is every size the state limit sets.
func stateBounds() bounds {
	return bounds{
		header: headerShare,
		image:  MaxStateBytes - headerShare,
		stream: MaxStateBytes,
	}
}

// admitted is the share of a bound that writes which grow the state may
// fill. The rest is the room the writes the cap does not judge are taken
// from.
func admitted(bound int64) int64 {
	return bound / 4 * 3
}

// ErrCapacity refuses a write that would take the replicated state past the
// admission cap. It clears as the state shrinks: entries deleted, history
// pruned.
var ErrCapacity = errors.New("cds-ha: the replicated state is at its capacity")

// ErrStateTooLarge is a state too large for a snapshot a replica can read.
var ErrStateTooLarge = errors.New("cds-ha: the replicated state is larger than a snapshot carries")

// Admit refuses a log entry, as its proposer holds it, that would take the
// state past the admission cap. The replica that takes the write judges it,
// and the leader judges it again for a write forwarded to it; Apply never
// does, because each replica's own database pages decide it and every
// replica must apply an entry alike.
func (f *FSM) Admit(entry []byte) error {
	var e Entry
	if err := decodeStrict(entry, &e); err != nil {
		return err
	}
	return f.admit(stateBounds(), e, int64(len(entry)))
}

// admit refuses e, whose entry is entryBytes long, once the part of the
// state it grows would pass its share of b. The entry's own length is what
// the write adds: a secret's path and value, or a document the allowlist
// store writes as rows.
func (f *FSM) admit(b bounds, e Entry, entryBytes int64) error {
	if !cappedWrite(e) {
		return nil
	}
	header, image, err := f.stateSize()
	if err != nil {
		// The cap is a safety net, not a gate on availability.
		slog.Warn("cds-ha: the size of this replica's state cannot be read, so the admission cap judges no write", "error", err)
		return nil
	}
	if e.Kind == KindSecret {
		return overCap("the snapshot header", header+entryBytes, admitted(b.header))
	}
	return overCap("the allowlist store", image+entryBytes, admitted(b.image))
}

// overCap is ErrCapacity when a part of the state grown to size passes
// limit, naming the part that is full.
func overCap(part string, size, limit int64) error {
	if size <= limit {
		return nil
	}
	return fmt.Errorf("%w: %s would be about %d bytes, and a write that grows it is refused past %d",
		ErrCapacity, part, size, limit)
}

// stateSize is the size of the snapshot this replica's state would make: the
// header it would carry, and the allowlist database image. The image is the
// store's live pages, which is what VACUUM INTO writes. Sizing the header
// encodes it, so this costs one pass over the state the process holds.
func (f *FSM) stateSize() (header, image int64, err error) {
	image, err = f.allowlist.LiveBytes()
	if err != nil {
		return 0, 0, err
	}
	sn, err := f.state()
	if err != nil {
		return 0, 0, err
	}
	line, err := headerLine(sn)
	if err != nil {
		return 0, 0, err
	}
	return int64(len(line)), image, nil
}

// cappedWrite reports a write the cap judges: an allowlist document or a
// secret. Every other entry passes, including the prunes and token spends
// that make room, the startup writes a replica at the cap must still do, and
// the kinds the cluster's policy and the decree record already bound.
func cappedWrite(e Entry) bool {
	switch e.Kind {
	case KindAllowlist:
		return e.Allowlist != nil && cappedAllowlistOp(e.Allowlist.Op)
	case KindSecret:
		return e.Secret != nil
	}
	return false
}

// cappedAllowlistOp reports the allowlist writes the cap judges: the ones
// that write a document of the operator's choosing.
func cappedAllowlistOp(op allowlist.Op) bool {
	switch op {
	case allowlist.OpReplaceAll,
		allowlist.OpReplaceRoutes:
		return true
	}
	return false
}
