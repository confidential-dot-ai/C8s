package cdsha

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
)

// The admission cap keeps the replicated state inside what a snapshot can
// hold. Every snapshot (Raft's own, a joining member's, a backup) must fit
// the compressed bound MaxSnapshotBytes, and zstd output is not meaningfully
// larger than its input, so a state whose decoded header and allowlist image
// together fit MaxSnapshotBytes fits every bound on the snapshot, backup,
// restore and join path (maxSnapshotHeader, maxSnapshotImage, the backup
// and restore limits). A state past it cannot be backed up, a new member
// cannot join, and the Raft log cannot compact.
//
// Writes that grow the state are refused once the estimate after the write
// passes 75% of that envelope. The other quarter absorbs writes in flight
// between the check and their commit, the writes admitted past the cap
// (deletes, token spends, prunes, bindings, decrees, seeds), estimate error,
// and the time until the leader next prunes the history.
//
// The cap is judged before a write is proposed (Node.propose on the
// replica that takes it, and again by the leader for forwarded writes),
// never in FSM.Apply: the estimate depends on each replica's own database
// pages, and Apply must decide the same on every replica.
//
// Atomics, so a test can lower them under a running cluster.
var admitTotalBytes, admitHeaderBytes atomic.Int64

func init() {
	admitTotalBytes.Store(MaxSnapshotBytes / 4 * 3)
	admitHeaderBytes.Store(maxSnapshotHeader / 4 * 3)
}

// ErrCapacity refuses a write that would grow the replicated state past the
// admission cap. The text crosses the control channel; capacityErr rebuilds
// the sentinel from it.
var ErrCapacity = errors.New("cds-ha: the replicated state is at its snapshot capacity")

// capacityErr is err as ErrCapacity when its text says so: a leader's
// refusal reaches a follower as text only.
func capacityErr(msg string) error {
	if _, rest, ok := strings.Cut(msg, ErrCapacity.Error()); ok {
		return fmt.Errorf("%w%s", ErrCapacity, rest)
	}
	return nil
}

// headerSlack covers the parts of the snapshot header not counted
// separately: field names, the index, the format, the CA key.
const headerSlack = 4 << 10

// headerBase is the JSON size of the core and the decree record, cached:
// both change only with a decree, a restore or a CA renewal.
type headerBase struct {
	epoch   uint64
	decrees int
	at      time.Time
	bytes   int64
}

// snapshotEstimate is a cheap upper bound on the decoded snapshot: the
// header (core, decrees, secrets, bindings) and the allowlist image. The
// image is the store's live pages; VACUUM INTO, which makes the image,
// writes no more than those. Secrets and bindings keep running totals.
func (f *FSM) snapshotEstimate() (header, image int64, err error) {
	if image, err = f.allowlist.LiveBytes(); err != nil {
		return 0, 0, err
	}
	f.mu.RLock()
	base := f.base
	stale := base.epoch != f.core.Epoch || base.decrees != len(f.decrees) || time.Since(base.at) > time.Second
	f.mu.RUnlock()
	if stale {
		f.mu.RLock()
		b := headerBase{epoch: f.core.Epoch, decrees: len(f.decrees), at: time.Now()}
		core, err1 := json.Marshal(f.core)
		decrees, err2 := json.Marshal(f.decrees)
		f.mu.RUnlock()
		if err := errors.Join(err1, err2); err != nil {
			return 0, 0, err
		}
		b.bytes = int64(len(core) + len(decrees))
		f.mu.Lock()
		f.base = b
		f.mu.Unlock()
		base = b
	}
	header = base.bytes + headerSlack + f.secrets.SnapshotBytes() + f.ledger.SnapshotBytes()
	return header, image, nil
}

// growth is how much e may add to the snapshot, and whether it is subject
// to the cap at all. Writes that shrink the state, or that the cluster
// needs at the cap, are not:
//   - deletes and history prunes shrink it;
//   - token spends: every write spends one first, a DELETE included, so
//     refusing them would refuse the writes that make room; a spent token
//     is one small row, dropped at expiry;
//   - the signature of a document whose replace_all was admitted (the same
//     request);
//   - seeds and the journal start: startup work that fails closed, so
//     refusing them would crash-loop replicas restarted at the cap;
//   - bindings (bounded by --sandbox-ledger-max-entries; issuance needs
//     them), decrees, restores and CA renewals.
func (f *FSM) growth(e Entry, raw int) (int64, bool) {
	switch {
	case e.Kind == KindAllowlist && e.Allowlist != nil:
		switch e.Allowlist.Op {
		case allowlist.OpPutWorkload, allowlist.OpReplaceAll, allowlist.OpReplaceRoutes:
			return int64(raw), true
		}
	case e.Kind == KindSecret && e.Secret != nil:
		if n := f.secrets.SnapshotGrowth(*e.Secret); n > 0 {
			return n, true
		}
	}
	return 0, false
}

// admit refuses e (marshalled as raw) with ErrCapacity when it would grow
// the state past the cap. It runs before a write is proposed, never in
// Apply (see admitTotalBytes). A state whose size cannot be read is not
// refused: the guard is a safety net, not a gate on availability.
func (f *FSM) admit(e Entry, raw int) error {
	add, checked := f.growth(e, raw)
	if !checked {
		return nil
	}
	header, image, err := f.snapshotEstimate()
	if err != nil {
		return nil
	}
	capHeader, capTotal := admitHeaderBytes.Load(), admitTotalBytes.Load()
	if e.Kind == KindSecret && header+add > capHeader {
		return fmt.Errorf("%w: snapshot header would be about %d bytes, writes that grow it are refused past %d (75%% of %d); secrets are bounded by --secrets-max-paths and --secrets-max-value-bytes",
			ErrCapacity, header+add, capHeader, maxSnapshotHeader)
	}
	if total := header + image + add; total > capTotal {
		return fmt.Errorf("%w: the state would be about %d bytes (allowlist store %d), writes that grow it are refused past %d (75%% of the %d-byte snapshot limit); delete allowlist entries or lower --allowlist-history-bytes/--allowlist-history-versions",
			ErrCapacity, total, image, capTotal, MaxSnapshotBytes)
	}
	return nil
}

// admitRaw is admit for an entry that arrived marshalled (a forwarded
// write). One that does not decode is left to Apply to refuse.
func (f *FSM) admitRaw(raw json.RawMessage) error {
	var e Entry
	if json.Unmarshal(raw, &e) != nil {
		return nil
	}
	return f.admit(e, len(raw))
}

// tooLarge reports a snapshot or backup that failed on a size bound. Raft
// wraps the FSM's error with %v, so only the text survives.
func tooLarge(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, errSnapshotTooLarge.Error()) || strings.Contains(msg, "exceeds compressed size limit")
}

// maxBackupBackoff caps the back-off of failing backups, in Timing.Backup.
const maxBackupBackoff = 16

// backupDelay is the wait before the next backup after failures
// consecutive ones on a size bound: base, doubled per failure, capped.
func backupDelay(base time.Duration, failures int) time.Duration {
	mult := 1
	for i := 0; i < failures && mult < maxBackupBackoff; i++ {
		mult *= 2
	}
	return base * time.Duration(mult)
}
