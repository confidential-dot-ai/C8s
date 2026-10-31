// The leader's backup duty: once an interval it has Raft capture the whole
// replicated state, seals it to the cluster's recovery key (backup.go) and
// appends it to the board as one new object. It seals state at or above a
// checkpoint a majority of the voters held this leader's state at, so a
// replica that diverged seeds no backup (divergence.go).
//
// The board is the only place the cluster's state exists outside the
// replicas' memory, so a run of failures is an alarm: a total loss would
// restore state older than the cluster holds.

package cdsha

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/cdsboard"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// backupAlarmAttempts is the run of failures the alarm is raised at.
const backupAlarmAttempts = 3

// maxBackupDoublings bounds the backoff: every attempt encodes the whole
// state, so the duty waits one interval more than twice as long after each
// failure, up to 16 intervals.
const maxBackupDoublings = 4

// appendDeadline bounds the write of one sealed state to the board, which is
// the largest object a replica puts there: four passes over the board.
const appendDeadline = 4 * boardCycle

// StoredBackup is the backup a leader last appended to its cluster's board.
type StoredBackup struct {
	Version uint64 `json:"version"`
	Index   uint64 `json:"index"`
	// SealedAtMS is the clock of the leader that sealed it.
	SealedAtMS int64 `json:"sealed_at_ms"`
}

// backupDuty is what the duty keeps between its turns: the figures its own
// loop reads and writes, and the report every reader of Status sees.
type backupDuty struct {
	attemptedAt time.Time
	// storedIndex is the log index of the state on the board.
	storedIndex  uint64
	fails        int
	failingSince time.Time
	alarmed      bool

	report backupReport
}

// backupReport is what this replica says about its backups, to any reader of
// Status while the duty runs.
type backupReport struct {
	stored  atomic.Pointer[StoredBackup]
	failure atomic.Pointer[string]
}

// keepBackups appends the cluster's state to its board until ctx ends. It
// runs on a loop of its own: capturing and sealing the state encodes all of
// it, and no other duty of the replica waits for that.
func (n *Node) keepBackups(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n.backUpWhenDue(ctx)
	}
}

// backUpWhenDue appends one backup where this leader is due to.
func (n *Node) backUpWhenDue(ctx context.Context) {
	duty := n.backups
	confirmed, due := n.dueToBackUp(duty)
	if !due {
		return
	}
	backup, err := n.appendedBackup(ctx, confirmed)
	duty.attempted()
	if err != nil {
		duty.failed(n.cfg.Timing.Backup, err)
		return
	}
	duty.appended(backup)
}

// dueToBackUp is the checkpoint the next backup seals at or above, and
// whether this leader's turn to append one has come: its cluster names a
// board and a recovery key, it serves that cluster, an interval has passed
// since its last attempt, and the voters have confirmed a checkpoint above
// the state the board holds.
func (n *Node) dueToBackUp(duty *backupDuty) (Point, bool) {
	if n.cfg.AppendBackup == nil {
		return Point{}, false
	}
	if !n.leading() || n.fenced() != nil || !n.fsm.ClusterState().Joined() {
		return Point{}, false
	}
	if !duty.due(n.cfg.Timing.Backup, time.Now()) {
		return Point{}, false
	}
	confirmed, held := n.div.confirmedCheckpoint()
	return confirmed, held && confirmed.Index > duty.storedIndex
}

// appendedBackup seals this cluster's state and appends it to the board.
func (n *Node) appendedBackup(ctx context.Context, confirmed Point) (Backup, error) {
	backup, err := n.sealedState(confirmed)
	if err != nil {
		return Backup{}, err
	}
	return backup, n.appendBackup(ctx, backup)
}

// sealedState is this cluster's state as one sealed backup: the state Raft
// captured at or above the checkpoint the voters confirmed, and the seal to
// the recovery key.
func (n *Node) sealedState(confirmed Point) (Backup, error) {
	body, err := n.capturedState(confirmed)
	if err != nil {
		return Backup{}, err
	}
	backup, err := SealBackup(n.cfg.RecoveryKey, body, time.Now())
	if err != nil {
		return Backup{}, fmt.Errorf("seal the state to the cluster's recovery key: %w", err)
	}
	return backup, nil
}

// capturedState is the state this replica holds as a snapshot stream, at or
// above the checkpoint the voters confirmed. Raft captures it between two
// entries, so what it carries is the state at one log index.
func (n *Node) capturedState(confirmed Point) ([]byte, error) {
	if err := n.captureState(); err != nil {
		return nil, err
	}
	stream, index, held := n.snaps.heldState()
	if !held {
		return nil, errors.New("capture the state: this replica holds no snapshot of it")
	}
	if index < confirmed.Index {
		return nil, fmt.Errorf("capture the state: the snapshot this replica holds is at log index %d, and the voters confirmed the state at %d", index, confirmed.Index)
	}
	return readutil.ReadAll(stream, stateBounds().stream)
}

// captureState has Raft capture the state, which compacts this replica's log
// as well. A capture Raft answers with nothing new leaves the snapshot it
// holds as the newest state.
func (n *Node) captureState() error {
	err := n.raft.Load().Snapshot().Error()
	if err == nil || errors.Is(err, raft.ErrNothingNewToSnapshot) {
		return nil
	}
	return fmt.Errorf("capture the state: %w", err)
}

// appendBackup writes one sealed backup to the board under a name of its own.
func (n *Node) appendBackup(ctx context.Context, b Backup) error {
	object, err := b.Object()
	if err != nil {
		return err
	}
	appending, done := context.WithTimeout(ctx, appendDeadline)
	defer done()
	name := cdsboard.BackupName{
		CASHA256: certutil.CertFingerprint(b.SourceCert),
		Version:  b.Meta.Version,
		Index:    b.Meta.Index,
	}
	if err := n.cfg.AppendBackup(appending, name, object); err != nil {
		return fmt.Errorf("append the sealed state to the board: %w", err)
	}
	return nil
}

// due reports the duty's turn: the wait since its last attempt has passed.
func (d *backupDuty) due(interval time.Duration, now time.Time) bool {
	return now.Sub(d.attemptedAt) >= d.wait(interval)
}

// wait is how long the duty leaves between two attempts: one interval, and
// twice as long for every failure since the backup the board holds.
func (d *backupDuty) wait(interval time.Duration) time.Duration {
	return interval << min(d.fails, maxBackupDoublings)
}

// attempted records that the duty has just tried, so the wait is between the
// end of one attempt and the start of the next.
func (d *backupDuty) attempted() {
	d.attemptedAt = time.Now()
}

// appended records the backup the board holds.
func (d *backupDuty) appended(b Backup) {
	d.storedIndex = b.Meta.Index
	d.fails = 0
	d.alarmed = false
	d.report.failure.Store(nil)
	d.report.stored.Store(&StoredBackup{
		Version:    b.Meta.Version,
		Index:      b.Meta.Index,
		SealedAtMS: b.Meta.SealedAtMS,
	})
	slog.Info("cds-ha: this leader appended a sealed backup of its cluster's state to the board", "audit", true,
		"version", b.Meta.Version, "index", b.Meta.Index, "bytes", len(b.Ciphertext))
}

// failed records a backup this leader did not store, and raises the alarm
// once the run of failures is long enough.
func (d *backupDuty) failed(interval time.Duration, err error) {
	if d.fails == 0 {
		d.failingSince = time.Now()
	}
	d.fails++
	reason := fmt.Sprintf("failing since %s (%d attempts): %v", d.failingSince.UTC().Format(time.RFC3339), d.fails, err)
	d.report.failure.Store(&reason)
	if d.alarms() {
		d.alarmed = true
		slog.Error("cds-ha: ALARM: this cluster's board holds no backup of the state it has now; a total loss would restore older state",
			"error", err, "attempts", d.fails, "failing_for", time.Since(d.failingSince).Round(time.Second), "next_attempt_in", d.wait(interval))
		return
	}
	slog.Warn("cds-ha: this leader did not store a backup of its cluster's state", "error", err, "attempts", d.fails)
}

// alarms reports a run of failures the alarm is raised for, once per run.
func (d *backupDuty) alarms() bool {
	return !d.alarmed && d.fails >= backupAlarmAttempts
}

// reported is what an operator reads about this leader's backups: the newest
// one it appended to the board, and why its backups are failing.
func (d *backupDuty) reported() (*StoredBackup, string) {
	failure := d.report.failure.Load()
	if failure == nil {
		return d.report.stored.Load(), ""
	}
	return d.report.stored.Load(), *failure
}
