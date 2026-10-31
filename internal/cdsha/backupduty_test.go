package cdsha

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// The leader's duty: once an interval it appends the sealed state of its
// cluster to the board, and nothing while the log has not moved past the
// backup the board holds.

// backupsOnTheBoard waits until the cluster's board holds count backups, and
// answers with the backups it holds, oldest first.
func (c *liveCluster) backupsOnTheBoard(count int) []Backup {
	c.t.Helper()
	eventually(c.t, 20*time.Second, fmt.Sprintf("%d backups on the cluster's board", count), func() bool {
		return len(c.board.appendedBackups()) >= count
	})
	var backups []Backup
	for _, appended := range c.board.appendedBackups() {
		backup, err := ParseBackup(appended.sealed)
		if err != nil {
			c.t.Fatalf("the board holds an object that is no sealed backup: %v", err)
		}
		backups = append(backups, backup)
	}
	return backups
}

// meshCAOf is the mesh CA fingerprint an operator keeps from the live
// cluster, which is what a backup is authenticated against.
func meshCAOf(r *liveReplica) string {
	return certutil.CertFingerprint(r.node.ClusterState().MeshCACert)
}

func TestTheLeaderAppendsTheSealedStateOfItsClusterToTheBoard(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()

	backup := c.backupsOnTheBoard(1)[0]
	if err := VerifyBackupSource(backup, meshCAOf(leader)); err != nil {
		t.Fatalf("the backup is not of the cluster's mesh CA: %v", err)
	}
	body, err := OpenBackup(c.recovery, backup)
	if err != nil {
		t.Fatalf("the backup does not open with the cluster's recovery key: %v", err)
	}
	if err := ValidateRecoverySnapshot(body, backup, 0, 0); err != nil {
		t.Fatalf("the state the backup holds: %v", err)
	}
	named := c.board.appendedBackups()[0].name
	if named.CASHA256 != meshCAOf(leader) || named.Version != backup.Meta.Version || named.Index != backup.Meta.Index {
		t.Fatalf("the board holds the backup under %+v, and it holds version %d at index %d of mesh CA %s",
			named, backup.Meta.Version, backup.Meta.Index, meshCAOf(leader))
	}
	if backup.Meta.StateDigest == (digest{}) {
		t.Fatal("the backup names no digest of the state it holds")
	}
	if status := leader.node.Status(); status.BackupError != "" || status.LastBackup == nil || status.LastBackup.Index != backup.Meta.Index {
		t.Fatalf("the leader reports last_backup %+v and backup_error %q", status.LastBackup, status.BackupError)
	}
	for _, follower := range c.besides(leader) {
		if status := follower.node.Status(); status.LastBackup != nil {
			t.Fatalf("a replica that does not lead answers for the backups: %+v", status.LastBackup)
		}
	}
}

// Every backup is one new object, and the next one holds the state the log
// reached since.
func TestTheNextBackupFollowsTheOneTheBoardHolds(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	first := c.backupsOnTheBoard(1)[0]

	// Turns of the duties loop, not a span of time: the duty had its turn
	// several backup intervals over.
	c.afterBoardCycles(int(4 * c.timing.Backup / c.timing.Tick))
	if held := c.board.appendedBackups(); len(held) != 1 {
		t.Fatalf("a cluster whose state has not moved appended %d backups", len(held))
	}
	if err := writeASecret(c.leader(), "tenant/key"); err != nil {
		t.Fatalf("write a secret: %v", err)
	}
	next := c.backupsOnTheBoard(2)[1]
	if !next.Meta.Follows(first.Meta) {
		t.Fatalf("the backup of version %d at index %d does not follow the one of version %d at index %d",
			next.Meta.Version, next.Meta.Index, first.Meta.Version, first.Meta.Index)
	}
}

// Backups are the only copy of the state outside the replicas' memory, so a
// board that takes none is reported to the operator, and tried again.
func TestABoardThatTakesNoBackupIsReportedAndTriedAgain(t *testing.T) {
	c := newLiveCluster(t)
	c.board.refuseBackups(true)
	c.genesis(1)
	leader := c.leader()

	eventually(t, 20*time.Second, "the leader reporting that its backups fail", func() bool {
		return leader.node.Status().BackupError != ""
	})
	if status := leader.node.Status(); status.LastBackup != nil {
		t.Fatalf("a leader whose backups fail reports a stored backup: %+v", status.LastBackup)
	}
	c.board.refuseBackups(false)
	eventually(t, 20*time.Second, "the leader storing a backup again", func() bool {
		status := leader.node.Status()
		return status.LastBackup != nil && status.BackupError == ""
	})
}

// Raft compacts a replica's log by capturing its state on its own, so a
// capture it answers with nothing new leaves the snapshot it holds as the
// newest state, and the backup seals that.
func TestABackupSealsTheStateRaftAlreadyCaptured(t *testing.T) {
	c := newLiveCluster(t)
	c.board.refuseBackups(true)
	c.genesis(1)
	leader := c.leader()
	eventually(t, 20*time.Second, "the leader trying to back its cluster up", func() bool {
		return leader.node.Status().BackupError != ""
	})
	if err := leader.node.raft.Load().Snapshot().Error(); err != nil && !errors.Is(err, raft.ErrNothingNewToSnapshot) {
		t.Fatalf("capture the state: %v", err)
	}

	c.board.refuseBackups(false)
	backup := c.backupsOnTheBoard(1)[0]
	body, err := OpenBackup(c.recovery, backup)
	if err != nil {
		t.Fatalf("the backup does not open with the cluster's recovery key: %v", err)
	}
	if err := ValidateRecoverySnapshot(body, backup, 0, 0); err != nil {
		t.Fatalf("the state the backup holds: %v", err)
	}
	if applied := leader.node.fsm.AppliedIndex(); backup.Meta.Index != applied {
		t.Fatalf("the backup holds the state at index %d, and the leader applied %d", backup.Meta.Index, applied)
	}
}

func TestADutyThatStoredNoBackupIsDueAtOnceAndThenOnceAnInterval(t *testing.T) {
	duty := &backupDuty{}
	interval := time.Minute
	if !duty.due(interval, time.Now()) {
		t.Fatal("a leader that stored no backup is not due to store one")
	}
	duty.attempted()
	if duty.due(interval, duty.attemptedAt.Add(interval-time.Second)) {
		t.Fatal("a backup is due inside the interval since the last attempt")
	}
	if !duty.due(interval, duty.attemptedAt.Add(interval)) {
		t.Fatal("a backup is not due an interval after the last attempt")
	}
}

// Every attempt encodes the whole state, so a failing duty waits longer each
// time, and a stored backup puts it back on the interval.
func TestAFailingBackupWaitsLongerEachTime(t *testing.T) {
	duty := &backupDuty{}
	interval := time.Minute
	failed := errors.New("append the sealed state to the board: the board answered 503 Service Unavailable")
	for _, want := range []time.Duration{2 * interval, 4 * interval, 8 * interval, 16 * interval, 16 * interval} {
		duty.failed(interval, failed)
		if waited := duty.wait(interval); waited != want {
			t.Fatalf("after %d failures the duty waits %s, want %s", duty.fails, waited, want)
		}
	}
	if _, reported := duty.reported(); reported == "" {
		t.Fatal("a leader whose backups fail reports nothing")
	}
	duty.appended(Backup{Meta: BackupMeta{Version: 3, Index: 90}})
	if waited := duty.wait(interval); waited != interval {
		t.Fatalf("a stored backup leaves the duty waiting %s, want %s", waited, interval)
	}
	stored, reported := duty.reported()
	if reported != "" || stored == nil || stored.Index != 90 {
		t.Fatalf("a stored backup is reported as %+v, %q", stored, reported)
	}
}

// A failure is an alarm once the run of them reaches the attempts it takes,
// and then once per run.
func TestARunOfFailedBackupsRaisesTheAlarmOnce(t *testing.T) {
	duty := &backupDuty{}
	interval := time.Minute
	failed := errors.New("append the sealed state to the board: the board answered 503 Service Unavailable")
	for range backupAlarmAttempts - 1 {
		duty.failed(interval, failed)
		if duty.alarmed {
			t.Fatalf("a run of %d failures raised the alarm", duty.fails)
		}
	}
	duty.failed(interval, failed)
	if !duty.alarmed {
		t.Fatalf("a run of %d failures raised no alarm", duty.fails)
	}
	if duty.alarms() {
		t.Fatal("a run of failures raises the alarm twice")
	}
}

// A backup is of state a majority of the voters vouched for, so a
// disagreement no majority settles stops the backups until it is settled.
func TestADisagreementWithoutAMajorityStopsTheBackups(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leading := c.leader()
	rest := c.others(leading)
	diverged := rest[0]
	cut := rest[1]
	diverged.mayLeave()
	held := len(c.backupsOnTheBoard(1))

	c.partition(cut, true)
	c.appliedAlone(diverged, aloneWorkload)
	if err := write(leading, afterWorkload, testWorkload(t, 1)); err != nil {
		t.Fatalf("a write at the leader: %v", err)
	}
	eventually(t, 15*time.Second, "the alarm of a disagreement no majority settles", func() bool {
		return strings.HasPrefix(leading.node.Status().Divergence, "no majority")
	})

	// Turns of the duties loop several backup intervals over: the state has
	// moved, and no majority of the voters vouches for it.
	c.afterBoardCycles(int(4 * c.timing.Backup / c.timing.Tick))
	if appended := len(c.board.appendedBackups()); appended != held {
		t.Fatalf("a cluster whose voters hold no one state appended %d backups, and held %d before", appended, held)
	}

	c.partition(cut, false)
	c.stoppedAsDiverged(diverged)
	c.backupsOnTheBoard(held + 1)
}
