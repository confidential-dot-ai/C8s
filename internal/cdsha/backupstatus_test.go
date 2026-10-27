package cdsha

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A backup store that fails for any reason, not only a state over a size
// bound, shows in the leader's Status within a bound, next to the
// last backup it did store, and clears once backups resume.
func TestBackupStoreFailureShowsInStatus(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	status := func() Status {
		if l := c.leader(); l != nil {
			return l.node.Status()
		}
		return Status{}
	}
	eventually(t, 5*time.Second, "the last backup in Status", func() bool {
		st := status()
		return st.LastBackup != nil && st.LastBackup.Index > 0 && st.LastBackup.Epoch > 0 && st.BackupError == ""
	})
	stored := *status().LastBackup
	c.backups.mu.Lock()
	c.backups.err = errors.New("test: API server unavailable")
	c.backups.mu.Unlock()
	l := c.leader()
	if err := l.al.PutWorkload("w", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	bound := backupAlarmPeriods*testTiming.Backup + 10*testTiming.Tick
	eventually(t, bound+time.Second, "the failing store in Status.BackupError", func() bool {
		return strings.Contains(status().BackupError, "store: test: API server unavailable")
	})
	t.Logf("failure in Status after %v (bound %v): %q", time.Since(start).Round(time.Millisecond), bound, status().BackupError)
	if since := time.Since(start); since > bound {
		t.Fatalf("failure shown after %v, bound %v", since, bound)
	}
	if lb := status().LastBackup; lb == nil || lb.Index != stored.Index || lb.AgeMS <= 0 {
		t.Fatalf("last backup while failing: %+v, stored %+v", lb, stored)
	}
	c.backups.mu.Lock()
	c.backups.err = nil
	c.backups.mu.Unlock()
	want := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "backups resumed and the error cleared", func() bool {
		st := status()
		return st.BackupError == "" && st.LastBackup != nil && st.LastBackup.Index >= want
	})
}

// A refused backup does not count as stored: once the slot accepts backups
// again (the operator exported and deleted it), the leader stores the state
// it holds without waiting for a write, and the error clears.
func TestRefusedBackupRetriesWithoutWrites(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	// idle waits until the leader's state is stable for several checkpoint
	// periods and returns its applied index.
	idle := func(l *replica) uint64 {
		var last uint64
		eventually(t, 10*time.Second, "an idle cluster", func() bool {
			prev := last
			last = l.node.fsm.AppliedIndex()
			time.Sleep(5 * testTiming.Checkpoint)
			return prev == last && l.node.fsm.AppliedIndex() == last
		})
		return last
	}
	eventually(t, 5*time.Second, "a first backup", func() bool {
		l := c.leader()
		return l != nil && l.node.Status().LastBackup != nil
	})
	l := c.leader()
	idle(l)
	c.backups.mu.Lock()
	c.backups.err = fmt.Errorf("test: the slot holds another history: %w", ErrBackupNotNewer)
	c.backups.mu.Unlock()
	if err := l.al.PutWorkload("w", mkWorkload(t, 0)); err != nil {
		t.Fatal(err)
	}
	want := l.node.fsm.AppliedIndex()
	eventually(t, 5*time.Second, "the refusal in Status.BackupError", func() bool {
		return strings.Contains(l.node.Status().BackupError, "backup refused")
	})
	settled := idle(l)
	c.backups.mu.Lock()
	c.backups.err, c.backups.last = nil, nil
	c.backups.mu.Unlock()
	eventually(t, backupAlarmPeriods*testTiming.Backup+10*testTiming.Tick+time.Second, "a backup into the emptied slot with no write", func() bool {
		b, ok := c.backups.get()
		st := l.node.Status()
		return ok && b.Meta.Index >= want && st.BackupError == "" && st.LastBackup != nil && st.LastBackup.Index >= want
	})
	if got := l.node.fsm.AppliedIndex(); got != settled || !l.node.leading() {
		t.Fatalf("the state moved (applied %d -> %d) or leadership changed: the test no longer shows a retry without writes", settled, got)
	}
}
