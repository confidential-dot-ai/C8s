package cdsha

import (
	"errors"
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
