package cdsha

import (
	"errors"
	"testing"
	"time"
)

// StuckOverdue reports a stuck replica after the grace Run allows, without
// Run's help: a caller can end a replica whose Run loop is blocked.
func TestStuckOverdueWithoutRun(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	if l == nil {
		t.Fatal("no leader")
	}
	var f *replica
	for _, r := range c.live() {
		if r != l {
			f = r
			break
		}
	}
	f.cancel() // Run returns; nothing in its loop runs any more
	<-f.done
	if reason := f.node.StuckOverdue(); reason != "" {
		t.Fatalf("not stuck, overdue = %q", reason)
	}
	f.node.fsm.stop(errors.New("test: local store fault"))
	if reason := f.node.StuckOverdue(); reason != "" {
		t.Fatalf("just stuck, overdue = %q before the grace", reason)
	}
	grace := testTiming.DeadAfter + testTiming.Lease
	eventually(t, grace+2*time.Second, "stuck replica reported overdue", func() bool {
		return f.node.StuckOverdue() != ""
	})
}
