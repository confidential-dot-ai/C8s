package cdsha

import (
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// Heartbeat failures from the replication stream of a member's earlier
// membership (last contact before it was added again) do not count; a
// member is dead only after dead_after from its last successful contact.
func TestNoteFailureIgnoresStaleStreams(t *testing.T) {
	n := &Node{failing: map[raft.ServerID]time.Time{}, addedAt: map[raft.ServerID]time.Time{}}
	id := raft.ServerID("n4/1-a")
	t0 := time.Now()
	n.addedAt[id] = t0
	n.noteFailure(id, t0.Add(-10*time.Second), t0.Add(time.Second))
	if _, bad := n.failing[id]; bad {
		t.Fatal("a failure from before the member joined counted")
	}
	// The current stream fails: measured from its last contact.
	n.noteFailure(id, t0.Add(2*time.Second), t0.Add(5*time.Second))
	if got := n.failing[id]; !got.Equal(t0.Add(2 * time.Second)) {
		t.Fatalf("failing since %v, want the last contact", got)
	}
	// A stream that never reached it: from the join, not earlier.
	other := raft.ServerID("n5/1-b")
	n.addedAt[other] = t0
	n.noteFailure(other, time.Time{}, t0.Add(3*time.Second))
	if got := n.failing[other]; !got.Equal(t0.Add(3 * time.Second)) {
		t.Fatalf("never contacted: failing since %v", got)
	}
	unknown := raft.ServerID("n6/1-c")
	n.noteFailure(unknown, t0.Add(-time.Minute), t0)
	if got := n.failing[unknown]; !got.Equal(t0.Add(-time.Minute)) {
		t.Fatalf("member without a join time: %v", got)
	}
}
