package cdsha

import (
	"slices"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// The allowlist history is bounded through the log, so every replica of the
// cluster keeps the same documents: a history each replica bounded on its own
// judgement would leave them serving different ones.
func TestTheAllowlistHistoryIsBoundedThroughTheLog(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	taking := c.replicas[0]
	for digest := range historyDocuments + 4 {
		c.writeAllowlist(taking, digest)
	}

	for _, r := range c.replicas {
		member := string(r.node.member)
		eventually(t, 30*time.Second, "the history of replica "+member+" inside its bound", func() bool {
			return len(historyOf(t, r)) == historyDocuments
		})
	}
	kept := historyOf(t, taking)
	for _, r := range c.replicas {
		if held := historyOf(t, r); !slices.Equal(held, kept) {
			t.Fatalf("replica %s kept %d documents of the leader's %d, and not the same ones", r.node.member, len(held), len(kept))
		}
	}
}

// writeAllowlist waits for the cluster to take the document, retrying the
// refusal of a cluster electing another leader meanwhile.
func (c *liveCluster) writeAllowlist(r *liveReplica, digest int) {
	c.t.Helper()
	document := testDocument(c.t, digest)
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := r.node.Allowlist().ReplaceAll(document, allowlist.OperatorWrite{})
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("the cluster did not take allowlist document %d: %v", digest, err)
		}
		time.Sleep(testTiming.Tick)
	}
}

// testDocument tells one written allowlist document from the next by digest.
func testDocument(t *testing.T, digest int) *pkgallowlist.Allowlist {
	t.Helper()
	return &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"workload": testWorkload(t, digest)},
	}
}

// historyOf is the allowlist documents a replica holds, oldest first.
func historyOf(t *testing.T, r *liveReplica) []string {
	t.Helper()
	history, err := r.node.Allowlist().History()
	if err != nil {
		t.Fatalf("read the history of replica %s: %v", r.node.member, err)
	}
	digests := make([]string, 0, len(history))
	for _, entry := range history {
		digests = append(digests, entry.Digest)
	}
	return digests
}
