package cdsha

import (
	"fmt"
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func historyWorkload(t *testing.T, i int) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest(fmt.Sprintf("sha256:%064x", i+1))
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: d}}}
}

// The leader bounds the allowlist history through the log, so every replica
// keeps the same newest entries; a joiner takes the pruned history.
func TestLeaderPrunesTheHistoryEverywhere(t *testing.T) {
	saved := pruneSlack
	pruneSlack = 2
	t.Cleanup(func() { pruneSlack = saved })
	c := newCluster(t, 3)
	c.historyVersions = 5
	c.genesis("n0", "n1", "n2")
	eventually(t, 10*time.Second, "format 2", func() bool { return c.leader() != nil && c.leader().node.Core().format() >= 2 })
	for i := range 12 {
		if err := c.leader().al.PutWorkload(fmt.Sprintf("w%d", i), historyWorkload(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range c.live() {
		eventually(t, 10*time.Second, "pruned on "+r.name, func() bool { n, _ := r.al.HistoryLen(); return n <= 5+2 && n >= 5 })
	}
	want, _ := c.leader().al.History()
	for _, r := range c.live() {
		eventually(t, 5*time.Second, "same history on "+r.name, func() bool {
			got, _ := r.al.History()
			return fmt.Sprint(got) == fmt.Sprint(want)
		})
	}
}

// At format 1 (a group still running a release without the prune command)
// the leader does not prune.
func TestNoPruneBeforeEveryMemberReadsIt(t *testing.T) {
	saved := pruneSlack
	pruneSlack = 2
	t.Cleanup(func() { pruneSlack = saved })
	c := newCluster(t, 3)
	c.historyVersions = 3
	c.reads["n2"] = 1
	c.genesis("n0", "n1", "n2")
	for i := range 10 {
		if err := c.leader().al.PutWorkload(fmt.Sprintf("w%d", i), historyWorkload(t, i)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(5 * testTiming.Backup)
	if n, _ := c.leader().al.HistoryLen(); n < 10 {
		t.Fatalf("pruned to %d at format 1", n)
	}
}
