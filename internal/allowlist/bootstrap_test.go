package allowlist

import (
	"testing"
	"time"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestBootstrapNoOpPreservesSeedRulesWithoutWriting(t *testing.T) {
	a := oneContainerWorkload(mustParseDigest(t, digestA))
	b := oneContainerWorkload(mustParseDigest(t, digestB))
	open := a
	open.Containers = append([]pkgallowlist.Container(nil), a.Containers...)
	open.Containers[0].Command = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/c8s", "cds"}}
	open.Containers[0].Args = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}
	generated := "cds-" + mustParseDigest(t, digestA).Hex()[:12]
	for _, tc := range []struct {
		name   string
		stored map[string]pkgallowlist.Workload
		seed   map[string]pkgallowlist.Workload
		noOp   bool
	}{
		{"same seed", map[string]pkgallowlist.Workload{"web": a}, map[string]pkgallowlist.Workload{"web": a}, true},
		{"preserve operator entry", map[string]pkgallowlist.Workload{"web": a}, map[string]pkgallowlist.Workload{"web": b}, true},
		{"missing entry", map[string]pkgallowlist.Workload{"web": a}, map[string]pkgallowlist.Workload{"new": b}, false},
		{"replace open generated entry", map[string]pkgallowlist.Workload{generated: open}, map[string]pkgallowlist.Workload{generated: a}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, handle := openInMemoryStore(t)
			if _, _, err := handle.SeedWorkloads(tc.stored); err != nil {
				t.Fatal(err)
			}
			before, _, err := store.ScanDigest()
			if err != nil {
				t.Fatal(err)
			}
			noOp, err := store.BootstrapNoOp(Command{Op: OpSeed, AtMS: time.Now().UnixMilli(), Workloads: tc.seed})
			if err != nil || noOp != tc.noOp {
				t.Fatalf("noOp=%v err=%v, want %v", noOp, err, tc.noOp)
			}
			after, _, err := store.ScanDigest()
			if err != nil || after != before {
				t.Fatalf("bootstrap check mutated state: %v", err)
			}
			added, retired, err := handle.SeedWorkloads(tc.seed)
			if err != nil || (added+retired == 0) != tc.noOp {
				t.Fatalf("seed disagrees with check: added=%d retired=%d err=%v", added, retired, err)
			}
		})
	}
}

func TestBootstrapNoOpRequiresAnIntactCurrentJournal(t *testing.T) {
	for _, tc := range []struct {
		name, mutate string
		noOp, failed bool
	}{
		{"intact", "", true, false},
		{"missing head", "DELETE FROM journal_event", false, false},
		{"missing object", "DELETE FROM journal_object", false, true},
		{"corrupt object", "UPDATE journal_object SET body = CAST('{}' AS BLOB)", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := openJournaledStore(t)
			if tc.mutate != "" {
				if _, err := store.db.Exec(tc.mutate); err != nil {
					t.Fatal(err)
				}
			}
			noOp, err := store.BootstrapNoOp(Command{Op: OpStartJournal, AtMS: time.Now().UnixMilli()})
			if noOp != tc.noOp || (err != nil) != tc.failed {
				t.Fatalf("noOp=%v err=%v", noOp, err)
			}
		})
	}
}
