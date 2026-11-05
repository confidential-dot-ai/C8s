package cdsobject

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestBootstrapNoOpRequiresFreshStateAndKeepsNecessaryWrites(t *testing.T) {
	f := newFixture(t)
	a, b := f.node(t), f.node(t)
	f.genesis(t, a)
	digest, err := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	seed := map[string]pkgallowlist.Workload{"web": {Containers: []pkgallowlist.Container{{Digest: digest}}}}
	if added, _, err := a.Allowlist().SeedWorkloads(seed); err != nil || added != 1 {
		t.Fatalf("initial seed: added=%d err=%v", added, err)
	}
	before := a.WALStats()
	if added, retired, err := a.Allowlist().SeedWorkloads(seed); err != nil || added+retired != 0 {
		t.Fatalf("repeat seed: added=%d retired=%d err=%v", added, retired, err)
	}
	if err := a.Allowlist().StartJournal(); err != nil {
		t.Fatal(err)
	}
	if after := a.WALStats(); after.Applied != before.Applied || after.Puts != before.Puts || after.Gets < before.Gets+2 {
		t.Fatalf("bootstrap checks did not use fresh reads without writes: before=%+v after=%+v", before, after)
	}
	// Another replica removes the seed while a's local view still contains it.
	if err := b.ConfirmRead(); err != nil {
		t.Fatal(err)
	}
	if err := b.Allowlist().ReplaceAll(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: map[string]pkgallowlist.Workload{}}, allowlist.OperatorWrite{}); err != nil {
		t.Fatal(err)
	}
	if added, _, err := a.Allowlist().SeedWorkloads(seed); err != nil || added != 1 {
		t.Fatalf("stale state skipped a required seed: added=%d err=%v", added, err)
	}
	f.bucket.outage.Store(true)
	defer f.bucket.outage.Store(false)
	if err := a.Allowlist().StartJournal(); err == nil {
		t.Fatal("bootstrap accepted its local journal without a fresh storage read")
	}
}
