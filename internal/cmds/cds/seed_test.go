package cds

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func digest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

const (
	digestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	digestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// anySeed renders a seed document with one any-argv entry per (name, digest).
func anySeed(entries map[string]string) string {
	body := `{"schema":"c8s.allowlist/v1","workloads":{`
	first := true
	for name, d := range entries {
		if !first {
			body += ","
		}
		first = false
		body += `"` + name + `":{"label":"ghcr.io/x/` + name + `:v1","containers":[{"digest":"` + d + `","command":{"policy":"any"},"args":{"policy":"any"}}]}`
	}
	return body + `}}`
}

// parseSeed is the workload document a measured configuration carries.
func parseSeed(t *testing.T, entries map[string]string) *pkgallowlist.Allowlist {
	t.Helper()
	seed, err := pkgallowlist.ParseJSON([]byte(anySeed(entries)))
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	return seed
}

func TestSeedWorkloads_AddsAllEntries(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := seedWorkloads(&store, parseSeed(t, map[string]string{"cds": digestA, "as": digestB})); err != nil {
		t.Fatalf("seedWorkloads: %v", err)
	}

	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(doc.Workloads) != 2 {
		t.Fatalf("seeded %d entries, want 2: %v", len(doc.Workloads), doc.Workloads)
	}
	if got := doc.Workloads["cds"].Label; got != "ghcr.io/x/cds:v1" {
		t.Errorf("cds label = %q, want ghcr.io/x/cds:v1", got)
	}
	// Each seeded container digest is admitted via the workload index.
	for _, d := range []string{digestA, digestB} {
		if ok, err := store.Contains(digest(t, d)); err != nil || !ok {
			t.Fatalf("Contains(%s) = %t, %v; want true, nil", d, ok, err)
		}
	}
}

// Re-seeding the same set on every CDS restart must not bump the store version;
// the version is the worker pull ETag, so churn would force every worker to
// re-pull on every CDS restart.
func TestSeedWorkloads_IdempotentDoesNotBumpVersion(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	seed := parseSeed(t, map[string]string{"cds": digestA})
	if err := seedWorkloads(&store, seed); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	_, v1, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	if err := seedWorkloads(&store, seed); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	_, v2, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if v1 != v2 {
		t.Fatalf("version bumped on re-seed: %q -> %q (would force worker re-pull)", v1, v2)
	}
}

// Seeding is additive: an entry an operator wrote at runtime must survive a
// restart's re-seed, and a seeded name it already holds is not overwritten.
func TestSeedWorkloads_PreservesExistingEntries(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	runtime := pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: digest(t, digestB)}}}
	if err := store.PutWorkload("runtime", runtime); err != nil {
		t.Fatalf("pre-put: %v", err)
	}

	if err := seedWorkloads(&store, parseSeed(t, map[string]string{"cds": digestA, "runtime": digestA})); err != nil {
		t.Fatalf("seedWorkloads: %v", err)
	}

	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if _, ok := doc.Workloads["cds"]; !ok {
		t.Errorf("seed entry missing: %v", doc.Workloads)
	}
	if got := doc.Workloads["runtime"].Containers[0].Digest.String(); got != digestB {
		t.Errorf("runtime-added entry overwritten by seed: digest = %s, want %s", got, digestB)
	}
}

// Seeding into a closed store must fail closed.
func TestSeedWorkloads_FailsClosedOnStoreError(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	_ = store.Close()

	if err := seedWorkloads(&store, parseSeed(t, map[string]string{"cds": digestA})); err == nil {
		t.Fatal("seedWorkloads succeeded on a closed store; want fail-closed error")
	}
}
