package cds

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func writeSeed(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write seed file: %v", err)
	}
	return path
}

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

func TestSeedStore_AddsAllEntries(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	path := writeSeed(t, anySeed(map[string]string{"cds": digestA, "as": digestB}))
	if err := seedStore(&store, path); err != nil {
		t.Fatalf("seedStore: %v", err)
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
func TestSeedStore_IdempotentDoesNotBumpVersion(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	path := writeSeed(t, anySeed(map[string]string{"cds": digestA}))
	if err := seedStore(&store, path); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	_, v1, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	if err := seedStore(&store, path); err != nil {
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
func TestSeedStore_PreservesExistingEntries(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	runtime := pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: digest(t, digestB)}}}
	if err := store.PutWorkload("runtime", runtime); err != nil {
		t.Fatalf("pre-put: %v", err)
	}

	path := writeSeed(t, anySeed(map[string]string{"cds": digestA, "runtime": digestA}))
	if err := seedStore(&store, path); err != nil {
		t.Fatalf("seedStore: %v", err)
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

func TestSeedStore_FailsClosedOnBadDigest(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	// "sha256:bad" fails ParseJSON's digest validation.
	path := writeSeed(t, anySeed(map[string]string{"cds": "sha256:bad"}))
	if err := seedStore(&store, path); err == nil {
		t.Fatal("seedStore accepted a malformed digest; want fail-closed error")
	}
}

func TestSeedStore_FailsClosedOnMissingFile(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := seedStore(&store, filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Fatal("seedStore accepted a missing seed file; want fail-closed error")
	}
}

// Seeding into a closed store must fail closed.
func TestSeedStore_FailsClosedOnStoreError(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	_ = store.Close()

	path := writeSeed(t, anySeed(map[string]string{"cds": digestA}))
	if err := seedStore(&store, path); err == nil {
		t.Fatal("seedStore succeeded on a closed store; want fail-closed error")
	}
}

// A seed layer never enters the store, while --allowlist-seed does: an upload
// replaces the stored document only, decisions still hold the seed layer, and
// a seed entry wins a name both layers hold.
func TestOpenSeedLayerSurvivesUpload(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	launch := writeSeed(t, anySeed(map[string]string{"launch": digestB}))
	layers, err := openSeed(&store, launch, writeSeed(t, anySeed(map[string]string{"cds": digestA})))
	if err != nil {
		t.Fatal(err)
	}
	if stored, _, err := store.LoadAll(); err != nil || len(stored.Workloads) != 1 || stored.Workloads["launch"].Label == "" {
		t.Fatalf("store holds %v, %v; want the launch workloads alone, not the seed layer", stored.Workloads, err)
	}
	upload, err := pkgallowlist.ParseJSON([]byte(anySeed(map[string]string{"app": digestB, "cds": digestB})))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAll(upload); err != nil {
		t.Fatal(err)
	}
	decided, version, err := layers.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decided.Workloads["app"]; !ok || len(decided.Workloads) != 2 {
		t.Fatalf("decisions hold %v, want app and cds", decided.Workloads)
	}
	if got := decided.Workloads["cds"].Containers[0].Digest.String(); got != digestA {
		t.Errorf("cds decides on %s, want the seed's %s", got, digestA)
	}
	if stored, current, err := store.LoadAll(); err != nil || current != version || len(stored.Workloads) != 2 {
		t.Errorf("store holds %v at %s, want the upload at the layered version %s (%v)", stored.Workloads, current, version, err)
	}
	if _, _, seed, _ := layers.LoadLayers(); seed == nil {
		t.Error("no seed layer")
	}
}

// Without --seed-layer the seed is merged into the store and there is no
// layer.
func TestOpenSeedWithoutLayerSeedsTheStore(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	layers, err := openSeed(&store, writeSeed(t, anySeed(map[string]string{"cds": digestA})), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, seed, _ := layers.LoadLayers(); seed != nil {
		t.Errorf("seed layer %v without --seed-layer", seed.Workloads)
	}
	if stored, _, err := store.LoadAll(); err != nil || len(stored.Workloads) != 1 {
		t.Fatalf("store holds %v, %v; want the seed", stored.Workloads, err)
	}
}

// A seed layer fails closed on a bad seed, as seeding the store does.
func TestOpenSeedLayerFailsClosed(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := openSeed(&store, "", writeSeed(t, `{"schema":"c8s.allowlist/v1","workloads":{"x":{}}`)); err == nil {
		t.Fatal("openSeed accepted a malformed seed")
	}
}
