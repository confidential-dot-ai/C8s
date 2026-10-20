package cds

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	if _, err := seedStore(&store, path); err != nil {
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
	if _, err := seedStore(&store, path); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	_, v1, err := store.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	if _, err := seedStore(&store, path); err != nil {
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
	if _, err := seedStore(&store, path); err != nil {
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
	if _, err := seedStore(&store, path); err == nil {
		t.Fatal("seedStore accepted a malformed digest; want fail-closed error")
	}
}

func TestSeedStore_FailsClosedOnMissingFile(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if _, err := seedStore(&store, filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
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
	if _, err := seedStore(&store, path); err == nil {
		t.Fatal("seedStore succeeded on a closed store; want fail-closed error")
	}
}

// A followed seed is a layer of its own: a changed seed takes effect without a
// restart and never enters the store.
func TestFollowSeedSetsChangedSeedLayer(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	layers := allowlist.NewLayered(&store)
	path := writeSeed(t, anySeed(map[string]string{"cds": digestA}))
	applied, err := seedLayer(layers, path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tick := make(chan time.Time)
	done := make(chan struct{})
	go func() { followSeed(ctx, layers, path, applied, tick); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	// tick is unbuffered: a send returns only once the previous check is done.
	check := func() { tick <- time.Time{}; tick <- time.Time{} }

	if err := os.WriteFile(path, []byte(anySeed(map[string]string{"cds": digestA, "operator-v2": digestB})), 0o600); err != nil {
		t.Fatal(err)
	}
	check()
	doc, _, err := layers.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Workloads["operator-v2"]; !ok {
		t.Fatalf("changed seed not applied: %v", doc.Workloads)
	}
	if stored, _, err := store.LoadAll(); err != nil || len(stored.Workloads) != 0 {
		t.Fatalf("the seed reached the store: %v, %v", stored.Workloads, err)
	}
}

// An upload replaces the stored document only: the followed seed still
// decides, and GET /allowlist serves exactly what the operator wrote.
func TestFollowedSeedSurvivesUpload(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	layers := allowlist.NewLayered(&store)
	ctx, cancel := context.WithCancel(context.Background())
	done, err := startSeed(ctx, layers, writeSeed(t, anySeed(map[string]string{"cds": digestA})), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); <-done })

	app, err := pkgallowlist.ParseJSON([]byte(anySeed(map[string]string{"app": digestB})))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAll(app); err != nil {
		t.Fatal(err)
	}
	served, _, err := store.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(served.Workloads) != 1 || served.Workloads["app"].Label == "" {
		t.Fatalf("served %v, want the uploaded app entry alone", served.Workloads)
	}
	decided, _, err := layers.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"cds", "app"} {
		if _, ok := decided.Workloads[name]; !ok {
			t.Errorf("decisions lack %q after the upload: %v", name, decided.Workloads)
		}
	}
}

// Without --follow-seed a changed seed is not published: editing the seed's
// ConfigMap is no substitute for an operator token. A following store on the
// same file shows when the change would have been applied.
func TestStartSeedWithoutFollowIgnoresChanges(t *testing.T) {
	orig := seedRecheckInterval
	seedRecheckInterval = time.Millisecond
	t.Cleanup(func() { seedRecheckInterval = orig })
	open := func() *allowlist.Layered {
		store, err := allowlist.OpenInMemory()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		return allowlist.NewLayered(&store)
	}
	fixed, following := open(), open()
	path := writeSeed(t, anySeed(map[string]string{"cds": digestA}))
	ctx, cancel := context.WithCancel(context.Background())
	fixedDone, err := startSeed(ctx, fixed, path, false)
	if err != nil {
		t.Fatal(err)
	}
	followingDone, err := startSeed(ctx, following, path, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		<-fixedDone
		<-followingDone
	})
	_, before, err := fixed.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(anySeed(map[string]string{"cds": digestA, "intruder": digestB})), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		doc, _, err := following.LoadAll()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := doc.Workloads["intruder"]; ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the following store never applied the change")
		}
		time.Sleep(time.Millisecond)
	}
	doc, after, err := fixed.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := doc.Workloads["intruder"]; ok || after != before {
		t.Errorf("without --follow-seed: workloads %v at version %s, want no intruder at version %s", doc.Workloads, after, before)
	}
}

// startSeed's channel closes once a cancelled follower returns, so a caller
// waiting on it may then close the store.
func TestStartSeedDoneClosesOnCancel(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done, err := startSeed(ctx, allowlist.NewLayered(&store), writeSeed(t, anySeed(map[string]string{"cds": digestA})), true)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the follower did not stop after its context was cancelled")
	}
}
