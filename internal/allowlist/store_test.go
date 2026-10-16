package allowlist

import (
	"errors"
	"path/filepath"
	"strconv"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const digestA = "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
const digestB = "sha256:b1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
const digestC = "sha256:c1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

// oneContainerWorkload builds a minimally-specified entry (policies default to
// deny) with one main container at digest.
func oneContainerWorkload(digest types.Digest) pkgallowlist.Workload {
	return pkgallowlist.Workload{
		Containers: []pkgallowlist.Container{{Digest: digest}},
	}
}

func mustParseDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

func TestReplaceAllBumpsVersionByOne(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatalf("put: %v", err)
	}
	_, beforeVersion, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if err := store.ReplaceAll(&pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"b": oneContainerWorkload(mustParseDigest(t, digestB))},
	}); err != nil {
		t.Fatalf("replace: %v", err)
	}

	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := doc.Workloads["b"]; !ok || len(doc.Workloads) != 1 {
		t.Fatalf("workloads after replace = %#v", doc.Workloads)
	}
	// Replace must *increment* the version, not clear or reset it: the version
	// lives in its own table, so the DELETEs leave it untouched and
	// bumpVersionTx increments it. Assert monotonic +1 (a reset-to-default bug
	// would still satisfy version != beforeVersion, so check the value).
	before, err := strconv.Atoi(beforeVersion)
	if err != nil {
		t.Fatalf("beforeVersion %q not numeric: %v", beforeVersion, err)
	}
	after, err := strconv.Atoi(version)
	if err != nil {
		t.Fatalf("version %q not numeric: %v", version, err)
	}
	if after != before+1 {
		t.Fatalf("expected version %d after replace, got %d (before=%d)", before+1, after, before)
	}
}

func TestReplaceAllEmptyClears(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := store.ReplaceAll(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}); err != nil {
		t.Fatalf("replace empty: %v", err)
	}
	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(doc.Workloads) != 0 {
		t.Fatalf("expected empty allowlist after replace with empty document, got %d", len(doc.Workloads))
	}
}

// A fresh store must start at version "1": CDS clients cache on the derived
// ETag (W/"1"), so the initial value is part of the API contract, not an
// implementation detail.
func TestInitialVersionIsOne(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if version != "1" {
		t.Fatalf("version: got %q, want %q", version, "1")
	}
	if len(doc.Workloads) != 0 {
		t.Fatalf("expected empty workloads, got %d", len(doc.Workloads))
	}
}

func TestVersionMatchesLoadAllWithoutLoadingRows(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	version, err := store.Version()
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if version != "1" {
		t.Fatalf("initial version: got %q, want %q", version, "1")
	}

	// Version is the ETag the worker pull carries, so it must move in lockstep
	// with the counter LoadAll reports after a write.
	if err := store.PutWorkload("a", oneContainerWorkload(mustParseDigest(t, digestA))); err != nil {
		t.Fatalf("put: %v", err)
	}
	_, loadVersion, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	version, err = store.Version()
	if err != nil {
		t.Fatalf("version after put: %v", err)
	}
	if version != loadVersion {
		t.Fatalf("Version() = %q, LoadAll version = %q; the cheap read must match", version, loadVersion)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := store.Version(); err == nil {
		t.Fatal("Version on a closed store should fail, not report a stale counter")
	}
}

func TestPutAndDeleteWorkloadRoundtrip(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)
	if err := store.PutWorkload("web", oneContainerWorkload(dA)); err != nil {
		t.Fatalf("put: %v", err)
	}

	doc, version, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if version != "2" {
		t.Fatalf("version after put: got %q, want 2", version)
	}
	w, ok := doc.Workloads["web"]
	if !ok || len(w.Containers) != 1 || w.Containers[0].Digest != dA {
		t.Fatalf("stored workload = %#v", doc.Workloads)
	}
	// Absent policies must have normalized to deny on the way in.
	if w.Containers[0].Command.Policy != pkgallowlist.PolicyDeny {
		t.Fatalf("entrypoint policy = %q, want deny", w.Containers[0].Command.Policy)
	}

	// The container digest is now admitted via the workload index.
	if ok, err := store.Contains(dA); err != nil || !ok {
		t.Fatalf("Contains(workload digest) = %t, %v; want true, nil", ok, err)
	}

	found, err := store.DeleteWorkload("web")
	if err != nil || !found {
		t.Fatalf("delete: found=%t err=%v", found, err)
	}
	if ok, err := store.Contains(dA); err != nil || ok {
		t.Fatalf("Contains after delete = %t, %v; want false, nil", ok, err)
	}
	if found, err := store.DeleteWorkload("web"); err != nil || found {
		t.Fatalf("re-delete: found=%t err=%v; want false, nil", found, err)
	}
}

func TestPutWorkloadRejectsBadName(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	err = store.PutWorkload("bad/name", oneContainerWorkload(mustParseDigest(t, digestA)))
	if err == nil {
		t.Fatal("PutWorkload accepted a name with a slash")
	}
	if !errors.Is(err, ErrInvalidWorkload) {
		t.Fatalf("error should wrap ErrInvalidWorkload, got %v", err)
	}
}

func TestSeedWorkloadsIsAdditiveAndIdempotent(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	seed := map[string]pkgallowlist.Workload{
		"web": oneContainerWorkload(mustParseDigest(t, digestA)),
		"db":  oneContainerWorkload(mustParseDigest(t, digestB)),
	}
	added, _, err := store.SeedWorkloads(seed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if added != 2 {
		t.Fatalf("added: got %d, want 2", added)
	}
	_, v1, _ := store.LoadAll()
	if v1 != "2" {
		t.Fatalf("version after seed: got %q, want 2 (one bump)", v1)
	}

	// Re-seeding the same set adds nothing and does not bump.
	added, _, err = store.SeedWorkloads(seed)
	if err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	if added != 0 {
		t.Fatalf("re-seed added: got %d, want 0", added)
	}
	_, v2, _ := store.LoadAll()
	if v1 != v2 {
		t.Fatalf("version bumped on no-op re-seed: %q -> %q", v1, v2)
	}

	// An entry an operator already wrote under a seeded name is left alone.
	edited := map[string]pkgallowlist.Workload{"web": oneContainerWorkload(mustParseDigest(t, digestC))}
	if added, _, err := store.SeedWorkloads(edited); err != nil || added != 0 {
		t.Fatalf("seed over an existing name: added=%d err=%v; want 0, nil", added, err)
	}
	doc, _, _ := store.LoadAll()
	if got := doc.Workloads["web"].Containers[0].Digest.String(); got != digestA {
		t.Fatalf("seed overwrote an existing entry: digest = %s, want %s", got, digestA)
	}
}

// An upgrade from a release that named a component entry <image>-<12hex> and
// left its args and mounts open, or one that pinned them but left env open,
// retires that entry when the seed generates a pinned shape for the image;
// exact stale shapes and other entries stay.
func TestSeedWorkloadsRetiresReplacedOpenComponentEntries(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	digest := mustParseDigest(t, digestA)
	hex := digest.Hex()[:12]
	matched := pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyMatch, Variables: map[string]pkgallowlist.EnvMatcher{}}
	component := func(args, mounts string, env pkgallowlist.EnvPolicy) pkgallowlist.Workload {
		return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{
			Digest:  digest,
			Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/c8s", "cds"}},
			Args:    pkgallowlist.ArgvPolicy{Policy: args},
			Mounts:  pkgallowlist.MountPolicy{Policy: mounts},
			Env:     env,
		}}}
	}
	open := pkgallowlist.EnvPolicy{Policy: pkgallowlist.PolicyAny}
	stored := map[string]pkgallowlist.Workload{
		"cds-" + hex:               component(pkgallowlist.PolicyAny, pkgallowlist.PolicyAny, open),
		"cds-" + hex + "-0000000a": component(pkgallowlist.PolicyExact, pkgallowlist.PolicyAny, matched),
		"cds-" + hex + "-0000000b": component(pkgallowlist.PolicyExact, pkgallowlist.PolicyExact, matched),
		"cds-" + hex + "-0000000d": component(pkgallowlist.PolicyExact, pkgallowlist.PolicyExact, open),
		"cds-" + hex + "-dead":     component(pkgallowlist.PolicyAny, pkgallowlist.PolicyAny, open),
		"mine":                     component(pkgallowlist.PolicyAny, pkgallowlist.PolicyAny, open),
		"other-" + hex:             pkgallowlist.DigestEntry(digest, "other"),
	}
	if _, _, err := store.SeedWorkloads(stored); err != nil {
		t.Fatalf("seed previous release: %v", err)
	}
	_, before, _ := store.LoadAll()

	seed := map[string]pkgallowlist.Workload{"cds-" + hex + "-0000000c": component(pkgallowlist.PolicyExact, pkgallowlist.PolicyExact, matched)}
	added, retired, err := store.SeedWorkloads(seed)
	if err != nil || added != 1 || retired != 3 {
		t.Fatalf("seed: added=%d retired=%d err=%v; want 1, 3, nil", added, retired, err)
	}
	doc, after, _ := store.LoadAll()
	for _, name := range []string{"cds-" + hex, "cds-" + hex + "-0000000a", "cds-" + hex + "-0000000d"} {
		if _, ok := doc.Workloads[name]; ok {
			t.Errorf("open component entry %q survived the seed", name)
		}
	}
	for _, name := range []string{"cds-" + hex + "-0000000b", "cds-" + hex + "-0000000c", "cds-" + hex + "-dead", "mine", "other-" + hex} {
		if _, ok := doc.Workloads[name]; !ok {
			t.Errorf("entry %q retired, want it kept", name)
		}
	}
	if before == after {
		t.Errorf("version %q not bumped by a seed that changed the set", after)
	}
	if ok, err := store.Contains(digest); err != nil || !ok {
		t.Errorf("digest index lost %s: %v, %v", digest, ok, err)
	}
	if _, _, err := store.SeedWorkloads(seed); err != nil {
		t.Fatal(err)
	}
	if _, again, _ := store.LoadAll(); again != after {
		t.Errorf("version bumped on a no-op re-seed: %q -> %q", after, again)
	}
}

func TestReplaceAllSwapsWorkloads(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	if err := store.PutWorkload("old-wl", oneContainerWorkload(mustParseDigest(t, digestB))); err != nil {
		t.Fatalf("put: %v", err)
	}

	replacement := &pkgallowlist.Allowlist{
		Schema: pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{
			"new-wl": oneContainerWorkload(mustParseDigest(t, digestA)),
		},
	}
	if err := store.ReplaceAll(replacement); err != nil {
		t.Fatalf("replace all: %v", err)
	}

	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if _, ok := doc.Workloads["old-wl"]; ok {
		t.Fatal("pre-replace workload survived ReplaceAll")
	}
	if _, ok := doc.Workloads["new-wl"]; !ok {
		t.Fatalf("replacement workload missing = %#v", doc.Workloads)
	}
	// The old workload's container digest is no longer admitted.
	if ok, _ := store.Contains(mustParseDigest(t, digestB)); ok {
		t.Fatal("old workload digest still admitted after ReplaceAll")
	}
}

// ReplaceAll must store and index every workload in the document, not just the
// first one the map iteration happens to visit.
func TestReplaceAllIndexesEveryWorkload(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dA := mustParseDigest(t, digestA)
	dB := mustParseDigest(t, digestB)
	replacement := &pkgallowlist.Allowlist{
		Schema: pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{
			"web": oneContainerWorkload(dA),
			"db":  oneContainerWorkload(dB),
		},
	}
	if err := store.ReplaceAll(replacement); err != nil {
		t.Fatalf("replace all: %v", err)
	}

	doc, _, err := store.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, name := range []string{"web", "db"} {
		if _, ok := doc.Workloads[name]; !ok {
			t.Fatalf("workload %q missing after ReplaceAll: %#v", name, doc.Workloads)
		}
	}
	// Both workloads' container digests must be admitted via the index.
	for _, d := range []types.Digest{dA, dB} {
		if ok, err := store.Contains(d); err != nil || !ok {
			t.Fatalf("Contains(%s) = %t, %v; want true, nil", d, ok, err)
		}
	}
}

// PutWorkload must index every container digest of the entry, init and main.
func TestPutWorkloadIndexesAllContainers(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	dInit := mustParseDigest(t, digestA)
	dMain := mustParseDigest(t, digestB)
	w := pkgallowlist.Workload{
		InitContainers: []pkgallowlist.Container{{Digest: dInit}},
		Containers:     []pkgallowlist.Container{{Digest: dMain}},
	}
	if err := store.PutWorkload("web", w); err != nil {
		t.Fatalf("put: %v", err)
	}

	for _, d := range []types.Digest{dInit, dMain} {
		if ok, err := store.Contains(d); err != nil || !ok {
			t.Fatalf("Contains(%s) = %t, %v; want true, nil", d, ok, err)
		}
	}
}

func TestContains(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	present := mustParseDigest(t, digestA)
	absent := mustParseDigest(t, digestB)
	if err := store.PutWorkload("a", oneContainerWorkload(present)); err != nil {
		t.Fatal(err)
	}

	if ok, err := store.Contains(present); err != nil || !ok {
		t.Fatalf("Contains(present) = %t, %v; want true, nil", ok, err)
	}
	if ok, err := store.Contains(absent); err != nil || ok {
		t.Fatalf("Contains(absent) = %t, %v; want false, nil", ok, err)
	}
}

func TestOpenStoreCreatesAndReopens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")

	store, err := OpenStore(path)
	if err != nil {
		t.Fatalf("open new store: %v", err)
	}
	dA := mustParseDigest(t, digestA)
	if err := store.PutWorkload("nginx", oneContainerWorkload(dA)); err != nil {
		t.Fatalf("put: %v", err)
	}
	dB := mustParseDigest(t, digestB)
	if err := store.PutWorkload("web", oneContainerWorkload(dB)); err != nil {
		t.Fatalf("put workload: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopening the same path must find the existing schema and data.
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()

	doc, version, err := reopened.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if version != "3" {
		t.Fatalf("version: got %q, want %q", version, "3")
	}
	if _, ok := doc.Workloads["nginx"]; !ok {
		t.Fatalf("entry missing after reopen: %#v", doc.Workloads)
	}
	if ok, err := reopened.Contains(dB); err != nil || !ok {
		t.Fatalf("Contains(workload digest) after reopen = %t, %v; want true, nil", ok, err)
	}
}

// Generation is the snapshot-cache invalidation signal: it moves on every
// committed mutation and never on a read.
func TestGenerationMovesOnEveryMutation(t *testing.T) {
	store, err := OpenInMemory()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer store.Close()

	gen := store.Generation()
	step := func(name string, mutate func() error) {
		t.Helper()
		if err := mutate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		next := store.Generation()
		if next <= gen {
			t.Fatalf("%s left the generation at %d", name, next)
		}
		gen = next
	}

	step("PutWorkload", func() error {
		return store.PutWorkload("w", oneContainerWorkload(mustParseDigest(t, digestB)))
	})
	step("DeleteWorkload", func() error { _, err := store.DeleteWorkload("w"); return err })
	step("ReplaceAll", func() error {
		return store.ReplaceAll(&pkgallowlist.Allowlist{Schema: pkgallowlist.Schema})
	})
	step("SeedWorkloads", func() error {
		_, _, err := store.SeedWorkloads(map[string]pkgallowlist.Workload{"s": oneContainerWorkload(mustParseDigest(t, digestC))})
		return err
	})
	// Reads never move it.
	steady := store.Generation()
	if _, _, err := store.LoadAll(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Contains(mustParseDigest(t, digestC)); err != nil {
		t.Fatal(err)
	}
	if store.Generation() != steady {
		t.Fatal("a read moved the generation")
	}
}

func TestEnvironmentValuesPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	al, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"w":{"containers":[{"digest":"` + digestA + `","env":{"policy":"exact","values":{"MODE":"production"}}}]}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ReplaceAll(al); err != nil {
		t.Fatal(err)
	}
	store.Close()
	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, _, err := store.LoadAll()
	if err != nil || got.Schema != pkgallowlist.Schema || got.Workloads["w"].Containers[0].Env.Values["MODE"] != "production" {
		t.Fatalf("schema lost: %v %v", got, err)
	}
	if err := store.PutWorkload("w", al.Workloads["w"]); err != nil {
		t.Fatal(err)
	}

}
