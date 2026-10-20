package allowlist_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func anyEntry(t *testing.T, label, digest string) pkgallowlist.Workload {
	t.Helper()
	d, err := types.ParseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	return pkgallowlist.Workload{Label: label, Containers: []pkgallowlist.Container{{
		Digest:  d,
		Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
		Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
	}}}
}

func doc(workloads map[string]pkgallowlist.Workload) *pkgallowlist.Allowlist {
	return &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema, Workloads: workloads}
}

const (
	layerDigestA = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	layerDigestB = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// The seed's entry wins a name both layers hold, a nil seed is the stored
// document, and every other entry of either layer decides.
func TestCombine(t *testing.T) {
	stored := doc(map[string]pkgallowlist.Workload{
		"app": anyEntry(t, "app", layerDigestA),
		"cds": anyEntry(t, "operator-cds", layerDigestA),
	})
	seed := doc(map[string]pkgallowlist.Workload{"cds": anyEntry(t, "seed-cds", layerDigestB)})

	if got := allowlist.Combine(stored, nil); got != stored {
		t.Errorf("Combine(stored, nil) is not stored")
	}
	got := allowlist.Combine(stored, seed)
	if len(got.Workloads) != 2 || got.Workloads["app"].Label != "app" || got.Workloads["cds"].Label != "seed-cds" {
		t.Errorf("Combine = %v, want app from the store and cds from the seed", got.Workloads)
	}
}

// The seed layer is never written to the store: an upload leaves it, the
// layered version moves when either layer changes, and its bytes are served
// under their digest.
func TestLayeredSeedSurvivesReplaceAll(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	layers := allowlist.NewLayered(&store)
	seed := doc(map[string]pkgallowlist.Workload{"cds": anyEntry(t, "cds", layerDigestB)})
	v0, err := layers.Version()
	if err != nil {
		t.Fatal(err)
	}
	if err := layers.SetSeed(seed); err != nil {
		t.Fatal(err)
	}
	v1, err := layers.Version()
	if err != nil {
		t.Fatal(err)
	}
	if v1 == v0 {
		t.Errorf("version %s unchanged by SetSeed", v1)
	}
	if err := store.ReplaceAll(doc(map[string]pkgallowlist.Workload{"app": anyEntry(t, "app", layerDigestA)})); err != nil {
		t.Fatal(err)
	}
	all, version, err := layers.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := all.Workloads["cds"]; !ok || len(all.Workloads) != 2 {
		t.Errorf("after an upload decisions hold %v, want app and cds", all.Workloads)
	}
	if current, _ := layers.Version(); version != current || version == v1 {
		t.Errorf("LoadAll version %s, Version %s, before the upload %s", version, current, v1)
	}
	if ok, err := store.Contains(mustDigest(t, layerDigestB)); err != nil || ok {
		t.Errorf("store.Contains(seed digest) = %t, %v; want false", ok, err)
	}

	body, err := seed.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	got, ok := layers.SeedObject("sha256:" + hex.EncodeToString(sum[:]))
	if !ok || !bytes.Equal(got, body) {
		t.Errorf("SeedObject = %q, %t; want the seed's canonical bytes", got, ok)
	}
	if _, ok := layers.SeedObject("sha256:" + hex.EncodeToString(make([]byte, 32))); ok {
		t.Error("SeedObject served another digest")
	}
}

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// GET /allowlist names the seed layer in its header, so a client can tell
// that the served document need not carry C8s's own entries.
func TestHandleListNamesSeedLayer(t *testing.T) {
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	layers := allowlist.NewLayered(&store)
	h := allowlist.Handler{Store: &store, Layers: layers}
	get := func() string {
		w := httptest.NewRecorder()
		h.HandleList(w, httptest.NewRequest(http.MethodGet, "/allowlist", nil))
		return w.Header().Get(pkgallowlist.SeedHeader)
	}
	if got := get(); got != "" {
		t.Errorf("seed header %q without a seed layer", got)
	}
	if err := layers.SetSeed(doc(map[string]pkgallowlist.Workload{"cds": anyEntry(t, "cds", layerDigestB)})); err != nil {
		t.Fatal(err)
	}
	if got, want := get(), layers.SeedDigest(); got != want || want == "" {
		t.Errorf("seed header %q, want %q", got, want)
	}
}
