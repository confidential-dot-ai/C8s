package cds

import (
	"bytes"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// layeredStore stores stored's document and sets seed's as the seed layer.
func layeredStore(t *testing.T, stored, seed fakeStore) (*allowlist.Layered, *pkgallowlist.Allowlist, *pkgallowlist.Allowlist) {
	t.Helper()
	store, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	storedDoc, _, _ := stored.LoadAll()
	if err := store.ReplaceAll(storedDoc); err != nil {
		t.Fatal(err)
	}
	seedDoc, _, _ := seed.LoadAll()
	layers, err := allowlist.NewLayered(&store, seedDoc)
	if err != nil {
		t.Fatal(err)
	}
	return layers, storedDoc, seedDoc
}

func canonicalDigest(t *testing.T, al *pkgallowlist.Allowlist) []byte {
	t.Helper()
	d, err := al.CanonicalDigest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// With a seed layer the stored document carries application entries only. A
// pod matching an application entry, beside an injected helper the seed admits, is stamped with the served document's digest; a pod matching a
// seed entry is stamped with the seed's.
func TestAttest_SeedLayerStampsTheMatchedLayer(t *testing.T) {
	layers, storedDoc, seedDoc := layeredStore(t,
		fakeStore{workloads: map[string]pkgallowlist.Workload{"api": namedEntry(t, wlDigestA)}},
		fakeStore{
			anyArgv:   map[string]bool{wlDigestC: true},
			workloads: map[string]pkgallowlist.Workload{"mesh": namedEntry(t, wlDigestB)},
		})

	app := issueWithInventory(t, layers, []string{wlDigestA, wlDigestC}, []workloadclaims.SandboxContainer{
		{Digest: wlDigestA, Mounts: []pkgallowlist.ObservedMount{}},
		{Digest: wlDigestC, Argv: []string{"/c8s", "get-cert"}, Role: "credentials"},
	}, nil)
	if app == nil || app.Name != "api" {
		t.Fatalf("application pod matched %+v, want api", app)
	}
	if !bytes.Equal(app.AllowlistDigest, canonicalDigest(t, storedDoc)) {
		t.Errorf("application stamp digest %x, want the served document's", app.AllowlistDigest)
	}

	mesh := issueWithInventory(t, layers, []string{wlDigestB}, containersView(wlDigestB), nil)
	if mesh == nil || mesh.Name != "mesh" {
		t.Fatalf("seed pod matched %+v, want mesh", mesh)
	}
	if !bytes.Equal(mesh.AllowlistDigest, canonicalDigest(t, seedDoc)) {
		t.Errorf("seed stamp digest %x, want the seed's", mesh.AllowlistDigest)
	}
	if mesh.AllowlistVersion != app.AllowlistVersion {
		t.Errorf("seed stamp version %s, want the store version %s", mesh.AllowlistVersion, app.AllowlistVersion)
	}
}
