package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// writeSyntheticBundle builds a minimal deterministic docker-archive bundle:
// one image, one layer, fixed bytes and zeroed tar metadata.
func writeSyntheticBundle(t *testing.T) string {
	t.Helper()

	var layer bytes.Buffer
	tw := tar.NewWriter(&layer)
	body := []byte("systemfloor fixture layer\n")
	if err := tw.WriteHeader(&tar.Header{Name: "etc/fixture", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layerDigest := sha256.Sum256(layer.Bytes())

	config := []byte(fmt.Sprintf(
		`{"architecture":"amd64","os":"linux","config":{"Entrypoint":["/bin/fixture"]},"rootfs":{"type":"layers","diff_ids":["sha256:%x"]}}`,
		layerDigest))
	configDigest := sha256.Sum256(config)

	manifest, err := json.Marshal([]map[string]any{{
		"Config":   fmt.Sprintf("blobs/sha256/%x", configDigest),
		"RepoTags": []string{"example.com/library/fixture:1.2.3"},
		"Layers":   []string{fmt.Sprintf("blobs/sha256/%x", layerDigest)},
	}})
	if err != nil {
		t.Fatal(err)
	}

	var bundle bytes.Buffer
	tw = tar.NewWriter(&bundle)
	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write("manifest.json", manifest)
	write(fmt.Sprintf("blobs/sha256/%x", configDigest), config)
	write(fmt.Sprintf("blobs/sha256/%x", layerDigest), layer.Bytes())
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "bundle.tar")
	if err := os.WriteFile(path, bundle.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The golden digest is what the vendored containerd (containerd/v2 in go.mod)
// reconstructs importing this exact bundle. It matches a real containerd
// 2.1.4 daemon's `ctr images import` of the rke2 airgap bundles (26/26), so
// the import digest is stable across that range. A library bump that changes
// the reconstruction breaks here before it silently wedges a node boot.
func TestBundleEntries_MatchesDaemonImport(t *testing.T) {
	f, err := os.Open(writeSyntheticBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := importEntries(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %v", entries)
	}
	const want = "sha256:087f0ac20596efe1fa93dad0f2467e5ad1b6f84bb57a3e8d5dd5c196f9708b33"
	if entries[0].digest != want {
		t.Fatalf("import digest = %s, want the daemon-computed %s", entries[0].digest, want)
	}
	if entries[0].ref != "example.com/library/fixture:1.2.3" {
		t.Fatalf("ref = %q", entries[0].ref)
	}
}

func TestManifestEntries_DigestPinnedOnly(t *testing.T) {
	yaml := `
          image: rancher/local-path-provisioner:v0.0.36@sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f
          imagePullPolicy: IfNotPresent
        image: busybox:1.38.0
`
	path := filepath.Join(t.TempDir(), "manifest.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := manifestEntries(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want exactly the digest-pinned ref, got %v", entries)
	}
	if entries[0].digest != "sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f" {
		t.Fatalf("digest = %q", entries[0].digest)
	}
}

func TestRender_DedupesAliasedDigests(t *testing.T) {
	// Two tags on one manifest (or a bundle/manifest overlap) must not emit a
	// second entry for the same digest.
	digestA := "sha256:" + strings.Repeat("a", 64)
	digestB := "sha256:" + strings.Repeat("b", 64)
	out, err := render([]entry{
		{digest: digestA, ref: "example.com/a:1"},
		{digest: digestA, ref: "example.com/a:2"},
		{digest: digestB, ref: "example.com/b:1"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(out, digestA) != 1 || strings.Count(out, digestB) != 1 {
		t.Fatalf("aliased digest produced duplicate entries:\n%s", out)
	}
}

// The rendered block must decode as an allowlist document whose entries admit
// their digest under any argv — the shape the plugin's base allowlist loads.
func TestRender_ParsesAsBaseWorkloads(t *testing.T) {
	digestA := "sha256:" + strings.Repeat("a", 64)
	out, err := render([]entry{{digest: digestA, ref: "example.com/a:1"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Workloads map[string]allowlist.Workload `yaml:"workloads"`
	}
	if err := yaml.Unmarshal([]byte("schema: c8s.allowlist/v1\nworkloads:\n"+out), &doc); err != nil {
		t.Fatalf("rendered block does not decode: %v\n%s", err, out)
	}
	if len(doc.Workloads) != 1 {
		t.Fatalf("want 1 entry, got %v", doc.Workloads)
	}
	for name, w := range doc.Workloads {
		if name != "a-"+strings.Repeat("a", 12) {
			t.Errorf("entry name = %q, want the DigestEntryName form", name)
		}
		if len(w.Containers) != 1 || w.Containers[0].Digest.String() != digestA || !w.Containers[0].IsUnconstrained() {
			t.Errorf("entry = %#v, want %s under unconstrained launch policies", w, digestA)
		}
		if w.Label != "example.com/a:1" {
			t.Errorf("label = %q", w.Label)
		}
	}
}

func TestRender_ExcludesRefs(t *testing.T) {
	// Argv-pinned images must stay out of the system floor.
	out, err := render([]entry{
		{digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ref: "busybox:1.38.0@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ref: "rancher/local-path-provisioner:v0.0.36@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
	}, []string{"busybox"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "busybox") {
		t.Fatalf("excluded ref rendered:\n%s", out)
	}
	if !strings.Contains(out, `"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`) {
		t.Fatalf("non-excluded ref dropped:\n%s", out)
	}
}

func TestSplice_ReplacesBetweenMarkers(t *testing.T) {
	template := strings.Join([]string{
		"head",
		"    " + beginMarker,
		"    stale",
		"    " + endMarker,
		"tail",
	}, "\n")
	got, err := splice(template, "    fresh\n")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{
		"head",
		"    " + beginMarker,
		"    fresh",
		"    " + endMarker,
		"tail",
	}, "\n")
	if got != want {
		t.Fatalf("splice =\n%s\nwant\n%s", got, want)
	}
	if _, err := splice("no markers", "x"); err == nil {
		t.Fatal("missing markers must error")
	}
}
