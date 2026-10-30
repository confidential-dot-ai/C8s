//go:build !c8s_node

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// writeLayoutBlob stores v as a blob of the layout at dir and returns its digest.
func writeLayoutBlob(t *testing.T, dir string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	path := filepath.Join(dir, "blobs", "sha256", hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeNodeImageLayout writes an OCI layout, as airgap-images.sh stores it
// under layouts, of an index holding one image with the given architecture
// and Env, and returns the index digest.
func writeNodeImageLayout(t *testing.T, layouts, arch string, env []string) string {
	t.Helper()
	staging := filepath.Join(layouts, "staging")
	config := map[string]any{"os": "linux", "architecture": arch, "config": map[string]any{"Env": env}}
	manifest := map[string]any{"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageManifest, "config": map[string]any{"mediaType": ocispec.MediaTypeImageConfig, "digest": writeLayoutBlob(t, staging, config), "size": 1}}
	index := map[string]any{"schemaVersion": 2, "mediaType": ocispec.MediaTypeImageIndex, "manifests": []any{map[string]any{"mediaType": ocispec.MediaTypeImageManifest, "digest": writeLayoutBlob(t, staging, manifest), "size": 1}}}
	digest := writeLayoutBlob(t, staging, index)
	dir := filepath.Join(layouts, "oci-"+strings.TrimPrefix(digest, "sha256:"))
	if err := os.Rename(staging, dir); err != nil {
		t.Fatal(err)
	}
	layout, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": ocispec.MediaTypeImageIndex, "digest": digest, "size": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), layout, 0o644); err != nil {
		t.Fatal(err)
	}
	return digest
}

// writeNodeImageRender writes what node-image render leaves for one component
// running digest with service links off and env MODE=strict, under a seed
// whose env matches the runtime's variables, MODE and pinned.
func writeNodeImageRender(t *testing.T, digest string, pinned map[string]string) string {
	t.Helper()
	variables := map[string]any{"MODE": map[string]any{"exact": "strict"}}
	for _, name := range []string{"HOSTNAME", "KUBERNETES_SERVICE_HOST", "KUBERNETES_PORT", "KUBERNETES_PORT_443_TCP", "KUBERNETES_PORT_443_TCP_ADDR"} {
		variables[name] = map[string]any{"present": true}
	}
	for name, value := range kubeletVariables {
		if value != "" {
			variables[name] = map[string]any{"exact": value}
		}
	}
	for name, value := range pinned {
		variables[name] = map[string]any{"exact": value}
	}
	seed, err := json.Marshal(map[string]any{"schema": "c8s.allowlist/v1", "workloads": map[string]any{"core": map[string]any{"containers": []any{map[string]any{
		"digest":  digest,
		"command": map[string]any{"policy": "exact", "argv": []string{"/app/c8s"}},
		"args":    map[string]any{"policy": "deny"},
		"env":     map[string]any{"policy": "match", "variables": variables},
	}}}}})
	if err != nil {
		t.Fatal(err)
	}
	integration := `apiVersion: apps/v1
kind: Deployment
metadata: {name: c8s-cds, namespace: c8s-system}
spec:
  template:
    spec:
      enableServiceLinks: false
      containers:
        - name: cds
          image: registry.example.com/cds@` + digest + `
          command: ["/app/c8s"]
          env: [{name: MODE, value: strict}]
`
	out := t.TempDir()
	for name, data := range map[string][]byte{"c8s-integration.yaml": []byte(integration), "allowlist-seed.json": seed, "local-names.txt": nil} {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestCheckNodeImages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		arch   string
		env    []string
		pinned map[string]string
		ok     bool
	}{
		{"image sets no variables", "amd64", nil, map[string]string{"PATH": containerdDefaultPath}, true},
		{"image variables pinned", "amd64", []string{"PATH=/bin", "LANG=C"}, map[string]string{"PATH": "/bin", "LANG": "C"}, true},
		{"image value differs from the pin", "amd64", []string{"PATH=/usr/bin"}, map[string]string{"PATH": "/bin"}, false},
		{"image variable not listed", "amd64", []string{"PATH=/bin", "LANG=C"}, map[string]string{"PATH": "/bin"}, false},
		{"pin the image does not set", "amd64", []string{"PATH=/bin"}, map[string]string{"PATH": "/bin", "LANG": "C"}, false},
		{"manifest overrides an image variable", "amd64", []string{"PATH=/bin", "MODE=lax"}, map[string]string{"PATH": "/bin"}, true},
		{"no image for the node's platform", "arm64", nil, map[string]string{"PATH": containerdDefaultPath}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layouts := t.TempDir()
			digest := writeNodeImageLayout(t, layouts, tc.arch, tc.env)
			err := checkNodeImages(writeNodeImageRender(t, digest, tc.pinned), layouts)
			if (err == nil) != tc.ok {
				t.Fatalf("checkNodeImages() error = %v, want ok %v", err, tc.ok)
			}
		})
	}
}

func TestCheckNodeImagesRefusesTamperedBlob(t *testing.T) {
	layouts := t.TempDir()
	digest := writeNodeImageLayout(t, layouts, "amd64", nil)
	out := writeNodeImageRender(t, digest, map[string]string{"PATH": containerdDefaultPath})
	blobs := filepath.Join(layouts, "oci-"+strings.TrimPrefix(digest, "sha256:"), "blobs", "sha256")
	entries, err := os.ReadDir(blobs)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		path := filepath.Join(blobs, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, ' '), 0o644); err != nil {
			t.Fatal(err)
		}
		if checkNodeImages(out, layouts) == nil {
			t.Fatalf("accepted a layout whose blob %s differs from its digest", e.Name())
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The render names the images the operator injects node-locally, in the
// manifests and in the seed that pins the operator's exact argv; check-images
// maps both back through local-names.txt, and without it refuses an image no
// layout holds.
func TestCheckNodeImagesResolvesLocalNames(t *testing.T) {
	layouts := t.TempDir()
	digest := writeNodeImageLayout(t, layouts, "amd64", nil)
	out := writeNodeImageRender(t, digest, map[string]string{"PATH": containerdDefaultPath})
	image, local := "registry.example.com/cds@"+digest, "registry.example.com/cds:"+nodeLocalTag
	injected := "--mesh-image=" + local
	rawSeed, err := os.ReadFile(filepath.Join(out, "allowlist-seed.json"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := pkgallowlist.ParseJSON(rawSeed)
	if err != nil {
		t.Fatal(err)
	}
	core := seed.Workloads["core"]
	core.Containers[0].Args = pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{injected}}
	seed.Workloads["core"] = core
	if rawSeed, err = seed.Canonical(); err != nil {
		t.Fatal(err)
	}
	rendered, err := os.ReadFile(filepath.Join(out, "c8s-integration.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	command := []byte(`          command: ["/app/c8s"]` + "\n")
	withArgs := bytes.Replace(rendered, command, append(command, []byte(`          args: ["`+injected+`"]`+"\n")...), 1)
	if bytes.Equal(withArgs, rendered) {
		t.Fatalf("fixture render shape changed: %s", rendered)
	}
	for name, data := range map[string][]byte{
		"allowlist-seed.json":  rawSeed,
		"c8s-integration.yaml": withArgs,
		"local-names.txt":      []byte(image + " " + local + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkNodeImages(out, layouts); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "local-names.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if checkNodeImages(out, layouts) == nil {
		t.Fatal("accepted an injected image named node-locally with no map back to its digest")
	}
}

func TestResolveLocalNames(t *testing.T) {
	ref, local := "registry.example.com/cds@sha256:"+strings.Repeat("c", 64), "registry.example.com/cds:"+nodeLocalTag
	names := []byte(ref + " " + local + "\n")
	doc := []byte("      - --mesh-image=" + local + "\n      - --get-cert-image=" + local + "\n")
	resolved, err := resolveLocalNames(doc, names)
	if err != nil || bytes.Contains(resolved, []byte(local)) {
		t.Fatalf("resolveLocalNames() = %s, %v", resolved, err)
	}
	if unchanged, err := resolveLocalNames(doc, nil); err != nil || !bytes.Equal(unchanged, doc) {
		t.Fatalf("no names changed the document: %s, %v", unchanged, err)
	}
	if _, err := resolveLocalNames(doc, []byte("one-field\n")); err == nil {
		t.Fatal("accepted a local-names.txt line that is not a reference and a name")
	}
}
