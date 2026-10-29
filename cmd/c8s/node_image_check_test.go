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
	for name, data := range map[string][]byte{"c8s-integration.yaml": []byte(integration), "allowlist-seed.json": seed} {
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

func TestResolveLocalNames(t *testing.T) {
	ref := "registry.example.com/cds@sha256:" + strings.Repeat("c", 64)
	in := []byte("    image: registry.example.com/cds:c8s-node\n    image: other@sha256:" + strings.Repeat("d", 64) + "\n")
	out, err := resolveLocalNames(in, []byte(ref+" registry.example.com/cds:c8s-node\n"))
	if err != nil || !bytes.Contains(out, []byte("image: "+ref+"\n")) || bytes.Contains(out, []byte(":c8s-node")) {
		t.Fatalf("%s %v", out, err)
	}
	if _, err := resolveLocalNames(in, []byte("one-field\n")); err == nil {
		t.Fatal("bad line accepted")
	}
	flagged := []byte("      - --mesh-image=registry.example.com/cds:c8s-node\n")
	if out, _ := resolveLocalNames(flagged, []byte(ref+" registry.example.com/cds:c8s-node\n")); !bytes.Contains(out, []byte("--mesh-image="+ref)) {
		t.Fatalf("injected-image flag not resolved: %s", out)
	}
	if same, _ := resolveLocalNames(in, nil); !bytes.Equal(same, in) {
		t.Fatal("no names changed the manifest")
	}
}

// The operator's seed argv names injected images node-locally, as render
// writes it; check-images maps both the render and the seed back through
// local-names.txt (a build failed when only the render was mapped).
func TestCheckNodeImagesWithLocalNames(t *testing.T) {
	layouts := t.TempDir()
	digest := writeNodeImageLayout(t, layouts, "amd64", nil)
	out := writeNodeImageRender(t, digest, map[string]string{"PATH": containerdDefaultPath})
	ref, local := "registry.example.com/cds@"+digest, "registry.example.com/cds:c8s-node"
	seedPath := filepath.Join(out, "allowlist-seed.json")
	raw, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"args":{"policy":"deny"}`), []byte(`"args":{"policy":"exact","argv":["--mesh-image=`+local+`"]}`), 1)
	if !bytes.Contains(raw, []byte(local)) {
		t.Fatalf("fixture seed shape changed: %s", raw)
	}
	integration, _ := os.ReadFile(filepath.Join(out, "c8s-integration.yaml"))
	integration = append(integration, []byte("          args: [\"--mesh-image="+local+"\"]\n")...)
	for name, data := range map[string][]byte{
		"allowlist-seed.json": raw, "c8s-integration.yaml": integration, "local-names.txt": []byte(ref + " " + local + "\n"),
	} {
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkNodeImages(out, layouts); err != nil {
		t.Fatal(err)
	}
}
