//go:build !c8s_node

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// writeBlob stores v in layout's blob store and returns its digest.
func writeBlob(t *testing.T, layout string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	hexDigest := hex.EncodeToString(sum[:])
	dir := filepath.Join(layout, "blobs", "sha256")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, hexDigest), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return "sha256:" + hexDigest
}

// writeLayout writes a multi-platform image whose linux/amd64 config sets env
// and returns the image digest.
func writeLayout(t *testing.T, layouts string, env []string) string {
	t.Helper()
	staging := filepath.Join(layouts, "staging")
	config := writeBlob(t, staging, map[string]any{"config": map[string]any{"Entrypoint": []string{"/app/c8s"}, "Cmd": []string{"armtls-mesh"}, "Env": env}})
	manifest := writeBlob(t, staging, map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 1},
		"layers": []any{},
	})
	other := writeBlob(t, staging, map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": writeBlob(t, staging, map[string]any{"config": map[string]any{}})}})
	index := writeBlob(t, staging, map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": other, "size": 1, "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest, "size": 1, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	})
	layout := filepath.Join(layouts, "oci-"+strings.TrimPrefix(index, "sha256:"))
	if err := os.Rename(staging, layout); err != nil {
		t.Fatal(err)
	}
	top, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": index, "size": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "index.json"), top, 0o644); err != nil {
		t.Fatal(err)
	}
	return index
}

// check-images checks the env the preloaded image config sets, which render
// knows only as the chart declares it.
func TestNodeImageCheckImagesReadsImageEnv(t *testing.T) {
	for name, tc := range map[string]struct {
		env     []string
		wantErr bool
	}{
		"declared env":         {env: []string{"PATH=/usr/bin:/bin"}},
		"undeclared variable":  {env: []string{"PATH=/usr/bin:/bin", "LD_LIBRARY_PATH=/opt/lib"}, wantErr: true},
		"other PATH":           {env: []string{"PATH=/opt/bin:/usr/bin:/bin"}, wantErr: true},
		"default PATH instead": {env: nil, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			layouts, out := t.TempDir(), t.TempDir()
			digest := writeLayout(t, layouts, tc.env)
			integration := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-armtls-mesh
spec:
  template:
    spec:
      containers:
        - name: mesh
          image: registry.example.com/c8s@` + digest + `
          env: [{name: NODE_IP, valueFrom: {fieldRef: {fieldPath: status.hostIP}}}]
`
			seed := `{"schema":"c8s.allowlist/v1","workloads":{"core":{"containers":[{"digest":"` + digest + `","command":{"policy":"exact","argv":["/app/c8s","armtls-mesh"]},"args":{"policy":"any"},"mounts":{"policy":"any"},` +
				seedEnv(t, `"PATH":{"exact":"/usr/bin:/bin"},"NODE_IP":{"present":true}`) + `}]}}}`
			for file, body := range map[string]string{"c8s-integration.yaml": integration, "allowlist-seed.json": seed} {
				if err := os.WriteFile(filepath.Join(out, file), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			err := checkNodeImages(out, layouts)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkNodeImages(image env %q) = %v, want error %v", tc.env, err, tc.wantErr)
			}
		})
	}
}

func TestNodeImageCheckImagesRejectsTamperedBlob(t *testing.T) {
	layouts := t.TempDir()
	digest := writeLayout(t, layouts, []string{"PATH=/usr/bin:/bin"})
	layout := filepath.Join(layouts, "oci-"+strings.TrimPrefix(digest, "sha256:"))
	if err := os.WriteFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := layoutImageConfig(layout, digest); err == nil {
		t.Fatal("layoutImageConfig accepted a blob that does not match its digest")
	}
}

// The migration example is what readers pass to derive --env-file after the
// upgrade: each policy must list the variables the runtime sets in every
// container, or the restarted pod stops matching.
func TestDocumentedMigrationEnvListsRuntimeVariables(t *testing.T) {
	doc, err := os.ReadFile("../../docs/secrets.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "#### Migrate env policies")
	if !ok {
		t.Fatal("secrets.md lacks the env migration section")
	}
	example := regexp.MustCompile("(?s)```json\n(.*?)\n```").FindStringSubmatch(section)
	if example == nil {
		t.Fatal("env migration section has no JSON example")
	}
	policies, err := pkgallowlist.ParseEnvPoliciesJSON([]byte(example[1]))
	if err != nil {
		t.Fatal(err)
	}
	for container, policy := range policies {
		for _, name := range runtimeVariables {
			_, matched := policy.Variables[name]
			_, pinned := policy.Values[name]
			if !matched && !pinned {
				t.Errorf("migration example %s policy omits %s", container, name)
			}
		}
	}
}
