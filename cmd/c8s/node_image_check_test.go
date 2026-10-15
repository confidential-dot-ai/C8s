//go:build !c8s_node

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode"

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

// writeLayout writes a multi-platform image whose linux/amd64 config sets env,
// under nested further indexes, whose entries omit their platform when
// platformless is set, and returns the image digest.
func writeLayout(t *testing.T, layouts string, env []string, nested int, platformless bool) string {
	t.Helper()
	staging := filepath.Join(layouts, "staging")
	config := writeBlob(t, staging, map[string]any{"os": "linux", "architecture": "amd64", "config": map[string]any{"Entrypoint": []string{"/app/c8s"}, "Cmd": []string{"armtls-mesh"}, "Env": env}})
	manifest := writeBlob(t, staging, map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config, "size": 1},
		"layers": []any{},
	})
	other := writeBlob(t, staging, map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": writeBlob(t, staging, map[string]any{"os": "linux", "architecture": "arm64", "config": map[string]any{}})}})
	index := writeBlob(t, staging, map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": other, "size": 1, "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
			map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest, "size": 1, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
		},
	})
	for range nested {
		entry := map[string]any{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": index, "size": 1}
		if !platformless {
			entry["platform"] = map[string]string{"os": "linux", "architecture": "amd64"}
		}
		index = writeBlob(t, staging, map[string]any{
			"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json",
			"manifests": []any{entry},
		})
	}
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
	path := []string{"PATH=/usr/bin:/bin"}
	for name, tc := range map[string]struct {
		env          []string
		seed         string
		nested       int
		platformless bool
		wantErr      bool
	}{
		"declared env":         {env: path},
		"undeclared variable":  {env: []string{"PATH=/usr/bin:/bin", "LD_LIBRARY_PATH=/opt/lib"}, wantErr: true},
		"other PATH":           {env: []string{"PATH=/opt/bin:/usr/bin:/bin"}, wantErr: true},
		"default PATH instead": {env: nil, wantErr: true},
		"nested index":         {env: path, nested: 2},
		"platformless index":   {env: path, nested: 2, platformless: true},
		// The kubelet sets its variables over the image's.
		"kubelet port over the image's":  {env: append(path, "KUBERNETES_SERVICE_PORT=9999"), seed: `,"KUBERNETES_SERVICE_PORT":{"exact":"443"}`},
		"image port pinned":              {env: append(path, "KUBERNETES_SERVICE_PORT=9999"), seed: `,"KUBERNETES_SERVICE_PORT":{"exact":"9999"}`, wantErr: true},
		"HOSTNAME pinned":                {env: path, seed: `,"HOSTNAME":{"exact":"mesh"}`, wantErr: true},
		"HOSTNAME pinned to the image's": {env: append(path, "HOSTNAME=mesh"), seed: `,"HOSTNAME":{"exact":"mesh"}`},
	} {
		t.Run(name, func(t *testing.T) {
			layouts, out := t.TempDir(), t.TempDir()
			digest := writeLayout(t, layouts, tc.env, tc.nested, tc.platformless)
			integration := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: c8s-armtls-mesh
spec:
  template:
    spec:
      enableServiceLinks: false
      containers:
        - name: mesh
          image: registry.example.com/c8s@` + digest + `
          env: [{name: NODE_IP, valueFrom: {fieldRef: {fieldPath: status.hostIP}}}]
`
			seed := `{"schema":"c8s.allowlist/v1","workloads":{"core":{"containers":[{"digest":"` + digest + `","command":{"policy":"exact","argv":["/app/c8s","armtls-mesh"]},"args":{"policy":"any"},"mounts":{"policy":"any"},` +
				seedEnv(t, `"PATH":{"exact":"/usr/bin:/bin"},"NODE_IP":{"present":true}`+tc.seed) + `}]}}}`
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
	digest := writeLayout(t, layouts, []string{"PATH=/usr/bin:/bin"}, 0, false)
	layout := filepath.Join(layouts, "oci-"+strings.TrimPrefix(digest, "sha256:"))
	if err := os.WriteFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(digest, "sha256:")), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := layoutImageConfig(layout, digest); err == nil {
		t.Fatal("layoutImageConfig accepted a blob that does not match its digest")
	}
}

// writeIndexJSON lists digest in the layout's index.json.
func writeIndexJSON(t *testing.T, layout, digest string) {
	t.Helper()
	top, err := json.Marshal(map[string]any{"schemaVersion": 2, "manifests": []any{map[string]any{"digest": digest, "size": 1}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "index.json"), top, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The platform comes from the image config: a single manifest carries none,
// and an index entry may omit it.
func TestLayoutImageConfigChecksPlatform(t *testing.T) {
	image := func(t *testing.T, layout, arch string) string {
		config := writeBlob(t, layout, map[string]any{"os": "linux", "architecture": arch, "config": map[string]any{"Entrypoint": []string{"/c8s"}}})
		return writeBlob(t, layout, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": map[string]any{"digest": config, "size": 1}})
	}
	index := func(t *testing.T, layout string, entries ...map[string]any) string {
		manifests := make([]any, len(entries))
		for i, e := range entries {
			manifests[i] = e
		}
		return writeBlob(t, layout, map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": manifests})
	}
	for name, tc := range map[string]struct {
		top     func(t *testing.T, layout string) string
		wantErr bool
	}{
		"single amd64 manifest": {top: func(t *testing.T, layout string) string { return image(t, layout, "amd64") }},
		"single arm64 manifest": {top: func(t *testing.T, layout string) string { return image(t, layout, "arm64") }, wantErr: true},
		"platformless amd64 entry": {top: func(t *testing.T, layout string) string {
			return index(t, layout, map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": image(t, layout, "amd64"), "size": 1})
		}},
		"platformless arm64 entry": {top: func(t *testing.T, layout string) string {
			return index(t, layout, map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": image(t, layout, "arm64"), "size": 1})
		}, wantErr: true},
		"amd64 entry over an arm64 image": {top: func(t *testing.T, layout string) string {
			return index(t, layout, map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": image(t, layout, "arm64"), "size": 1, "platform": map[string]string{"os": "linux", "architecture": "amd64"}})
		}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			layout := t.TempDir()
			top := tc.top(t, layout)
			writeIndexJSON(t, layout, top)
			_, err := layoutImageConfig(layout, top)
			if (err != nil) != tc.wantErr {
				t.Fatalf("layoutImageConfig(%s) = %v, want error %v", name, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), top) {
				t.Fatalf("layoutImageConfig(%s) = %v, want an error naming %s", name, err, top)
			}
		})
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

// The migration guides keep their sections, and every link in them names a
// document and heading that exist.
func TestDocumentedMigrationsResolve(t *testing.T) {
	link := regexp.MustCompile(`\]\(([^)\s]*)\)`)
	for _, tc := range []struct{ file, section string }{
		{"allowlist-and-capabilities.md", "### Migrate stored component entries"},
		{"secrets.md", "#### Migrate env policies that list service links"},
		{"secrets.md", "#### Move clients that pin the old name"},
	} {
		doc, err := os.ReadFile(filepath.Join("../../docs", tc.file))
		if err != nil {
			t.Fatal(err)
		}
		_, section, ok := strings.Cut(string(doc), "\n"+tc.section+"\n")
		if !ok {
			t.Errorf("%s lacks %q", tc.file, tc.section)
			continue
		}
		level := strings.Index(tc.section, " ")
		if end := regexp.MustCompile(`\n#{1,` + strconv.Itoa(level) + `} `).FindStringIndex(section); end != nil {
			section = section[:end[0]]
		}
		for _, m := range link.FindAllStringSubmatch(section, -1) {
			target, anchor, _ := strings.Cut(m[1], "#")
			if strings.Contains(target, "://") {
				continue
			}
			if target == "" {
				target = tc.file
			}
			linked, err := os.ReadFile(filepath.Join("../../docs", target))
			if err != nil {
				t.Errorf("%s %q links to %s: %v", tc.file, tc.section, m[1], err)
				continue
			}
			if anchor != "" && !slices.Contains(headingAnchors(string(linked)), anchor) {
				t.Errorf("%s %q links to %s, which has no heading #%s", tc.file, tc.section, target, anchor)
			}
		}
	}
}

// headingAnchors returns the anchors GitHub derives from doc's headings.
func headingAnchors(doc string) []string {
	var anchors []string
	for _, line := range strings.Split(doc, "\n") {
		heading, ok := strings.CutPrefix(strings.TrimLeft(line, "#"), " ")
		if !ok || !strings.HasPrefix(line, "#") {
			continue
		}
		anchor := strings.Map(func(r rune) rune {
			switch {
			case r == ' ':
				return '-'
			case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
				return unicode.ToLower(r)
			}
			return -1
		}, heading)
		anchors = append(anchors, anchor)
	}
	return anchors
}
