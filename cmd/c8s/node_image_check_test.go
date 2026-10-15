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

// writeLayout writes a multi-platform image whose linux/amd64 config sets env,
// under nested further indexes, whose entries omit their platform when
// platformless is set, and returns the image digest.
func writeLayout(t *testing.T, layouts string, env []string, nested int, platformless bool) string {
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

// A refusal names the digest the operator pinned, not an inner index's.
func TestLayoutManifestNamesPinnedDigest(t *testing.T) {
	layout := t.TempDir()
	arm := writeBlob(t, layout, map[string]any{"schemaVersion": 2, "config": map[string]any{"digest": writeBlob(t, layout, map[string]any{"config": map[string]any{}})}})
	inner := writeBlob(t, layout, map[string]any{"schemaVersion": 2, "manifests": []any{
		map[string]any{"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": arm, "size": 1, "platform": map[string]string{"os": "linux", "architecture": "arm64"}},
	}})
	top := writeBlob(t, layout, map[string]any{"schemaVersion": 2, "manifests": []any{
		map[string]any{"mediaType": "application/vnd.oci.image.index.v1+json", "digest": inner, "size": 1, "platform": map[string]string{"os": "linux", "architecture": "amd64"}},
	}})
	_, err := layoutManifest(layout, top)
	if err == nil || !strings.Contains(err.Error(), top) {
		t.Fatalf("layoutManifest(arm64-only image %s) = %v, want an error naming it", top, err)
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

// Each migration guide must close the gap its rename or rebuild opens: a
// measured node keeps its base until the cluster moves to a rebuilt image by
// a supported procedure, a document write reaches every client pinning the
// document without either snapshot reaching a client holding the other, an
// emptyDir CDS store loses entries applied before the upgrade, a locked node
// denies exec, and an image no match policy lists reports no per-variable
// digests.
func TestDocumentedMigrationsCoverStalePins(t *testing.T) {
	for _, tc := range []struct {
		file, section string
		want, forbid  []string
	}{
		{
			"../../docs/allowlist-and-capabilities.md", "### Migrate stored component entries",
			[]string{
				"nriImagePolicy.baked=true", "--served-policy-file", "operator.md#default-install-behavior",
				"every node runs an image whose base carries the match policies",
				"Before you upgrade the chart", "secrets.md#migrate-env-policies-that-list-service-links", "secrets.md#move-clients-that-pin-the-old-name",
				"Apply nothing yet", "Restore the operator-added workload entries", "Resolve every error except those on component entries with `env: any`",
				"Each relaunch starts CDS from the baked seed, so repeat step 1",
			},
			[]string{"Drain", "server.json", "reports no error on the exported document"},
		},
		{
			"../../docs/secrets.md", "#### Move clients that pin the old name",
			[]string{"--workload NEW_NAME", "To roll back", "every client that passes `--allowlist FILE`", "maintenance window", "fails in both directions", "pause the pinning client's traffic", "isolated cohort"},
			[]string{"for this workload", "cannot take the new document before"},
		},
		{
			"../../docs/secrets.md", "#### Migrate env policies that list service links",
			[]string{
				"c8s secrets explain", "c8s allowlist export pre-upgrade.json", "After the upgrade, once the new CDS Pod is `Ready`",
				"repeat steps 4 and 5 after each relaunch", "reports `variableDigests` only for an image",
			},
			[]string{"kubectl exec POD_NAME", "before you roll out the upgrade", "Get it with `c8s allowlist get OLD_NAME`"},
		},
	} {
		doc, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatal(err)
		}
		_, section, ok := strings.Cut(string(doc), tc.section+"\n")
		if !ok {
			t.Errorf("%s lacks %q", tc.file, tc.section)
			continue
		}
		section, _, _ = strings.Cut(section, "\n#")
		section = strings.Join(strings.Fields(section), " ")
		for _, want := range tc.want {
			if !strings.Contains(section, want) {
				t.Errorf("%s %q does not mention %s", tc.file, tc.section, want)
			}
		}
		for _, forbid := range tc.forbid {
			if strings.Contains(section, forbid) {
				t.Errorf("%s %q mentions %s", tc.file, tc.section, forbid)
			}
		}
	}
}
