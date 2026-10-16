package workflows

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Resolve the selected commit's CDI disk and attestation tuple through the
// production registry code, replacing only curl at its process boundary.
func TestTDXStagedImageRefs(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	var resolve workflowStep
	for _, step := range action.Runs.Steps {
		if step.Name == "resolve the node image built from the commit under test" {
			resolve = step
		}
	}
	if resolve.Run == "" || resolve.If != "inputs.exact_image != 'true'" {
		t.Fatal("missing staged image-ref resolution step")
	}
	const repository = "ghcr.io/confidential-dot-ai/node-guest-base"
	if resolve.Env["IMAGE_REPO"] != repository {
		t.Fatalf("unexpected image repository: %v", resolve.Env)
	}
	fixture := t.TempDir()
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(fixture, "bin/retry.sh"), "retry() { \"$@\"; }\n", 0o644)
	write(filepath.Join(fixture, "bin/curl"), `#!/usr/bin/env bash
set -euo pipefail
url= output= head=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -H|--max-time) shift 2 ;;
    -o) output=$2; shift 2 ;;
    -sI) head=true; shift ;;
    -fsSL) shift ;;
    https://*) url=$1; shift ;;
    *) echo "unexpected curl argument: $1" >&2; exit 1 ;;
  esac
done
printf '%s\n' "$url" >> "$FIXTURE_REQUESTS"
base=https://ghcr.io/v2/confidential-dot-ai/node-guest-base
case "$url" in
  'https://ghcr.io/token?scope=repository:confidential-dot-ai/node-guest-base:pull')
    printf '%s\n' '{"token":"fixture-token"}' ;;
  "$base/manifests/rke2-tdx-cdi-abcdef0")
    [[ $head == true ]] || exit 1
    printf 'HTTP/1.1 %s fixture\r\nDocker-Content-Digest: %s\r\n\r\n' "$FIXTURE_IMAGE_STATUS" "$FIXTURE_IMAGE_DIGEST" ;;
  "$base/manifests/rke2-tdx-abcdef0") cat "$FIXTURE_ORAS" ;;
  "$base/blobs/$FIXTURE_LAYER_DIGEST")
    [[ $output == "$FIXTURE_BLOB_OUTPUT" ]] || exit 1
    cp "$FIXTURE_MANIFEST" "$output" ;;
  *) echo "unexpected registry request: $url" >&2; exit 1 ;;
esac
`, 0o755)
	type testCase struct {
		name, field, value                                    string
		missing, noImage, badDigest, duplicate, wrongPlatform bool
	}
	cases := []testCase{
		{name: "complete tuple"},
		{name: "image not published", noImage: true},
		{name: "invalid image digest", badDigest: true},
		{name: "duplicate manifest layers", duplicate: true},
		{name: "wrong manifest platform", wrongPlatform: true},
	}
	for _, field := range []string{"mrtd", "rtmr1", "rtmr2"} {
		cases = append(cases,
			testCase{name: "missing " + field, field: field, missing: true},
			testCase{name: "uppercase " + field, field: field, value: strings.Repeat("A", 96)},
			testCase{name: "short " + field, field: field, value: strings.Repeat("a", 95)},
			testCase{name: "nonhex " + field, field: field, value: strings.Repeat("g", 96)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output := t.TempDir()
			tuple := map[string]string{
				"mrtd": strings.Repeat("a", 96), "rtmr1": strings.Repeat("b", 96), "rtmr2": strings.Repeat("c", 96),
			}
			if tc.field != "" {
				if tc.missing {
					delete(tuple, tc.field)
				} else {
					tuple[tc.field] = tc.value
				}
			}
			platform := "tdx"
			if tc.wrongPlatform {
				platform = "snp"
			}
			manifest, err := json.Marshal(map[string]any{"version": 3, "build": map[string]string{"platform": platform}, "tdx": tuple})
			if err != nil {
				t.Fatal(err)
			}
			layerDigest := "sha256:" + strings.Repeat("b", 64)
			layer := map[string]any{"digest": layerDigest, "annotations": map[string]string{"org.opencontainers.image.title": "manifest.json"}}
			layers := []any{layer}
			if tc.duplicate {
				layers = append(layers, layer)
			}
			oras, err := json.Marshal(map[string]any{"layers": layers})
			if err != nil {
				t.Fatal(err)
			}
			write(filepath.Join(output, "manifest.json"), string(manifest), 0o644)
			write(filepath.Join(output, "oras.json"), string(oras), 0o644)
			status, imageDigest := "200", "sha256:"+strings.Repeat("a", 64)
			if tc.noImage {
				status = "404"
			}
			if tc.badDigest {
				imageDigest = "sha256:invalid"
			}
			blobOutput := filepath.Join(output, "downloaded manifest.json")
			script := strings.ReplaceAll(resolve.Run, "/tmp/image-manifest.json", "'"+strings.ReplaceAll(blobOutput, "'", "'\"'\"'")+"'")
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", script)
			cmd.Env = append(os.Environ(),
				"PATH="+filepath.Join(fixture, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
				"IMAGE_REPO="+repository, "VARIANT=rke2-tdx", "c8sRef=abcdef0", "GITHUB_WORKSPACE="+fixture,
				"GITHUB_ENV="+filepath.Join(output, "environment"),
				"FIXTURE_IMAGE_STATUS="+status, "FIXTURE_IMAGE_DIGEST="+imageDigest,
				"FIXTURE_ORAS="+filepath.Join(output, "oras.json"), "FIXTURE_MANIFEST="+filepath.Join(output, "manifest.json"),
				"FIXTURE_LAYER_DIGEST="+layerDigest, "FIXTURE_BLOB_OUTPUT="+blobOutput,
				"FIXTURE_REQUESTS="+filepath.Join(output, "requests"))
			log, err := cmd.CombinedOutput()
			raw, readErr := os.ReadFile(filepath.Join(output, "environment"))
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if tc.name != "complete tuple" {
				if err == nil || len(raw) != 0 {
					t.Fatalf("invalid image metadata was exported: err=%v env=%q log=%s", err, raw, log)
				}
				diagnostic := "not a TDX node image manifest"
				if tc.noImage {
					diagnostic = "no node image for the commit under test"
				} else if tc.badDigest {
					diagnostic = "ghcr answered"
				} else if tc.duplicate {
					diagnostic = "expected one manifest.json layer"
				}
				if !strings.Contains(string(log), diagnostic) {
					t.Fatalf("image metadata failed at the wrong boundary: want %q log=%s", diagnostic, log)
				}
				if tc.noImage {
					requests, readErr := os.ReadFile(filepath.Join(output, "requests"))
					if readErr != nil {
						t.Fatal(readErr)
					}
					want := "https://ghcr.io/token?scope=repository:confidential-dot-ai/node-guest-base:pull\n" +
						"https://ghcr.io/v2/confidential-dot-ai/node-guest-base/manifests/rke2-tdx-cdi-abcdef0\n"
					if string(requests) != want || !strings.Contains(string(log), "no node image for the commit under test") {
						t.Fatalf("missing image was not rejected without fallback: requests=%q log=%s", requests, log)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve staged refs: %v\n%s", err, log)
			}
			got := make(map[string]string)
			for line := range strings.SplitSeq(strings.TrimSpace(string(raw)), "\n") {
				key, value, ok := strings.Cut(line, "=")
				if !ok {
					t.Fatalf("invalid environment assignment %q", line)
				}
				got[key] = value
			}
			want := map[string]string{
				"image": repository + "@" + imageDigest, "rootPvc": "c8s-root-" + strings.Repeat("a", 12),
				"mrtd": tuple["mrtd"], "rtmr1": tuple["rtmr1"], "rtmr2": tuple["rtmr2"],
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("staged environment: got %v, want %v", got, want)
			}
		})
	}
}
