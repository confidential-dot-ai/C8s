package main

// Offline regressions for the runtime runner's source/provenance gate.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const repoRoot = "../../../.."

var sourceFiles = []string{
	"images/node-guest/c8s/mkosi.sync",
	"images/node-guest/c8s/image-policy.yaml.in",
	"test/integration/cluster/lib.sh",
	"internal/cmds/nri-image-policy/pod_runtime_kubelet_integration_linux_test.go",
	"internal/cmds/nri-image-policy/pod_runtime_recovery_integration_linux_test.go",
	"internal/testdata/node-identities.json",
	"test/integration/pod-runtime/runtime-pins.json",
}

// stageSource copies the files the gate reads into a fresh source tree and
// returns it with the pins.
func stageSource(t *testing.T) (string, pins) {
	t.Helper()
	source := t.TempDir()
	for _, name := range sourceFiles {
		data, err := os.ReadFile(filepath.Join(repoRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(source, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var p pins
	raw, err := os.ReadFile(filepath.Join(source, "test/integration/pod-runtime/runtime-pins.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return source, p
}

func rewrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func expectRefusal(t *testing.T, source string, p pins, reason string) {
	t.Helper()
	_, err := validateRuntimeInputs(source, p, "amd64")
	if err == nil || !strings.Contains(err.Error(), reason) {
		t.Fatalf("got %v, want a refusal mentioning %q", err, reason)
	}
}

func TestCurrentSourceAndBothArchitectures(t *testing.T) {
	source, p := stageSource(t)
	for _, architecture := range []string{"amd64", "arm64"} {
		runner, err := validateRuntimeInputs(source, p, architecture)
		if err != nil {
			t.Fatalf("%s: %v", architecture, err)
		}
		if !regexp.MustCompile(`^kindest/node:.*@sha256:[a-f0-9]{64}$`).MatchString(runner) {
			t.Fatalf("%s: runner %q is not digest pinned", architecture, runner)
		}
	}
}

func TestPrepareLabelsProvenanceWithoutByteEquivalence(t *testing.T) {
	source, p := stageSource(t)
	stage := filepath.Join(source, "stage")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	previous := gitOutput
	defer func() { gitOutput = previous }()
	calls := 0
	gitOutput = func(string, ...string) ([]byte, error) {
		calls++
		if calls == 1 {
			return []byte(strings.Repeat("0", 40)), nil
		}
		return nil, nil
	}
	if err := prepare(source, stage, "amd64"); err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err := readJSON(filepath.Join(stage, "inputs.json"), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt["runtimePlatformDigest"] != p.Platforms["amd64"] {
		t.Fatalf("runtimePlatformDigest = %v", receipt["runtimePlatformDigest"])
	}
	bundles, _ := receipt["guestAirgapBundlesAMD64"].(map[string]any)
	for bundle, digest := range p.GuestAirgapBundlesAMD64 {
		if bundles[bundle] != digest {
			t.Fatalf("guestAirgapBundlesAMD64[%s] = %v", bundle, bundles[bundle])
		}
	}
	if receipt["historicalRuntimeAirgapDigest"] != p.HistoricalRuntimeAirgapDigest {
		t.Fatalf("historicalRuntimeAirgapDigest = %v", receipt["historicalRuntimeAirgapDigest"])
	}
	if _, present := receipt["airgapFloorDigest"]; present {
		t.Fatal("the receipt must not claim an airgap floor digest")
	}
	if provenance, _ := receipt["runtimeProvenance"].(string); !strings.Contains(provenance, "runtime/CNI guest airgap byte equivalence unverified") {
		t.Fatalf("runtimeProvenance = %q", provenance)
	}
}

func TestGuestVersionAndBundleDrift(t *testing.T) {
	source, p := stageSource(t)
	path := filepath.Join(source, "images/node-guest/c8s/mkosi.sync")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := string(raw)
	type drift struct{ before, after, reason string }
	cases := []drift{{p.RKE2Version, "v0.0.0+rke2r1", "RKE2 version"}}
	for bundle, digest := range p.GuestAirgapBundlesAMD64 {
		cases = append(cases, drift{digest, strings.Repeat("0", 64), bundle + " bundle"})
	}
	for _, c := range cases {
		if strings.Count(original, c.before) != 1 {
			t.Fatalf("%s: %q must appear exactly once in mkosi.sync", c.reason, c.before)
		}
		rewrite(t, path, strings.Replace(original, c.before, c.after, 1))
		expectRefusal(t, source, p, c.reason)
	}
	rewrite(t, path, original)
	assignment := `RKE2_IMAGES_CORE_SHA256="` + p.GuestAirgapBundlesAMD64["core"] + `"`
	for _, changed := range []string{strings.Replace(original, assignment, "", 1), original + "\n" + assignment + "\n"} {
		rewrite(t, path, changed)
		expectRefusal(t, source, p, "core bundle")
	}
}

func TestCNIRuleDrift(t *testing.T) {
	source, p := stageSource(t)
	path := filepath.Join(source, "images/node-guest/c8s/image-policy.yaml.in")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := string(raw)
	digest := p.CNI.AirgapFloorDigest
	image := "docker.io/rancher/hardened-cni-plugins:" + p.CNI.Version
	cases := map[string]string{
		"digest":    strings.ReplaceAll(original, digest, "sha256:"+strings.Repeat("0", 64)),
		"version":   strings.ReplaceAll(original, image, image+"-changed"),
		"not-init":  strings.ReplaceAll(original, "      cilium:\n        initContainers:", "      cilium:\n        containers:"),
		"duplicate": original + "\n            image: \"" + image + "\"\n",
	}
	for reason, changed := range cases {
		if changed == original {
			t.Fatalf("%s: the drift case changed nothing", reason)
		}
		rewrite(t, path, changed)
		expectRefusal(t, source, p, "Cilium init rule")
	}
}

func TestMalformedRegistryPins(t *testing.T) {
	source, p := stageSource(t)
	for _, family := range []string{"runtime", "cni"} {
		for _, field := range []string{"registryIndex", "amd64", "arm64"} {
			broken := p
			broken.Platforms = map[string]string{}
			broken.CNI.Platforms = map[string]string{}
			for k, v := range p.Platforms {
				broken.Platforms[k] = v
			}
			for k, v := range p.CNI.Platforms {
				broken.CNI.Platforms[k] = v
			}
			switch {
			case family == "runtime" && field == "registryIndex":
				broken.RegistryIndex = "sha256:bad"
			case family == "runtime":
				broken.Platforms[field] = "sha256:bad"
			case field == "registryIndex":
				broken.CNI.RegistryIndex = "sha256:bad"
			default:
				broken.CNI.Platforms[field] = "sha256:bad"
			}
			expectRefusal(t, source, broken, "sha256 pins")
		}
	}
}
