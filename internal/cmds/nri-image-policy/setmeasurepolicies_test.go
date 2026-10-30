package nriimagepolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bakedConfig mirrors the shape the node image ships: a base allowlist whose
// digests only the image build knows, and the CDS its launch staging pins.
const bakedConfig = `# nri-image-policy boot config — the MEASURED boot-time base allowlist.
platform: "snp"

plugin:
  health_addr: "unix:///run/nri-image-policy/health.sock"

workload_claims:
  socket_dir: "/run/nri-image-policy"
  proc_root: "/proc"
  advertise_host: ""

allowlist:
  base:
    schema: c8s.allowlist/v1
    workloads:
      hardened-kubernetes-7d4e658ad73a:
        label: "docker.io/rancher/hardened-kubernetes:v1.34.5-rke2r1-build20260227"
        containers:
          - digest: "sha256:7d4e658ad73aca6a80ab26d392395e9958f03105df5541d7552f70451ac0267d"
            image: "docker.io/rancher/hardened-kubernetes:v1.34.5-rke2r1-build20260227"
            command: {policy: any}
            args: {policy: any}
      rke2-runtime-4f502170a33e:
        label: "docker.io/rancher/rke2-runtime:v1.34.5-rke2r1"
        containers:
          - digest: "sha256:4f502170a33ec2b687e1b703abe31b1e290ff17cd45fba45b138c73689d3b02c"
            image: "docker.io/rancher/rke2-runtime:v1.34.5-rke2r1"
            command: {policy: any}
            args: {policy: any}
  pull:
    url: "https://127.0.0.1:30808"
    interval: "30s"
    timeout: "30s"
    attestation_api_url: "http://127.0.0.1:8400"
    cds_measurements_config: "/run/confos/launch/cds.json"
    # Deploy-time value; the installer's post-install refresh sets it.
    measure_policies: false

containerd:
  socket: "/run/k3s/containerd/containerd.sock"
  namespace: "k8s.io"

policy:
  mode: "fail-closed"
  enforce_existing: true
  deny_missing_annotation: true
  label_rules: []

logging:
  level: "info"
` + meshYAML

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func setMeasurePolicies(t *testing.T, path string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runSetMeasurePolicies(&out, append([]string{"--config", path}, args...)); err != nil {
		t.Fatalf("set-measure-policies: %v", err)
	}
	return strings.TrimSpace(out.String())
}

func TestSetMeasurePoliciesPreservesFileMode(t *testing.T) {
	path := writeConfig(t, bakedConfig)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	setMeasurePolicies(t, path, "--measure-policies=true")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

// The switch lands and the baked base allowlist — which the chart cannot
// re-render, because only the image build resolves the RKE2 system digests —
// survives untouched, as does the CDS the node's launch staging pins.
func TestSetMeasurePoliciesKeepsTheBakedConfig(t *testing.T) {
	path := writeConfig(t, bakedConfig)

	if got := setMeasurePolicies(t, path, "--measure-policies=true"); got != patchUpdated {
		t.Fatalf("outcome = %q, want %q", got, patchUpdated)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("patched config does not load: %v\n%s", err, data)
	}
	if !cfg.Allowlist.Pull.MeasurePolicies {
		t.Error("measure_policies not set")
	}
	if got := cfg.Allowlist.Pull.CDSMeasurementsConfig; got != "/run/confos/launch/cds.json" {
		t.Errorf("cds_measurements_config = %q, want the staged document", got)
	}
	if len(cfg.Allowlist.Base.Workloads) != 2 {
		t.Errorf("base = %v, want the 2 baked entries", cfg.Allowlist.Base.Workloads)
	}
	if cfg.Platform != "snp" || cfg.WorkloadClaims.SocketDir != "/run/nri-image-policy" {
		t.Errorf("patch disturbed unrelated keys: platform=%q socket_dir=%q", cfg.Platform, cfg.WorkloadClaims.SocketDir)
	}
	if !strings.Contains(string(data), "MEASURED boot-time base allowlist") {
		t.Errorf("patch dropped the config's comments:\n%s", data)
	}
}

// Re-running the same install must not restart containerd, so an unchanged
// switch reports unchanged and leaves the file's bytes alone.
func TestSetMeasurePoliciesIsIdempotent(t *testing.T) {
	path := writeConfig(t, bakedConfig)
	setMeasurePolicies(t, path, "--measure-policies=true")

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if got := setMeasurePolicies(t, path, "--measure-policies=true"); got != patchUnchanged {
		t.Fatalf("second run outcome = %q, want %q", got, patchUnchanged)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("an unchanged switch rewrote the file:\n%s", second)
	}
	if got := setMeasurePolicies(t, path, "--measure-policies=false"); got != patchUpdated {
		t.Fatalf("disable outcome = %q, want %q", got, patchUpdated)
	}
	if loadPatched(t, path).Allowlist.Pull.MeasurePolicies {
		t.Error("--measure-policies=false left measuring on")
	}
}

// Every rejection leaves the file as it was: a config the plugin cannot load
// would stop a required NRI plugin registering, which blocks every container
// on the node.
func TestSetMeasurePoliciesRejectsBadInputWithoutTouchingTheFile(t *testing.T) {
	cases := map[string]struct {
		body string
		args []string
	}{
		"no switch":     {bakedConfig, nil},
		"not a boolean": {bakedConfig, []string{"--measure-policies=maybe"}},
		"no pull section": {
			body: strings.Replace(bakedConfig, "  pull:", "  nopull:", 1),
			args: []string{"--measure-policies=true"},
		},
		"config already invalid": {
			body: strings.Replace(bakedConfig, `url: "https://`, `url: "http://`, 1),
			args: []string{"--measure-policies=true"},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, tc.body)
			var out bytes.Buffer
			if err := runSetMeasurePolicies(&out, append([]string{"--config", path}, tc.args...)); err == nil {
				t.Fatalf("set-measure-policies accepted %v", tc.args)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read config: %v", err)
			}
			if string(data) != tc.body {
				t.Errorf("rejected input still rewrote the file:\n%s", data)
			}
		})
	}
}

// The daemon path must stay reachable: only the verb selects the patcher.
func TestRunDispatchesTheSetMeasurePoliciesVerb(t *testing.T) {
	path := writeConfig(t, bakedConfig)
	if err := Run([]string{setMeasurePoliciesVerb, "--config", path, "--measure-policies=true"}); err != nil {
		t.Fatalf("Run %s: %v", setMeasurePoliciesVerb, err)
	}
	if !loadPatched(t, path).Allowlist.Pull.MeasurePolicies {
		t.Error("measure_policies not set")
	}
}

func loadPatched(t *testing.T, path string) *config {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("patched config does not load: %v\n%s", err, data)
	}
	return cfg
}
