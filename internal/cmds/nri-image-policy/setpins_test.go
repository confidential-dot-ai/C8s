package nriimagepolicy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	pinA = "7bb3af51e22d5371ebd9f2f1788273938005c9d27e8172f420263e50e27808bbc6f0e0beed195d21f81423da010afbe4"
	pinB = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
)

// bakedConfig mirrors the shape the node image ships: a base allowlist whose
// digests only the image build knows, and empty CDS pins.
const bakedConfig = `# nri-image-policy boot config — the MEASURED boot-time base allowlist.
platform: "snp"

plugin:
  health_addr: "unix:///var/run/nri-image-policy/health.sock"

workload_claims:
  socket_dir: "/var/run/nri-image-policy"
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
    # Deploy-time values; the installer's post-install config refresh pins them.
    cds_measurements: []

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
`

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image-policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func setPins(t *testing.T, path string, extra ...string) string {
	t.Helper()
	var out bytes.Buffer
	if err := runSetCDSPins(&out, append([]string{"--config", path}, extra...)); err != nil {
		t.Fatalf("set-cds-pins: %v", err)
	}
	return strings.TrimSpace(out.String())
}

func TestSetCDSPinsPreservesFileMode(t *testing.T) {
	path := writeConfig(t, bakedConfig)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	setPins(t, path, "--cds-measurements", pinA)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
}

// The pins land and the baked base allowlist — which the chart cannot
// re-render, because only the image build resolves the RKE2 system digests —
// survives untouched.
func TestSetCDSPinsKeepsTheBakedBase(t *testing.T) {
	path := writeConfig(t, bakedConfig)

	if got := setPins(t, path, "--cds-measurements", pinA+","+pinB); got != pinsUpdated {
		t.Fatalf("outcome = %q, want %q", got, pinsUpdated)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("patched config does not load: %v\n%s", err, data)
	}
	if got := cfg.Allowlist.Pull.CDSMeasurements; len(got) != 2 || got[0] != pinA || got[1] != pinB {
		t.Errorf("cds_measurements = %v, want [%s %s]", got, pinA, pinB)
	}
	if len(cfg.Allowlist.Base.Workloads) != 2 {
		t.Errorf("base = %v, want the 2 baked entries", cfg.Allowlist.Base.Workloads)
	}
	if cfg.Platform != "snp" || cfg.WorkloadClaims.SocketDir != "/var/run/nri-image-policy" {
		t.Errorf("patch disturbed unrelated keys: platform=%q socket_dir=%q", cfg.Platform, cfg.WorkloadClaims.SocketDir)
	}
	if !strings.Contains(string(data), "MEASURED boot-time base allowlist") {
		t.Errorf("patch dropped the config's comments:\n%s", data)
	}
}

// Re-running the same install must not restart containerd, so an unchanged pin
// set reports unchanged and leaves the file's bytes alone.
func TestSetCDSPinsIsIdempotent(t *testing.T) {
	path := writeConfig(t, bakedConfig)
	setPins(t, path, "--cds-measurements", pinA)

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if got := setPins(t, path, "--cds-measurements", pinA); got != pinsUnchanged {
		t.Fatalf("second run outcome = %q, want %q", got, pinsUnchanged)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("unchanged pins rewrote the file:\n%s", second)
	}
}

// The on-disk pins are compared case-folded, so a hand-written uppercase digest
// does not read as a change and cost a restart.
func TestSetCDSPinsFoldsCaseWhenComparing(t *testing.T) {
	path := writeConfig(t, strings.Replace(bakedConfig,
		"cds_measurements: []",
		`cds_measurements: ["`+strings.ToUpper(pinA)+`"]`, 1))

	if got := setPins(t, path, "--cds-measurements", pinA); got != pinsUnchanged {
		t.Fatalf("outcome = %q, want %q", got, pinsUnchanged)
	}
}

func TestSetCDSPinsWritesRTMRsInIndexOrder(t *testing.T) {
	path := writeConfig(t, bakedConfig)
	setPins(t, path, "--cds-measurements", pinA, "--cds-rtmrs", "2="+pinB+",1="+pinA)

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("patched config does not load: %v", err)
	}
	want := []string{"1=" + pinA, "2=" + pinB}
	if got := cfg.Allowlist.Pull.CDSRTMRs; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("cds_rtmrs = %v, want %v", got, want)
	}
}

// Every rejection leaves the file as it was: a config the plugin cannot load
// would stop a required NRI plugin registering, which blocks every container
// on the node.
func TestSetCDSPinsRejectsBadInputWithoutTouchingTheFile(t *testing.T) {
	cases := map[string]struct {
		body string
		args []string
	}{
		"no measurements":          {bakedConfig, nil},
		"measurement is not hex":   {bakedConfig, []string{"--cds-measurements", "nothex"}},
		"measurement wrong length": {bakedConfig, []string{"--cds-measurements", "aabb"}},
		"rtmr index 0":             {bakedConfig, []string{"--cds-rtmrs", "0=" + pinA}},
		"no pull section": {strings.Replace(bakedConfig, "  pull:", "  nopull:", 1),
			[]string{"--cds-measurements", pinA}},
		"config already invalid": {strings.Replace(bakedConfig, `url: "https://`, `url: "http://`, 1),
			[]string{"--cds-measurements", pinA}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeConfig(t, tc.body)
			var out bytes.Buffer
			if err := runSetCDSPins(&out, append([]string{"--config", path}, tc.args...)); err == nil {
				t.Fatalf("set-cds-pins accepted %v", tc.args)
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
func TestRunDispatchesThesetCDSPinsVerb(t *testing.T) {
	path := writeConfig(t, bakedConfig)
	if err := Run([]string{setCDSPinsVerb, "--config", path, "--cds-measurements", pinA}); err != nil {
		t.Fatalf("Run %s: %v", setCDSPinsVerb, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read patched config: %v", err)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		t.Fatalf("patched config does not load: %v", err)
	}
	if len(cfg.Allowlist.Pull.CDSMeasurements) != 1 {
		t.Errorf("cds_measurements = %v, want one pin", cfg.Allowlist.Pull.CDSMeasurements)
	}
}
