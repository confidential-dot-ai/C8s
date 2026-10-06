package helmchart

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestChartImagePolicyUsesCanonicalFlags(t *testing.T) {
	policy := writeChartImagePolicy(t, chartTDXPolicy(chartTDXImage("first", chartDigestA, `[null,"`+chartDigestB+`"]`)))
	out, err := helmTemplate(t,
		"--set-file", "cds.measurementsConfig="+policy,
		"--set-file", "armtlsMesh.measurementsConfig="+policy,
		"--set-string", "cds.measurements[0]="+chartDigestA,
		"--set-string", "cds.rtmrs[0]=1="+chartDigestB,
	)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	want := map[string]bool{"c8s-cds": false, "c8s-operator": false, "c8s-router": false, "c8s-armtls-mesh": false}
	for _, workload := range renderedPodSpecs(t, out) {
		containers := append(workload.spec.Containers, workload.spec.InitContainers...)
		for _, container := range containers {
			for _, arg := range container.Args {
				if strings.HasPrefix(arg, "--measurements-config") {
					t.Fatalf("%s/%s uses removed policy alias: %s", workload.name, container.Name, arg)
				}
				if arg == "--image-policy-file" || strings.HasPrefix(arg, "--image-policy-file=") {
					if _, expected := want[workload.name]; expected {
						want[workload.name] = true
					}
				}
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("%s did not receive its complete policy through --image-policy-file", name)
		}
	}
}

const (
	chartDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	chartDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func chartTDXImage(name, digest, registers string) string {
	return fmt.Sprintf(`{"name":%q,"mrtd":%q,"rtmr":%s}`, name, digest, registers)
}

func chartTDXPolicy(images ...string) string {
	return `{"schema_version":"1","tee":"tdx","measurements":[` + strings.Join(images, ",") + `]}`
}

func writeChartImagePolicy(t *testing.T, policy string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "image-policy.json")
	if err := os.WriteFile(path, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChartNRIRejectsPolicyLoss(t *testing.T) {
	image := chartTDXImage("first", chartDigestA, `[null,"`+chartDigestB+`"]`)
	policy := chartTDXPolicy(image)
	for _, tc := range []struct {
		name, policy       string
		digests, registers []string
	}{
		{name: "missing pins", policy: policy},
		{name: "wider digest set", policy: policy, digests: []string{chartDigestA, chartDigestB}, registers: []string{"1=" + chartDigestB}},
		{name: "narrower digest set", policy: chartTDXPolicy(image, chartTDXImage("second", chartDigestB, `[null,"`+chartDigestB+`"]`)), digests: []string{chartDigestA}, registers: []string{"1=" + chartDigestB}},
		{name: "missing register", policy: policy, digests: []string{chartDigestA}},
		{name: "extra register", policy: policy, digests: []string{chartDigestA}, registers: []string{"1=" + chartDigestB, "2=" + chartDigestA}},
		{name: "wrong register", policy: policy, digests: []string{chartDigestA}, registers: []string{"1=" + chartDigestA}},
		{name: "divergent registers", policy: chartTDXPolicy(image, chartTDXImage("second", chartDigestB, `[null,"`+chartDigestA+`"]`)), digests: []string{chartDigestA, chartDigestB}, registers: []string{"1=" + chartDigestB}},
		{name: "anchor", policy: chartTDXPolicy(strings.TrimSuffix(image, "}") + `,"approver_key":"key"}`), digests: []string{chartDigestA}, registers: []string{"1=" + chartDigestB}},
		{name: "malformed JSON", policy: `{"schema_version":`},
		{name: "unsupported schema", policy: strings.Replace(policy, `"schema_version":"1"`, `"schema_version":"2"`, 1)},
		{name: "empty measurements", policy: chartTDXPolicy()},
		{name: "unknown constraint", policy: strings.Replace(policy, `"name":"first"`, `"name":"first","future_constraint":true`, 1), digests: []string{chartDigestA}, registers: []string{"1=" + chartDigestB}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeChartImagePolicy(t, tc.policy)
			for _, baked := range []bool{false, true} {
				args := []string{"--set-file", "cds.measurementsConfig=" + path, "--set", fmt.Sprintf("nriImagePolicy.baked=%t", baked)}
				for i, d := range tc.digests {
					args = append(args, "--set-string", fmt.Sprintf("cds.measurements[%d]=%s", i, d))
				}
				for i, r := range tc.registers {
					args = append(args, "--set-string", fmt.Sprintf("cds.rtmrs[%d]=%s", i, r))
				}
				out, err := helmTemplate(t, args...)
				if err == nil {
					t.Fatalf("baked=%t accepted policy that loses constraints", baked)
				}
				if !strings.Contains(out, "nri-image-policy") {
					t.Fatalf("baked=%t failed outside NRI guard: %s", baked, out)
				}
			}
		})
	}
}

func TestChartNRIEquivalentPolicy(t *testing.T) {
	zero := strings.Repeat("0", 96)
	policy := chartTDXPolicy(chartTDXImage("first", chartDigestA, `[null,"`+chartDigestB+`",""]`), chartTDXImage("second", chartDigestB, `[null,"`+chartDigestB+`","`+zero+`",null]`))
	path := writeChartImagePolicy(t, policy)
	// Reverse order and duplicate digests: these are sets, not ordered lists.
	digests := []string{chartDigestB, chartDigestA, chartDigestA}
	registers := []string{"2=" + zero, "1=" + chartDigestB}
	for _, baked := range []bool{false, true} {
		args := []string{"--set-file", "cds.measurementsConfig=" + path, "--set", fmt.Sprintf("nriImagePolicy.baked=%t", baked)}
		for i, d := range digests {
			args = append(args, "--set-string", fmt.Sprintf("cds.measurements[%d]=%s", i, d))
		}
		for i, r := range registers {
			args = append(args, "--set-string", fmt.Sprintf("cds.rtmrs[%d]=%s", i, r))
		}
		out, err := helmTemplate(t, args...)
		if err != nil {
			t.Fatalf("baked=%t: %v\n%s", baked, err, out)
		}
		if baked {
			ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
			script := strings.Join(containerArgs(t, &ds, "install"), "\n")
			for _, want := range []string{`--cds-measurements "` + strings.Join(digests, ",") + `"`, `--cds-rtmrs "` + strings.Join(registers, ",") + `"`} {
				if !strings.Contains(script, want) {
					t.Errorf("pins script missing %s", want)
				}
			}
		} else {
			cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
			if !slices.Equal(cfg.Allowlist.Pull.CDSMeasurements, digests) || !slices.Equal(cfg.Allowlist.Pull.CDSRTMRs, registers) {
				t.Fatalf("rendered NRI pins differ: %+v", cfg.Allowlist.Pull)
			}
		}
	}
}

func TestChartDisabledNRIAllowsCompletePolicy(t *testing.T) {
	policy, err := filepath.Abs("../testdata/node-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	out, err := helmTemplate(t, "--set", "nriImagePolicy.enabled=false", "--set-file", "cds.measurementsConfig="+policy)
	if err != nil {
		t.Fatalf("disabled NRI rejected anchored policy: %v\n%s", err, out)
	}
	if strings.Contains(out, "name: c8s-nri-image-policy-worker") {
		t.Fatal("disabled NRI rendered installer")
	}
}

func TestChartNRISNPDigestPolicy(t *testing.T) {
	policy := fmt.Sprintf(`{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"snp","measurement":%q}]}`, chartDigestA)
	path := writeChartImagePolicy(t, policy)
	out, err := helmTemplate(t, "--set-file", "cds.measurementsConfig="+path, "--set-string", "cds.measurements[0]="+chartDigestA)
	if err != nil {
		t.Fatalf("SNP policy rejected: %v\n%s", err, out)
	}
	cfg := renderedNRIBootConfig(t, out, "c8s-nri-image-policy-worker")
	if !slices.Equal(cfg.Allowlist.Pull.CDSMeasurements, []string{chartDigestA}) || len(cfg.Allowlist.Pull.CDSRTMRs) != 0 {
		t.Fatalf("SNP pins differ: %+v", cfg.Allowlist.Pull)
	}
}
