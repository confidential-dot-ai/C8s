package helmchart

import (
	"strings"
	"testing"
)

// The chart's platform clients hold no pin of their own: the node hands each
// of them the one it was installed with, so nothing renders a policy flag
// outside the router's upstream sidecar (TestChartRouterCDSPins).
func TestChartComponentsCarryNoPolicyFlags(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, workload := range renderedPodSpecs(t, out) {
		for _, container := range append(workload.spec.Containers, workload.spec.InitContainers...) {
			if container.Name == "cds-attest" {
				continue
			}
			assertNoArgWithPrefix(t, workload.name+"/"+container.Name, container.Args,
				"--image-policy-file", "--image-policy-json", "--cds-measurements", "--cds-rtmrs", "--measurements-config")
		}
	}
}

// The ConfigMap the installer copies to each node carries the Trust Authority endpoint
// beside its pin.
func TestChartHandsTheNodeItsCDSAddress(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	data := renderedConfigMap(t, out, "c8s-measurements").Data
	if data["cds.json"] == "" {
		t.Fatal("the Trust Authority pin reaches no node")
	}
	if got := data["cds-address"]; got != baseCDSAddress {
		t.Fatalf("cds-address = %q, want %q", got, baseCDSAddress)
	}
}

// A pin below schema 2 carries no launch file, which is the only thing
// binding a Trust Authority VM to the configuration it serves.
func TestChartRefusesACDSPinThatBindsNoLaunchFile(t *testing.T) {
	t.Parallel()
	flat := writeMeasurementsConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"`+baseTADigest+`"}]}`)
	out, err := helmTemplateUnpinned(t, cloudChartDir, "--set-string", "cds.address="+baseCDSAddress, "--set-file", "cds.measurementsConfig="+flat)
	if err == nil {
		t.Fatalf("helm template accepted a pin binding no launch file\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "cds_pin_schema" {
		t.Fatalf("validation kind = %q, want cds_pin_schema\n%s", kind, out)
	}
}

func TestChartTrustAuthorityValuesPreserveRenderedPolicy(t *testing.T) {
	t.Parallel()
	pin := baseTAPin(t)
	keys := "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
	legacy := []string{
		"--set-string", "cds.address=" + baseCDSAddress,
		"--set-file", "cds.measurementsConfig=" + pin,
		"--set-string", "cds.operatorKeys=" + keys,
	}
	canonical := []string{
		"--set-string", "ta.address=" + baseCDSAddress,
		"--set-file", "ta.measurementsConfig=" + pin,
		"--set-string", "ta.operatorKeys=" + keys,
	}
	want, err := helmTemplateUnpinned(t, cloudChartDir, legacy...)
	if err != nil {
		t.Fatalf("helm template with cds values: %v\n%s", err, want)
	}
	for _, args := range [][]string{canonical, append(legacy, canonical...)} {
		out, err := helmTemplateUnpinned(t, cloudChartDir, args...)
		if err != nil {
			t.Fatalf("helm template with ta values: %v\n%s", err, out)
		}
		if out != want {
			t.Fatal("the same Trust Authority values rendered different manifests")
		}
	}
}

func TestChartRefusesConflictingTrustAuthorityValues(t *testing.T) {
	t.Parallel()
	pin := baseTAPin(t)
	otherPin := writeMeasurementsConfig(t, strings.ReplaceAll(baseTAPinDocument(t), baseTADigest, strings.Repeat("cd", len(baseTADigest)/2)))
	legacy := baseTAPolicy(t)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "address",
			args: []string{"--set-string", "ta.address=other.example.com:8443", "--set-file", "ta.measurementsConfig=" + pin},
		},
		{
			name: "pin",
			args: []string{"--set-string", "ta.address=" + baseCDSAddress, "--set-file", "ta.measurementsConfig=" + otherPin},
		},
		{
			name: "operator keys",
			args: []string{
				"--set-string", "ta.address=" + baseCDSAddress,
				"--set-file", "ta.measurementsConfig=" + pin,
				"--set-string", "ta.operatorKeys=-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n",
			},
		},
		{
			name: "split configuration",
			args: []string{"--set-string", "ta.address=" + baseCDSAddress},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplateUnpinned(t, cloudChartDir, append(legacy, tc.args...)...)
			if err == nil || parseValidationErrorKind(out) != "ta_values_conflict" {
				t.Fatalf("want ta_values_conflict, got %v\n%s", err, out)
			}
		})
	}
}
