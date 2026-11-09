package helmchart

import (
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

// The ConfigMap the installer copies to each node carries the CDS endpoint
// beside its pin.
func TestChartHandsTheNodeItsCDSAddress(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	data := renderedConfigMap(t, out, "c8s-measurements").Data
	if data["cds.json"] == "" {
		t.Fatal("the CDS pin reaches no node")
	}
	if got := data["cds-address"]; got != baseCDSAddress {
		t.Fatalf("cds-address = %q, want %q", got, baseCDSAddress)
	}
}

// A pin below schema 2 carries no launch file, which is the only thing
// binding a CDS VM to the configuration it serves.
func TestChartRefusesACDSPinThatBindsNoLaunchFile(t *testing.T) {
	t.Parallel()
	flat := writeMeasurementsConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"`+baseCDSDigest+`"}]}`)
	out, err := helmTemplateUnpinned(t, repoChart, "--set-string", "cds.address="+baseCDSAddress, "--set-file", "cds.measurementsConfig="+flat)
	if err == nil {
		t.Fatalf("helm template accepted a pin binding no launch file\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "cds_pin_schema" {
		t.Fatalf("validation kind = %q, want cds_pin_schema\n%s", kind, out)
	}
}
