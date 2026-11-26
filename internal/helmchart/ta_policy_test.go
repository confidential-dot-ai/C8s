package helmchart

import "testing"

// The chart's platform clients hold no pin of their own: the node hands each
// of them the one it was installed with, so nothing renders a policy flag
// outside the router's upstream sidecar (TestChartRouterTAPins).
func TestChartComponentsCarryNoPolicyFlags(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	for _, workload := range renderedPodSpecs(t, out) {
		for _, container := range append(workload.spec.Containers, workload.spec.InitContainers...) {
			if container.Name == "ta-attest" {
				continue
			}
			assertNoArgWithPrefix(t, workload.name+"/"+container.Name, container.Args,
				"--image-policy-file", "--image-policy-json", "--measurements-config")
		}
	}
}

// The ConfigMap the installer copies to each node carries the Trust Authority endpoint
// beside its pin.
func TestChartHandsTheNodeItsTAAddress(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	data := renderedConfigMap(t, out, "c8s-measurements").Data
	if data["ta.json"] == "" {
		t.Fatal("the Trust Authority pin reaches no node")
	}
	if got := data["ta-address"]; got != baseTAAddress {
		t.Fatalf("ta-address = %q, want %q", got, baseTAAddress)
	}
}

// A pin below schema 2 carries no launch file, which is the only thing
// binding a Trust Authority VM to the configuration it serves.
func TestChartRefusesATAPinThatBindsNoLaunchFile(t *testing.T) {
	t.Parallel()
	flat := writeMeasurementsConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"ta","measurement":"`+baseTADigest+`"}]}`)
	out, err := helmTemplateUnpinned(t, cloudChartDir, "--set-string", "ta.address="+baseTAAddress, "--set-file", "ta.measurementsConfig="+flat)
	if err == nil {
		t.Fatalf("helm template accepted a pin binding no launch file\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "ta_pin_schema" {
		t.Fatalf("validation kind = %q, want ta_pin_schema\n%s", kind, out)
	}
}
