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

// A node image's own installer carries no pins either: its launch staging
// names the CDS, and the chart patches only the policy-measurement switch.
func TestChartBakedPluginInstallerPatchesMeasurePoliciesAlone(t *testing.T) {
	t.Parallel()
	out, err := helmTemplate(t, "--set", "attestationApi.cvmMode=bare-metal",
		"--set", "nriImagePolicy.baked=true", "--set", "nriImagePolicy.measurePolicies=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := strings.Join(containerArgs(t, &ds, "install"), "\n")
	if !strings.Contains(script, "set-measure-policies") || !strings.Contains(script, "--measure-policies=true") {
		t.Fatalf("the installer does not set the policy-measurement switch:\n%s", script)
	}
	for _, unwanted := range []string{"--cds-measurements", "--cds-rtmrs", baseCDSAddress} {
		if strings.Contains(script, unwanted) {
			t.Errorf("the installer carries %s: a measured config names its own CDS", unwanted)
		}
	}
}

// The ConfigMap the node reads its CDS from carries the address only where a
// node reads one: a plugin the image bakes takes it from its own launch
// staging.
func TestChartHandsTheNodeItsCDSAddressOnlyWhereOneReadsIt(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		args    []string
		address bool
	}{
		{name: "the chart installs the plugin", address: true},
		{name: "the node image bakes it", args: []string{"--set", "attestationApi.cvmMode=bare-metal", "--set", "nriImagePolicy.baked=true"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("helm template: %v\n%s", err, out)
			}
			data := renderedConfigMap(t, out, "c8s-measurements").Data
			if data["cds.json"] == "" {
				t.Fatal("the CDS pin reaches no node")
			}
			if got, ok := data["cds-address"]; ok != tc.address || (ok && got != baseCDSAddress) {
				t.Fatalf("cds-address = %q (present %v), want present=%v", got, ok, tc.address)
			}
		})
	}
}

// A pin below schema 2 carries no launch file, which is the only thing
// binding a CDS VM to the configuration it serves.
func TestChartRefusesACDSPinThatBindsNoLaunchFile(t *testing.T) {
	t.Parallel()
	flat := writeMeasurementsConfig(t, `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"`+baseCDSDigest+`"}]}`)
	out, err := helmTemplateUnpinned(t, ".", "--set-string", "cds.address="+baseCDSAddress, "--set-file", "cds.measurementsConfig="+flat)
	if err == nil {
		t.Fatalf("helm template accepted a pin binding no launch file\n%s", out)
	}
	if kind := parseValidationErrorKind(out); kind != "cds_pin_schema" {
		t.Fatalf("validation kind = %q, want cds_pin_schema\n%s", kind, out)
	}
}
