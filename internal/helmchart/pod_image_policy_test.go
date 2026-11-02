package helmchart

import (
	"strings"
	"testing"
)

// Pod issuance authority belongs in the measured CDS configuration, never in
// the cluster chart or its credential clients.
func TestChartCannotConfigurePodIssuance(t *testing.T) {
	t.Parallel()
	digest := strings.Repeat("a", 96)
	policy := writeMeasurementsConfig(t, `{"schema_version":"1","tee":"tdx","measurements":[{"name":"pod","mrtd":"`+digest+`","rtmr":[null,"`+digest+`","`+digest+`"]}]}`)
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"external", nil}, {"baked", bakedArgs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := helmTemplate(t, tc.args...)
			if err != nil {
				t.Fatalf("render: %v\n%s", err, out)
			}
			for _, workload := range renderedPodSpecs(t, out) {
				if workload.name == "c8s-cds" {
					t.Fatal("chart rendered an unmeasured CDS")
				}
				for _, c := range append(workload.spec.Containers, workload.spec.InitContainers...) {
					for _, arg := range c.Args {
						if strings.HasPrefix(arg, "--pod-image-policy-file=") {
							t.Fatalf("chart granted Pod issuance authority to %s/%s", workload.name, c.Name)
						}
					}
				}
			}
			args := append(append([]string{}, tc.args...), "--set-file", "cds.podImagePolicy="+policy)
			out, err = helmTemplate(t, args...)
			if err == nil || !strings.Contains(out, "podImagePolicy") {
				t.Fatalf("chart accepted an unmeasured Pod policy: %v\n%s", err, out)
			}
		})
	}
}
