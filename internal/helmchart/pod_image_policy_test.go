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
		name    string
		render  func(t *testing.T, args ...string) (string, error)
		refused func(out string) bool
	}{
		{"cloud", helmTemplate, func(out string) bool { return strings.Contains(out, "podImagePolicy") }},
		// Helm's wording for an unknown key differs by version ("Additional
		// property cds is not allowed" vs "additional properties 'cds' not
		// allowed"), so match on the shared stem.
		{"worker", helmTemplateWorker, func(out string) bool {
			return strings.Contains(strings.ToLower(out), "additional propert") && strings.Contains(out, "cds")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.render(t)
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
			out, err = tc.render(t, "--set-file", "cds.podImagePolicy="+policy)
			if err == nil || !tc.refused(out) {
				t.Fatalf("chart accepted an unmeasured Pod policy: %v\n%s", err, out)
			}
		})
	}
}
