package helmchart

import (
	"regexp"
	"strings"
	"testing"
)

// Helm words an unknown key differently by version.
var unknownTAKey = regexp.MustCompile(`(?i)additional propert(y ta is|ies 'ta') not allowed`)

// Pod issuance authority belongs in the measured Trust Authority configuration, never in
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
		{"worker", helmTemplateWorker, unknownTAKey.MatchString},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.render(t)
			if err != nil {
				t.Fatalf("render: %v\n%s", err, out)
			}
			for _, workload := range renderedPodSpecs(t, out) {
				if workload.name == "c8s-cds" {
					t.Fatal("chart rendered an unmeasured Trust Authority")
				}
				for _, c := range append(workload.spec.Containers, workload.spec.InitContainers...) {
					for _, arg := range c.Args {
						if strings.HasPrefix(arg, "--pod-image-policy-file=") {
							t.Fatalf("chart granted Pod issuance authority to %s/%s", workload.name, c.Name)
						}
					}
				}
			}
			out, err = tc.render(t, "--set-file", "ta.podImagePolicy="+policy)
			if err == nil || !tc.refused(out) {
				t.Fatalf("chart accepted an unmeasured Pod policy: %v\n%s", err, out)
			}
		})
	}
}
