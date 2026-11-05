package getcert

import (
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// A client holds CDS to the configuration it runs on, so the pin must name one
// CDS VM: a document pinning its image alone admits any of them.
func TestCDSPinsRequireALaunchBinding(t *testing.T) {
	bound := testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)
	pins, err := cdsPins(t.Context(), config{MeasurementsConfigJSON: bound})
	if err != nil {
		t.Fatal(err)
	}
	policy := pins.Current().Policy()
	if len(policy.Images) != 1 || len(policy.Images[0].LaunchFile) == 0 {
		t.Fatalf("pins = %+v, want the launch-bound image", policy.Images)
	}
	if len(policy.Measurements) != 0 || len(policy.Registers) != 0 {
		t.Fatal("complete policy produced a second flat fallback")
	}

	unbound := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + testutil.TestMeasurement + `"}]}`
	for name, cfg := range map[string]config{
		"no launch file":   {MeasurementsConfigJSON: unbound},
		"no pin at all":    {},
		"both sources":     {MeasurementsConfig: "policy.json", MeasurementsConfigJSON: bound},
		"missing file":     {MeasurementsConfig: "missing-file"},
		"not a pin at all": {MeasurementsConfigJSON: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cdsPins(t.Context(), cfg); err == nil {
				t.Fatal("a pin that is not one CDS VM's identity was accepted")
			}
		})
	}
}
