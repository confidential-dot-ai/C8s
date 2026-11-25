package getcert

import (
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
)

// A client holds Trust Authority to the configuration it runs on, so the pin must name one
// Trust Authority VM: a document pinning its image alone admits any of them.
func TestTAPinsRequireALaunchBinding(t *testing.T) {
	bound := testutil.TAPinDocument(testutil.TestMeasurement, testutil.TALaunchFile)
	pins, err := taPins(config{MeasurementsConfigJSON: bound})
	if err != nil {
		t.Fatal(err)
	}
	if len(pins.Images) != 1 || len(pins.Images[0].LaunchFile) == 0 {
		t.Fatalf("pins = %+v, want the launch-bound image", pins.Images)
	}
	if len(pins.Measurements) != 0 || len(pins.Registers) != 0 {
		t.Fatal("complete policy produced a second flat fallback")
	}

	unbound := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"ta","measurement":"` + testutil.TestMeasurement + `"}]}`
	for name, cfg := range map[string]config{
		"no launch file":   {MeasurementsConfigJSON: unbound},
		"no pin at all":    {},
		"both sources":     {MeasurementsConfig: "policy.json", MeasurementsConfigJSON: bound},
		"missing file":     {MeasurementsConfig: "missing-file"},
		"not a pin at all": {MeasurementsConfigJSON: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := taPins(cfg); err == nil {
				t.Fatal("a pin that is not one Trust Authority VM's identity was accepted")
			}
		})
	}
}
