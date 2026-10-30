package sidecar

import (
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// Where no node pins CDS and nothing names a pin, the sidecar reaches no CDS
// it can hold to anything.
func TestParsePinsRefusesAnUnpinnedCDS(t *testing.T) {
	if _, err := (&Config{}).ParsePins(); err == nil || !strings.Contains(err.Error(), "pins no image") {
		t.Fatalf("error = %v, want an unpinned-CDS refusal", err)
	}
}

func TestParsePinsAcceptsAPinnedCDS(t *testing.T) {
	cfg := Config{MeasurementsConfigJSON: testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)}
	got, err := cfg.ParsePins()
	if err != nil {
		t.Fatalf("ParsePins: %v", err)
	}
	if len(got.Images) != 1 || len(got.Images[0].LaunchFile) == 0 {
		t.Fatalf("pins = %+v, want the launch-bound image", got.Images)
	}
}

// A CDS is pinned to the configuration it runs on, so a document naming only
// its image admits any CDS VM.
func TestParsePinsRejectsAPinWithoutALaunchBinding(t *testing.T) {
	unbound := `{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` + testutil.TestMeasurement + `"}]}`
	cfg := Config{MeasurementsConfigJSON: unbound}
	if _, err := cfg.ParsePins(); err == nil || !strings.Contains(err.Error(), "launch file") {
		t.Fatalf("error = %v, want a launch-binding refusal", err)
	}
}

func TestParsePinsRejectsAnUnusablePinSource(t *testing.T) {
	bound := testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile)
	for name, cfg := range map[string]Config{
		"two sources":  {MeasurementsConfig: "policy.json", MeasurementsConfigJSON: bound},
		"missing file": {MeasurementsConfig: "missing-file"},
		"not a pin":    {MeasurementsConfigJSON: `{}`},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := cfg.ParsePins(); err == nil {
				t.Fatal("an unusable pin source was accepted")
			}
		})
	}
}
