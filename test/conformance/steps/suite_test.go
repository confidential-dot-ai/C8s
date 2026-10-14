package steps

import (
	"flag"
	"os"
	"testing"

	"github.com/cucumber/godog"
)

// opts takes --godog.* flags, e.g. --godog.format=pretty,cucumber:report.json
// --godog.tags=@area:enforcement. Undefined and pending steps do not fail the
// run: the suite's judge reports their outcomes as incomplete.
var opts = godog.Options{Format: "pretty"}

func init() { godog.BindFlags("godog.", flag.CommandLine, &opts) }

// TestFeatures is the entry point an external runner drives against a live
// cluster: CONFORMANCE_FEATURES names the feature directory and
// CONFORMANCE_BACKEND the environment (see ../README.md). Without them, as in
// `make test`, there is nothing to run.
func TestFeatures(t *testing.T) {
	features, backendName := os.Getenv("CONFORMANCE_FEATURES"), os.Getenv("CONFORMANCE_BACKEND")
	if features == "" || backendName == "" {
		t.Skip("CONFORMANCE_FEATURES and CONFORMANCE_BACKEND are unset; the conformance runner sets them")
	}
	be, err := newBackend(backendName)
	if err != nil {
		t.Fatal(err)
	}
	o := opts
	o.Paths = []string{features}
	o.TestingT = t
	suite := godog.TestSuite{
		Name:                "c8s-conformance",
		ScenarioInitializer: initializeScenario(be),
		Options:             &o,
	}
	if suite.Run() != 0 {
		t.Fail()
	}
}
