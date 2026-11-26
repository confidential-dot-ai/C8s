package testutil

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TALaunchFile is the configuration document a test Trust Authority VM is launched with.
// Its contents matter only to a test that also reports the matching binding.
const TALaunchFile = "schemaVersion: c8s-ta/v1\nclusterID: lane\n"

// NextTAImage is the image a Trust Authority pin decree moves a test cluster to.
const NextTAImage = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// TAPinDocument renders the only pin shape a Trust Authority client accepts: a refvalues
// document binding its one image, at measurement, to the exact launch file
// that Trust Authority runs on.
func TAPinDocument(measurement, launchFile string) string {
	return `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"ta","measurement":"` +
		measurement + `","launch_file":` + strconv.Quote(launchFile) + `}]}`
}

// TAPinFile writes TAPinDocument at TestMeasurement and returns its path.
func TAPinFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ta-pin.json")
	if err := os.WriteFile(path, []byte(TAPinDocument(TestMeasurement, TALaunchFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
