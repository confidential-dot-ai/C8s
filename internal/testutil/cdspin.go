package testutil

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// CDSLaunchFile is the configuration document a test CDS VM is launched with.
// Its contents matter only to a test that also reports the matching binding.
const CDSLaunchFile = "schemaVersion: c8s-cds/v1\nclusterID: lane\n"

// NextCDSImage is the image a CDS pin decree moves a test cluster to.
const NextCDSImage = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

// CDSPinDocument renders the only pin shape a CDS client accepts: a refvalues
// document binding its one image, at measurement, to the exact launch file
// that CDS runs on.
func CDSPinDocument(measurement, launchFile string) string {
	return `{"schema_version":"2","tee":"sev-snp","measurements":[{"name":"cds","measurement":"` +
		measurement + `","launch_file":` + strconv.Quote(launchFile) + `}]}`
}

// CDSPinFile writes CDSPinDocument at TestMeasurement and returns its path.
func CDSPinFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds-pin.json")
	if err := os.WriteFile(path, []byte(CDSPinDocument(TestMeasurement, CDSLaunchFile)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
