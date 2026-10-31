package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// testCDSPinFile stages the pin document a node's config names, at the launch
// identity testutil reports.
func testCDSPinFile(t *testing.T) string {
	t.Helper()
	return cdsPinFile(t, testutil.CDSPinDocument(testutil.TestMeasurement, testutil.CDSLaunchFile))
}

// cdsPinFile stages the pin document this node holds its CDS to.
func cdsPinFile(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cds.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPullAndInventoryUseTheCDSPinDocument(t *testing.T) {
	cfg := validConfig()
	cfg.Platform = "tdx"
	cfg.Allowlist.Pull.CDSMeasurementsConfig = testCDSPinFile(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// Both the pull client and inventory endpoint call this resolver. The CDS
	// VM's family is its own; this node attests on TDX.
	set, err := cfg.Allowlist.Pull.policySet()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Images) != 1 || len(set.Images[0].LaunchFile) == 0 {
		t.Fatalf("CDS policy = %+v, want the launch-bound image", set.Images)
	}
	if _, err := allowlistPullHTTPClient(cfg.Allowlist.Pull, armtls.FixedPins(set), testClusterDNS); err != nil {
		t.Fatal(err)
	}
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "missing-file"
	if _, err := cfg.Allowlist.Pull.policySet(); err == nil {
		t.Fatal("missing full policy fell back to unpinned")
	}
}
