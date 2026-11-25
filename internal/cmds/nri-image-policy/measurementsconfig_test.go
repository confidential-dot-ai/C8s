package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
)

// testTAPinFile stages the pin document a node's config names, at the launch
// identity testutil reports.
func testTAPinFile(t *testing.T) string {
	t.Helper()
	return taPinFile(t, testutil.TAPinDocument(testutil.TestMeasurement, testutil.TALaunchFile))
}

// taPinFile stages the pin document this node holds its Trust Authority to.
func taPinFile(t *testing.T, document string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ta.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPullAndInventoryUseTheTAPinDocument(t *testing.T) {
	cfg := validConfig()
	cfg.Platform = "tdx"
	cfg.Allowlist.Pull.TAMeasurementsConfig = testTAPinFile(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// Both the pull client and inventory endpoint call this resolver. The Trust Authority
	// VM's family is its own; this node attests on TDX.
	set, err := cfg.Allowlist.Pull.policySet()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Images) != 1 || len(set.Images[0].LaunchFile) == 0 {
		t.Fatalf("Trust Authority policy = %+v, want the launch-bound image", set.Images)
	}
	if _, err := allowlistPullHTTPClient(cfg.Allowlist.Pull, testClusterDNS); err != nil {
		t.Fatal(err)
	}
	cfg.Allowlist.Pull.TAMeasurementsConfig = "missing-file"
	if _, err := cfg.Allowlist.Pull.policySet(); err == nil {
		t.Fatal("missing full policy fell back to unpinned")
	}
}
