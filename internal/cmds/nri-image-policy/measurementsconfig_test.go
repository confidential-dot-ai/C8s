package nriimagepolicy

import (
	"strings"
	"testing"
)

func TestPullAndInventoryUseCompleteCDSPolicy(t *testing.T) {
	cfg := validConfig()
	// The plugin's platform is the one CDS runs with, so a document naming
	// another family is refused on every path that reads it.
	cfg.Platform = "tdx"
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "../../../internal/testdata/node-identities.json"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	// Both the pull client and inventory endpoint call this resolver.
	set, err := cfg.Allowlist.Pull.policySet(cfg.NormalizedPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Images) != 2 || len(set.Images[0].Anchor) == 0 || len(set.Images[0].Registers) != 2 {
		t.Fatal("CDS policy lost part of its image/operator tuple")
	}
	if _, err := allowlistPullHTTPClient(cfg.Allowlist.Pull, cfg.NormalizedPlatform()); err != nil {
		t.Fatal(err)
	}
	cfg.Allowlist.Pull.CDSMeasurementsConfig = "missing-file"
	if _, err := cfg.Allowlist.Pull.policySet(cfg.NormalizedPlatform()); err == nil {
		t.Fatal("missing full policy fell back to unpinned")
	}
}

func TestCDSPolicyConflictValidationIsShared(t *testing.T) {
	for _, tc := range []struct {
		name                string
		measurements, rtmrs []string
	}{
		{"digest", []string{"invalid"}, nil},
		{"register", nil, []string{"invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Allowlist.Pull.CDSMeasurementsConfig = "missing-file"
			cfg.Allowlist.Pull.CDSMeasurements = tc.measurements
			cfg.Allowlist.Pull.CDSRTMRs = tc.rtmrs
			validationErr := cfg.Validate()
			_, loadErr := cfg.Allowlist.Pull.policySet(cfg.NormalizedPlatform())
			if validationErr == nil || loadErr == nil || validationErr.Error() != loadErr.Error() || !strings.Contains(loadErr.Error(), "cannot be combined") {
				t.Fatalf("conflict must precede parsing and file reads: validation=%v load=%v", validationErr, loadErr)
			}
		})
	}
}
