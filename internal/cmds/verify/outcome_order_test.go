package verify

import (
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// Half an image tuple is still MRTD only: the kernel pin leaves the rootfs
// unmeasured, and the rootfs pin leaves the kernel unmeasured.
func TestPartialImagePolicyEntryIsNotAFullImage(t *testing.T) {
	reg := hexBytes(t)
	for _, tc := range []struct {
		name      string
		registers map[int][]byte
	}{
		{"kernel only", map[int][]byte{1: reg(testRTMR1)}},
		{"rootfs only", map[int][]byte{2: reg(testRTMR2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := writeImagePolicy(t, "node.json", refvalues.ReferenceValues{
				Family: teetypes.FamilyTDX,
				Images: []remote.ImagePin{{Name: "node", Digest: reg(testMRTD), Registers: tc.registers}},
			})
			cfg := config{measurementsConfig: policy}
			ev := &evidence{platform: "tdx"}
			oc := newOutcome(cfg, ev, tdxResult(testMRTD, matchingRTMRs()), nil, mustPlan(t, cfg))
			if oc.Verified || !strings.Contains(oc.Error, "MRTD only") {
				t.Fatalf("a matching half-pinned entry counted as a full TDX image: %+v", oc)
			}
		})
	}
}

// The pins are enforced in one fixed order, so a run failing several at once
// reports the first unmet one rather than whichever check noticed.
func TestFirstUnmetPinDecidesTheError(t *testing.T) {
	manifest := writeTestManifest(t)
	snpLaunch := strings.Repeat("ab", 48)
	wrongMRTD, wrongRTMR1 := strings.Repeat("ee", 48), strings.Repeat("00", 48)
	bootloader := uint8(3)
	snp := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims: teetypes.Claims{
			LaunchDigest: snpLaunch,
			TCB:          teetypes.TcbInfo{Type: "Snp", Bootloader: &bootloader},
		},
	}
	for _, tc := range []struct {
		name     string
		cfg      config
		platform string
		result   *teetypes.VerificationResult
		want     string
	}{
		{"the TDX-only register gate precedes the TCB floor",
			config{imageManifest: manifest, minTCBBootloader: 4}, "snp", snp,
			"runtime measurement registers exist only on TDX"},
		{"the TCB floor precedes the measurement allowlist",
			config{measurements: []string{strings.Repeat("cd", 48)}, minTCBBootloader: 4}, "snp", snp,
			"below the --min-tcb-bootloader floor"},
		{"the MRTD precedes the registers",
			config{imageManifest: manifest}, "tdx",
			tdxResult(wrongMRTD, map[string]any{"rtmr_1": wrongRTMR1, "rtmr_2": testRTMR2}),
			"MRTD mismatch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &evidence{platform: tc.platform}
			oc := newOutcome(tc.cfg, ev, tc.result, nil, mustPlan(t, tc.cfg))
			if oc.Verified || !strings.Contains(oc.Error, tc.want) {
				t.Fatalf("error = %q, want the first unmet pin to decide it (%q)", oc.Error, tc.want)
			}
		})
	}
}

// A register mismatch keeps what was already compared, in ascending index
// order, so the verdict says how far enforcement got.
func TestRTMRMismatchKeepsEnforcedRegisters(t *testing.T) {
	manifest := writeTestManifest(t)
	wrong := strings.Repeat("00", 48)
	for _, tc := range []struct {
		name  string
		cfg   config
		rtmrs map[string]any
		want  []string
	}{
		{"wrong rootfs", config{imageManifest: manifest},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": wrong},
			[]string{"1:" + testRTMR1}},
		{"wrong runtime chain", config{imageManifest: manifest, expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": wrong},
			[]string{"1:" + testRTMR1, "2:" + testRTMR2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ev := &evidence{platform: "tdx"}
			oc := newOutcome(tc.cfg, ev, tdxResult(testMRTD, tc.rtmrs), nil, mustPlan(t, tc.cfg))
			if oc.Verified {
				t.Fatalf("a mismatched register must fail the verdict: %+v", oc)
			}
			if !slices.Equal(oc.RTMRsPinned, tc.want) {
				t.Errorf("RTMRsPinned = %v, want %v", oc.RTMRsPinned, tc.want)
			}
		})
	}
}

// A history the operator key replays is checked, so the verdict passes with
// nothing left to warn about.
func TestOperatorPkeyReplayedHistoryVerifiesWithoutWarnings(t *testing.T) {
	plan, seed := historyPlan(t, config{})
	measured := []string{testPolicyP, testPolicyQ}
	ev := &evidence{platform: "tdx", measured: measured}
	replayed := runtimemeasure.FromDigestsSeeded(seed, measured)
	oc := newOutcome(config{}, ev, tdxResult(testMRTD, rtmr3Claims(replayed)), nil, plan)
	if !oc.Verified {
		t.Fatalf("a replaying history must verify: %s", oc.Error)
	}
	if len(oc.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", oc.Warnings)
	}
	if !slices.Equal(oc.MeasuredPolicies, measured) {
		t.Errorf("MeasuredPolicies = %v, want %v", oc.MeasuredPolicies, measured)
	}
}

// The MRTD-only rule judges a measurement pin, so a TDX run that sets none
// verifies and reports itself unpinned.
func TestUnpinnedTDXRunVerifies(t *testing.T) {
	ev := &evidence{platform: "tdx"}
	oc := newOutcome(config{}, ev, tdxResult(testMRTD, matchingRTMRs()), nil, mustPlan(t, config{}))
	if !oc.Verified || oc.Pinned {
		t.Fatalf("an unpinned TDX run must verify unpinned: %+v", oc)
	}
	if len(oc.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", oc.Warnings)
	}
}
