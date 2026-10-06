package verify

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

var (
	testMRTD  = strings.Repeat("1a", 48)
	testRTMR1 = strings.Repeat("2b", 48)
	testRTMR2 = strings.Repeat("3c", 48)
	testRTMR3 = strings.Repeat("4d", 48)
)

func writeTestManifest(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	content := `{"mrtd":"` + testMRTD + `","rtmr1":"` + testRTMR1 + `","rtmr2":"` + testRTMR2 + `"}`
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// mustPlan builds the run plan for cfg, failing the test on a usage error.
func mustPlan(t *testing.T, cfg config) *verifyPlan {
	t.Helper()
	plan, err := buildPolicy(cfg)
	if err != nil {
		t.Fatalf("buildPolicy: %v", err)
	}
	return plan
}

// tdxResult fabricates a passing TDX verdict carrying the given launch digest
// and rtmr_N claims, the shape attestation-go extracts from a verified quote.
func tdxResult(launch string, rtmrs map[string]any) *teetypes.VerificationResult {
	return &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformTDX,
		Claims: teetypes.Claims{
			LaunchDigest: launch,
			PlatformData: rtmrs,
		},
	}
}

func matchingRTMRs() map[string]any {
	return map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": testRTMR3}
}

// The manifest is one atomic pin: all three of its registers compare exactly,
// so a full match verifies and reports what was enforced.
func TestImageManifestPinVerifies(t *testing.T) {
	cfg := config{imageManifest: writeTestManifest(t), expectedRTMR3Hex: testRTMR3}
	plan := mustPlan(t, cfg)

	oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, matchingRTMRs()), nil, plan)
	if !oc.Verified {
		t.Fatalf("full tuple match must verify: %s", oc.Error)
	}
	if !oc.Pinned {
		t.Error("an image manifest is a measurement pin — the verdict must not report itself unpinned")
	}
	want := []string{"1:" + testRTMR1, "2:" + testRTMR2, "3:" + testRTMR3}
	if len(oc.RTMRsPinned) != len(want) {
		t.Fatalf("RTMRsPinned = %v, want %v", oc.RTMRsPinned, want)
	}
	for i := range want {
		if oc.RTMRsPinned[i] != want[i] {
			t.Errorf("RTMRsPinned[%d] = %q, want %q", i, oc.RTMRsPinned[i], want[i])
		}
	}
	if len(oc.Warnings) != 0 {
		t.Errorf("a full image pin must not warn: %v", oc.Warnings)
	}
}

// The manifest's MRTD is compared exactly and is never unioned into the
// --measurements allowlist. An allowlist is satisfied by ANY member, so a
// launch digest from a different build sitting in --measurements would
// otherwise pass while RTMR[1]/[2] were pinned against this manifest — the
// tuple split the atomic load exists to prevent, and the same rule
// get-kubeconfig applies to the same file.
//
// The CLI now refuses the two together outright (see
// TestMeasurementsWithImageManifestIsAUsageError), so the second half of this
// test drives a hand-built plan: widening the MRTD compare into the allowlist
// is exactly the bypass that was closed, and it must stay closed however the
// plan was assembled.
func TestImageManifestMRTDIsNotWidenedByMeasurements(t *testing.T) {
	otherLaunch := strings.Repeat("ee", 48)
	cfg := config{imageManifest: writeTestManifest(t)}
	plan := mustPlan(t, cfg)

	if len(plan.policy.Policy.Measurements) != 0 {
		t.Fatalf("--image-manifest must contribute nothing to the allowlist, got %d entries", len(plan.policy.Policy.Measurements))
	}

	// Graft an allowlist onto the manifest plan by hand.
	plan.policy.Policy.Measurements = mustPlan(t, config{measurements: []string{otherLaunch}}).policy.Policy.Measurements

	oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(otherLaunch, matchingRTMRs()), nil, plan)
	if oc.Verified {
		t.Fatal("a launch digest that is allowlisted but is NOT the manifest MRTD must fail: the image tuple is atomic")
	}
	if !strings.Contains(oc.Error, "MRTD mismatch") {
		t.Errorf("error = %q, want the MRTD mismatch", oc.Error)
	}

	// And the manifest's own MRTD does not become an allowlist member either:
	// the two pins are both enforced, never merged in either direction.
	oc = newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, matchingRTMRs()), nil, plan)
	if oc.Verified || !strings.Contains(oc.Error, "not in --measurements allowlist") {
		t.Errorf("the MRTD must still satisfy an explicit --measurements allowlist: %+v", oc)
	}
}

// --measurements and --image-manifest are alternatives, not complements. The
// manifest pins MRTD to exactly one value, so an allowlist beside it either
// restates that digest or contradicts it — and the contradiction is a policy no
// guest can ever satisfy, turning every run into an "MRTD mismatch" that reads
// like an attestation failure rather than the typo it is. The client-side
// verifier refuses the same pair, so both tools must answer alike.
func TestMeasurementsWithImageManifestIsAUsageError(t *testing.T) {
	manifest := writeTestManifest(t)
	measFile := filepath.Join(t.TempDir(), "measurements.txt")
	if err := os.WriteFile(measFile, []byte(testMRTD+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		cfg  config
		want string
	}{
		{"contradicting allowlist", config{imageManifest: manifest, measurements: []string{strings.Repeat("ee", 48)}},
			"--measurements cannot be combined with --image-manifest"},
		// Refused even when the allowlist agrees with the manifest: it can add
		// nothing, and accepting the agreeing case would leave the operator to
		// discover the contradicting one as a red verdict.
		{"agreeing allowlist", config{imageManifest: manifest, measurements: []string{testMRTD}},
			"--measurements cannot be combined with --image-manifest"},
		{"--measurements-file", config{imageManifest: manifest, measurementsFile: measFile},
			"--measurements-file cannot be combined with --image-manifest"},
		{"both allowlist flags", config{imageManifest: manifest, measurements: []string{testMRTD}, measurementsFile: measFile},
			"--measurements/--measurements-file cannot be combined with --image-manifest"},
		// The pair is a flag contradiction, settled before any file is opened —
		// so an unreadable allowlist file still reports the conflict.
		{"conflict beats an unreadable allowlist file", config{imageManifest: manifest, measurementsFile: filepath.Join(t.TempDir(), "absent.txt")},
			"cannot be combined with --image-manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildPolicy(tc.cfg)
			if err == nil {
				t.Fatal("the pair must be a usage error, not a policy no guest can satisfy")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
			// The message has to say what to do, not only what is refused.
			for _, phrase := range []string{"pins MRTD exactly", "To pin this image, drop", "drop --image-manifest"} {
				if !strings.Contains(err.Error(), phrase) {
					t.Errorf("error = %q, want it to explain the way out (%q)", err, phrase)
				}
			}

			// Usage class, not a verdict: exit 1, and nothing dialed.
			var out, errOut strings.Builder
			if code := run(context.Background(), tc.cfg, &out, &errOut); code != exitUsage {
				t.Errorf("run code = %d, want %d; stderr: %s", code, exitUsage, errOut.String())
			}
		})
	}

	// Each flag alone keeps working — this rejects a combination, not either
	// way of pinning a launch measurement.
	t.Run("--image-manifest alone", func(t *testing.T) {
		plan := mustPlan(t, config{imageManifest: manifest})
		if plan.pins.image == nil {
			t.Error("--image-manifest alone must still resolve the image tuple")
		}
	})
	for _, cfg := range []config{{measurements: []string{testMRTD}}, {measurementsFile: measFile}} {
		if plan := mustPlan(t, cfg); len(plan.policy.Policy.Measurements) != 1 {
			t.Errorf("%+v: an allowlist alone must still build, got %d entries", cfg, len(plan.policy.Policy.Measurements))
		}
	}
}

func TestRTMRPinMismatchesFailClosed(t *testing.T) {
	manifest := writeTestManifest(t)
	for _, tc := range []struct {
		name    string
		cfg     config
		rtmrs   map[string]any
		wantErr string
	}{
		{"wrong rtmr1", config{imageManifest: manifest},
			map[string]any{"rtmr_1": strings.Repeat("00", 48), "rtmr_2": testRTMR2},
			"RTMR[1] (guest kernel)"},
		{"wrong rtmr2", config{imageManifest: manifest},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": strings.Repeat("00", 48)},
			"RTMR[2] (guest rootfs)"},
		{"wrong rtmr3", config{imageManifest: manifest, expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": strings.Repeat("00", 48)},
			"RTMR[3]"},
		{"absent rtmr1 claim", config{imageManifest: manifest},
			map[string]any{"rtmr_2": testRTMR2},
			"carry no rtmr_1"},
		{"absent rtmr3 claim", config{imageManifest: manifest, expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2},
			"carry no rtmr_3"},
		{"malformed claim", config{imageManifest: manifest, expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": "zz"},
			"malformed"},
		{"claim wrong length", config{imageManifest: manifest, expectedRTMR3Hex: testRTMR3},
			map[string]any{"rtmr_1": testRTMR1, "rtmr_2": testRTMR2, "rtmr_3": "abcd"},
			"malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oc := newOutcome(tc.cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, tc.rtmrs), nil, mustPlan(t, tc.cfg))
			if oc.Verified {
				t.Fatal("mismatched/absent RTMR claim must fail the verdict")
			}
			if !strings.Contains(oc.Error, tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", oc.Error, tc.wantErr)
			}
		})
	}
}

// An RTMR pin against non-TDX evidence is a policy error naming the platform,
// never a silently ignored option: SNP has no runtime measurement registers,
// so "pass" would mean "nothing enforced". The gate runs before any register
// comparison, so the error says the policy was inapplicable rather than
// blaming a mismatch.
func TestRTMRPinRejectsNonTDXPlatform(t *testing.T) {
	snpLaunch := strings.Repeat("ab", 48)
	manifest := writeTestManifest(t)
	for _, cfg := range []config{
		{imageManifest: manifest},
		{imageManifest: manifest, expectedRTMR3Hex: testRTMR3},
	} {
		result := &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims:         teetypes.Claims{LaunchDigest: snpLaunch},
		}
		oc := newOutcome(cfg, &evidence{platform: "snp"}, result, nil, mustPlan(t, cfg))
		if oc.Verified {
			t.Fatal("an RTMR pin with SNP evidence must be a hard verdict failure")
		}
		if !strings.Contains(oc.Error, `"snp"`) || !strings.Contains(oc.Error, "TDX") {
			t.Errorf("error = %q, want it to name the platform and the TDX-only rule", oc.Error)
		}
	}
}

// The TDX platform tag is attester-chosen and covered by no transcript, and
// attestation-go verifies "tdx", "az-tdx" and "gcp-tdx" through one path. Every
// TDX policy decision must therefore normalize the tag: a cloud-prefixed
// variant must neither escape a TDX-only rule nor trip one that does not apply.
func TestTDXPolicyDecisionsNormalizeThePlatformTag(t *testing.T) {
	for _, tag := range []string{"tdx", "az-tdx", "gcp-tdx"} {
		t.Run(tag+" cannot escape the MRTD-only rejection", func(t *testing.T) {
			cfg := config{measurements: []string{testMRTD}}
			result := tdxResult(testMRTD, matchingRTMRs())
			result.Platform = teetypes.PlatformType(tag)
			oc := newOutcome(cfg, &evidence{platform: tag}, result, nil, mustPlan(t, cfg))
			if oc.Verified {
				t.Fatalf("%s escaped the MRTD-only deployment-class rejection by its platform tag", tag)
			}
			if !strings.Contains(oc.Error, "UNMEASURED") {
				t.Errorf("error = %q, want the MRTD-only rejection", oc.Error)
			}
		})

		t.Run(tag+" is not falsely rejected by the TDX-only pin gate", func(t *testing.T) {
			cfg := config{imageManifest: writeTestManifest(t), expectedRTMR3Hex: testRTMR3}
			result := tdxResult(testMRTD, matchingRTMRs())
			result.Platform = teetypes.PlatformType(tag)
			oc := newOutcome(cfg, &evidence{platform: tag}, result, nil, mustPlan(t, cfg))
			if !oc.Verified {
				t.Fatalf("%s is TDX; its RTMR pins must be enforceable: %s", tag, oc.Error)
			}
		})

		t.Run(tag+" rejects an SNP TCB floor", func(t *testing.T) {
			cfg := config{imageManifest: writeTestManifest(t), minTCBSNP: 3}
			result := tdxResult(testMRTD, matchingRTMRs())
			result.Platform = teetypes.PlatformType(tag)
			oc := newOutcome(cfg, &evidence{platform: tag}, result, nil, mustPlan(t, cfg))
			if oc.Verified {
				t.Fatalf("%s accepted a --min-tcb-* floor the TDX path never applies", tag)
			}
			if !strings.Contains(oc.Error, "min-tcb") {
				t.Errorf("error = %q, want it to name the unenforceable floor", oc.Error)
			}
		})
	}
}

// A passing TDX verdict pinned on MRTD alone must warn prominently: MRTD
// covers only the TDVF firmware, and the guest kernel/rootfs stay unmeasured
// by that policy. The warning is the degraded form — it requires an
// operator-pinned CA anchor (see TestTDXMRTDOnlyRejectedWithoutCAAnchor).
func TestTDXMRTDOnlyWarns(t *testing.T) {
	cfg := config{measurements: []string{testMRTD}}
	plan := mustPlan(t, cfg)
	plan.meshCA = x509.NewCertPool()
	anchored := &evidence{platform: "tdx"}

	oc := newOutcome(cfg, anchored, tdxResult(testMRTD, matchingRTMRs()), nil, plan)
	if !oc.Verified {
		t.Fatalf("verdict failed: %s", oc.Error)
	}
	if len(oc.Warnings) != 1 || !strings.Contains(oc.Warnings[0], "UNMEASURED") {
		t.Fatalf("Warnings = %v, want the MRTD-only warning", oc.Warnings)
	}

	// And the text render surfaces it.
	var out strings.Builder
	renderText(cfg, oc, &out)
	if !strings.Contains(out.String(), "WARNING") || !strings.Contains(out.String(), "MRTD") {
		t.Errorf("text render must carry the MRTD-only warning:\n%s", out.String())
	}

	// No warning for the same policy against SNP: MRTD is a TDX concept.
	snpResult := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims:         teetypes.Claims{LaunchDigest: testMRTD},
	}
	snpOC := newOutcome(cfg, &evidence{platform: "snp"}, snpResult, nil, plan)
	if !snpOC.Verified || len(snpOC.Warnings) != 0 {
		t.Errorf("SNP verdict must not carry the TDX warning: verified=%v warnings=%v", snpOC.Verified, snpOC.Warnings)
	}
}

// What decides between rejecting an MRTD-only TDX policy and warning about it
// is whether an operator-pinned CA anchor (--mesh-ca) stands beside the
// measurements — a property of the policy, not of the CLI mode string. Every
// mode, including the empty one --from-file leaves behind, is rejected when
// there is no pinned anchor at all.
func TestTDXMRTDOnlyRejectedWithoutCAAnchor(t *testing.T) {
	for _, mode := range []string{"", "auto", "armtls-cert", "discovery", "attest-pq"} {
		cfg := config{mode: mode, measurements: []string{testMRTD}}
		oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, matchingRTMRs()), nil, mustPlan(t, cfg))
		if oc.Verified {
			t.Errorf("mode %q: an MRTD-only TDX policy with no CA anchor must fail — the measurement pins are the entire trust anchor", mode)
		}
		if !strings.Contains(oc.Error, "UNMEASURED") || !strings.Contains(oc.Error, "deployment-class") {
			t.Errorf("mode %q: Error = %q, want the MRTD-only rejection", mode, oc.Error)
		}
	}

	// Only an operator-pinned anchor downgrades the same condition to a
	// warning. A chain checked against the responder-committed CA (attest-pq's
	// derived anchor) does NOT: the responder chose that CA, so it anchors
	// nothing the operator asked about and the verdict stays deployment-class.
	t.Run("--mesh-ca pinned", func(t *testing.T) {
		plan := mustPlan(t, config{measurements: []string{testMRTD}})
		plan.meshCA = x509.NewCertPool()
		cfg := config{mode: "attest-pq", measurements: []string{testMRTD}}
		oc := newOutcome(cfg, &evidence{platform: "tdx"}, tdxResult(testMRTD, matchingRTMRs()), nil, plan)
		if !oc.Verified {
			t.Fatalf("a pinned-anchor verdict must pass with a warning: %s", oc.Error)
		}
		if len(oc.Warnings) != 1 || !strings.Contains(oc.Warnings[0], "UNMEASURED") {
			t.Fatalf("Warnings = %v, want the MRTD-only warning", oc.Warnings)
		}
	})

	t.Run("responder-committed chain is not an anchor", func(t *testing.T) {
		cfg := config{mode: "attest-pq", measurements: []string{testMRTD}}
		ev := &evidence{platform: "tdx", leafChainDerived: true}
		oc := newOutcome(cfg, ev, tdxResult(testMRTD, matchingRTMRs()), nil, mustPlan(t, cfg))
		if oc.Verified {
			t.Fatal("a responder-chosen chain anchor must not downgrade the MRTD-only rejection")
		}
		if !strings.Contains(oc.Error, "UNMEASURED") || !strings.Contains(oc.Error, "deployment-class") {
			t.Errorf("Error = %q, want the MRTD-only rejection", oc.Error)
		}
	})
}

func TestRTMRPinFlagErrors(t *testing.T) {
	badManifest := filepath.Join(t.TempDir(), "artifacts.json")
	if err := os.WriteFile(badManifest, []byte(`{"files":{"disk.img":"sha256:ab"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		cfg     config
		wantErr string
	}{
		{"rtmr3 not hex", config{expectedRTMR3Hex: strings.Repeat("zz", 48)}, "not hex"},
		{"rtmr3 too short", config{expectedRTMR3Hex: "abcd"}, "want 48"},
		{"rtmr3 too long", config{expectedRTMR3Hex: strings.Repeat("ab", 64)}, "want 48"},
		// RTMR[3] records events extended into a guest whose image the
		// untrusted host chose, so alone it reports "(matched)" while proving
		// nothing about what booted. get-kubeconfig makes the manifest
		// mandatory for the same reason.
		{"rtmr3 without an image pin", config{expectedRTMR3Hex: testRTMR3}, "requires --image-manifest"},
		{"rtmr3 with only a measurement allowlist", config{expectedRTMR3Hex: testRTMR3, measurements: []string{testMRTD}}, "requires --image-manifest"},
		{"manifest missing", config{imageManifest: filepath.Join(t.TempDir(), "absent.json")}, "read image manifest"},
		{"generic artifact-hash manifest", config{imageManifest: badManifest}, "not it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := buildPolicy(tc.cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("buildPolicy error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// The --min-tcb-* floor is re-checked on the verified claims rather than left
// to the engine: an unenforced floor and a met floor render identically.
func TestMinTCBFloorEnforcedOnClaims(t *testing.T) {
	snpLaunch := strings.Repeat("ab", 48)
	snpResult := func(bootloader uint8) *teetypes.VerificationResult {
		return &teetypes.VerificationResult{
			SignatureValid: true,
			Platform:       teetypes.PlatformSNP,
			Claims: teetypes.Claims{
				LaunchDigest: snpLaunch,
				TCB:          teetypes.TcbInfo{Type: "Snp", Bootloader: &bootloader},
			},
		}
	}
	cfg := config{measurements: []string{snpLaunch}, minTCBBootloader: 4}
	plan := mustPlan(t, cfg)

	if oc := newOutcome(cfg, &evidence{platform: "snp"}, snpResult(4), nil, plan); !oc.Verified {
		t.Fatalf("a claim meeting the floor must verify: %s", oc.Error)
	}
	oc := newOutcome(cfg, &evidence{platform: "snp"}, snpResult(3), nil, plan)
	if oc.Verified || !strings.Contains(oc.Error, "below the --min-tcb-bootloader floor") {
		t.Errorf("a claim below the floor must fail: %+v", oc)
	}

	// A floored component the claims do not carry is unenforceable, so it
	// fails closed rather than passing on a nil.
	absent := &teetypes.VerificationResult{
		SignatureValid: true,
		Platform:       teetypes.PlatformSNP,
		Claims:         teetypes.Claims{LaunchDigest: snpLaunch, TCB: teetypes.TcbInfo{Type: "Snp"}},
	}
	if oc := newOutcome(cfg, &evidence{platform: "snp"}, absent, nil, plan); oc.Verified {
		t.Error("a floor against claims carrying no such component must fail closed")
	}
}
