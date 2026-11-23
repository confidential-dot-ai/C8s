package cdsconn

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/localverify"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/testutil"
)

func TestPinVerifierPreservesEvidencePolicyAndCancellation(t *testing.T) {
	pins, err := refvalues.Load(nodePolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []string{"", nodePolicyPath} {
		t.Run(config, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			evidence := json.RawMessage(`{"quote":"evidence"}`)
			params := localverify.Params{
				VerifyParams: teetypes.VerifyParams{
					ExpectedReportData:   []byte("binding"),
					ExpectedInitDataHash: []byte("init-data"),
					AllowDebug:           true,
					MinTCB:               &teetypes.SnpTcb{},
				},
				Measurements: pins.Digests(),
			}
			called := false
			o := Options{MeasurementsConfig: config, Verifier: testutil.VerifierStub(func(gotCtx context.Context, platform string, gotEvidence json.RawMessage, gotParams localverify.Params) (*teetypes.VerificationResult, error) {
				called = true
				if gotCtx != ctx || platform != "tdx" || !reflect.DeepEqual(gotEvidence, evidence) || !reflect.DeepEqual(gotParams, params) {
					t.Fatal("verifier changed the context, evidence, or verification policy")
				}
				return nil, gotCtx.Err()
			})}
			result, err := o.pinVerifier(pins).Verify(ctx, "tdx", evidence, params)
			if !called || result != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("called=%v, result=%v, error=%v; want canceled verification", called, result, err)
			}
		})
	}
}

func TestPinVerifierPreservesCollateralErrors(t *testing.T) {
	want := &localverify.CollateralError{Err: errors.New("collateral unavailable")}
	for _, config := range []string{"", nodePolicyPath} {
		t.Run(config, func(t *testing.T) {
			o := Options{MeasurementsConfig: config, Verifier: testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
				return nil, want
			})}
			result, err := o.pinVerifier(refvalues.ReferenceValues{}).Verify(context.Background(), "tdx", nil, localverify.Params{})
			var collateral *localverify.CollateralError
			if result != nil || !errors.As(err, &collateral) || collateral != want {
				t.Fatalf("result=%v, error=%v; want the original collateral error", result, err)
			}
		})
	}
}

func TestImagePinVerifierRejectsMixedEntries(t *testing.T) {
	pins, err := refvalues.Load(nodePolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	// Both complete images are trusted, but their launch digest, registers,
	// and anchor cannot be combined independently into a third trusted image.
	pins.Images[1].Digest = bytes.Repeat([]byte{0xd4}, refvalues.DigestSize)
	pins.Images[1].Registers = map[int][]byte{
		1: bytes.Repeat([]byte{0xe5}, refvalues.DigestSize),
		2: bytes.Repeat([]byte{0xf6}, refvalues.DigestSize),
	}
	policy := "sha256:" + strings.Repeat("1", 64)
	for _, tc := range []struct {
		name      string
		digest    int
		registers int
		anchor    int
		policies  []string // extended into RTMR[3] and claimed
		claimed   bool
		want      error
	}{
		{"first image", 0, 0, 0, nil, false, nil},
		{"second image", 1, 1, 1, nil, false, nil},
		{"crossed registers", 0, 1, 0, nil, false, remote.ErrRegistersNotAllowed},
		{"crossed anchor", 0, 0, 1, nil, false, remote.ErrAnchorNotAllowed},
		{"crossed digest", 1, 0, 0, nil, false, remote.ErrRegistersNotAllowed},
		{"claimed policy history", 0, 0, 0, []string{policy}, true, nil},
		{"unclaimed policy history", 0, 0, 0, []string{policy}, false, remote.ErrAnchorNotAllowed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(pins.Images[tc.anchor].Anchor), tc.policies)
			var params localverify.Params
			if tc.claimed {
				params.RuntimeExtensions = tc.policies
			}
			report := &teetypes.VerificationResult{Platform: teetypes.PlatformTDX, SignatureValid: true}
			report.Claims.LaunchDigest = hex.EncodeToString(pins.Images[tc.digest].Digest)
			report.Claims.PlatformData = map[string]any{
				"rtmr_1": hex.EncodeToString(pins.Images[tc.registers].Registers[1]),
				"rtmr_2": hex.EncodeToString(pins.Images[tc.registers].Registers[2]),
				"rtmr_3": hex.EncodeToString(seed[:]),
			}
			o := Options{MeasurementsConfig: nodePolicyPath, Verifier: testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
				return report, nil
			})}
			result, err := o.pinVerifier(pins).Verify(context.Background(), "tdx", nil, params)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
			if tc.want == nil && result != report {
				t.Fatal("successful verification did not retain the verified claims")
			}
			if tc.want != nil && result != nil {
				t.Fatal("rejected image exposed successful verified claims")
			}
		})
	}
}

// A TDX launch digest covers the firmware alone, so a host can boot its own
// kernel under a pinned MRTD. The verifier refuses pins that leave RTMR[1] or
// RTMR[2] unpinned on a verified TDX endpoint, whichever flag supplied them;
// an SNP launch digest is the guest image, so it stands alone.
func TestImagePinVerifierRequiresGuestRegisters(t *testing.T) {
	digest := bytes.Repeat([]byte{0xa1}, refvalues.DigestSize)
	register := func(b byte) []byte { return bytes.Repeat([]byte{b}, refvalues.DigestSize) }
	tdxImage := func(registers map[int][]byte) refvalues.ReferenceValues {
		return refvalues.ReferenceValues{Family: teetypes.FamilyTDX, Images: []remote.ImagePin{{Name: "cds", Digest: digest, Registers: registers}}}
	}
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		pins     refvalues.ReferenceValues
		want     string
	}{
		{"flat digest on tdx", teetypes.PlatformTDX, refvalues.FromFlags([][]byte{digest}, nil), "leaves RTMR[1] unpinned"},
		{"mrtd only", teetypes.PlatformTDX, tdxImage(nil), "leaves RTMR[1] unpinned"},
		{"mrtd and rtmr1", teetypes.PlatformAzTDX, tdxImage(map[int][]byte{1: register(0xb2)}), "leaves RTMR[2] unpinned"},
		{"mrtd and rtmr2", teetypes.PlatformTDX, tdxImage(map[int][]byte{2: register(0xc3)}), "leaves RTMR[1] unpinned"},
		{"mrtd, rtmr1 and rtmr2", teetypes.PlatformTDX, tdxImage(map[int][]byte{1: register(0xb2), 2: register(0xc3)}), ""},
		{"flat digest on snp", teetypes.PlatformSNP, refvalues.FromFlags([][]byte{digest}, nil), ""},
		{"flat digest on az-snp", teetypes.PlatformAzSNP, refvalues.FromFlags([][]byte{digest}, nil), ""},
		{"no verified platform", "", refvalues.FromFlags([][]byte{digest}, nil), "no guest image identity"},
		{"no pins", teetypes.PlatformSNP, refvalues.ReferenceValues{}, "no image is pinned"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := &teetypes.VerificationResult{Platform: tc.platform, SignatureValid: true}
			report.Claims.LaunchDigest = hex.EncodeToString(digest)
			report.Claims.PlatformData = map[string]any{"rtmr_1": hex.EncodeToString(register(0xb2)), "rtmr_2": hex.EncodeToString(register(0xc3))}
			o := Options{Verifier: testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
				return report, nil
			})}
			result, err := o.pinVerifier(tc.pins).Verify(context.Background(), string(tc.platform), nil, localverify.Params{})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Verify = %v, want the pinned guest accepted", err)
				}
				if result != report {
					t.Fatal("successful verification did not retain the verified claims")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify = %v, want a refusal containing %q", err, tc.want)
			}
			if result != nil {
				t.Fatal("a refused pin exposed verified claims")
			}
			if strings.Contains(tc.want, "RTMR") && !strings.Contains(err.Error(), "--image-policy-file") {
				t.Errorf("the refusal must name the flag that fixes it, got %q", err)
			}
		})
	}
}
