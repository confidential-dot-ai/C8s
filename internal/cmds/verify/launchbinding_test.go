package verify

import (
	"context"
	"encoding/hex"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// Every c8s verifier of a TDX launch binding reads one TDX evidence the same
// way: MRCONFIGID commits the launch file and RTMR[3] starts at zero, so a
// file digest extended into RTMR[3] binds nothing anywhere.
func TestTDXLaunchBindingEveryVerifier(t *testing.T) {
	file := approverKey(t)
	pubPath := filepath.Join(t.TempDir(), "operator.pub")
	if err := os.WriteFile(pubPath, file, 0o600); err != nil {
		t.Fatal(err)
	}
	reg := hexBytes(t)
	image := remote.ImagePin{Name: "node", Digest: reg(testMRTD), Registers: map[int][]byte{1: reg(testRTMR1), 2: reg(testRTMR2)}}
	anchored, launchFile := image, image
	launchFile.Registers = maps.Clone(image.Registers)
	anchored.Anchor, launchFile.LaunchFile = file, file

	verdict := func(oc Outcome) error {
		if !oc.Verified {
			return errors.New(oc.Error)
		}
		return nil
	}
	verifiers := []struct {
		name   string
		verify func(*testing.T, *teetypes.VerificationResult) error
	}{
		{"c8s verify --operator-pkey", func(t *testing.T, r *teetypes.VerificationResult) error {
			cfg := config{imageManifest: writeTestManifest(t), operatorPubkey: pubPath}
			return verdict(newOutcome(cfg, &evidence{platform: "tdx"}, r, nil, mustPlan(t, cfg)))
		}},
		{"c8s verify --image-policy-file approver_key", func(t *testing.T, r *teetypes.VerificationResult) error {
			cfg := config{measurementsConfig: writeImagePolicy(t, "node.json", refvalues.ReferenceValues{Family: teetypes.FamilyTDX, Images: []remote.ImagePin{anchored}})}
			return verdict(newOutcome(cfg, &evidence{platform: "tdx"}, r, nil, mustPlan(t, cfg)))
		}},
		{"armtls launch-file pin", func(_ *testing.T, r *teetypes.VerificationResult) error {
			return armtls.EnforceImages(remote.VerifyResponse{Result: *r}, []remote.ImagePin{launchFile}, teetypes.PlatformTDX, nil)
		}},
		{"get-kubeconfig gate", func(t *testing.T, r *teetypes.VerificationResult) error {
			exp, err := guestverify.PolicyFor(writeTestManifest(t), file, nil)
			if err != nil {
				t.Fatal(err)
			}
			orig := guestverify.VerifyEnvelope
			t.Cleanup(func() { guestverify.VerifyEnvelope = orig })
			guestverify.VerifyEnvelope = func([]byte, teetypes.VerifyParams) (*teetypes.VerificationResult, error) { return r, nil }
			_, err = guestverify.VerifyEvidence([]byte(`{"platform":"tdx","evidence":{}}`), nil, exp)
			return err
		}},
		{"in-guest launch-file self-check", func(t *testing.T, r *teetypes.VerificationResult) error {
			stub := mockapi.New(t)
			stub.SetPlatform(teetypes.PlatformTDX)
			v := mockapi.PassingVerdict(testMRTD)
			v.Claims.InitData, v.Claims.PlatformData = r.Claims.InitData, r.Claims.PlatformData
			stub.SetVerdict(v)
			_, err := credrelease.VerifyMeasuredLaunchFile(context.Background(), stub.URL(), file)
			return err
		}},
	}

	zero := make([]byte, 48)
	for _, ev := range []struct {
		name         string
		mrconfigid   []byte
		rtmr3        []byte
		wantAccepted bool
	}{
		{"MRCONFIGID binds the file, RTMR[3] zero", testutil.TDXLaunchBinding(file), zero, true},
		{"file digest in RTMR[3], MRCONFIGID zero", zero, testutil.RTMR3ExtendedWithFileDigest(file), false},
		{"file digest in RTMR[3] beside the binding", testutil.TDXLaunchBinding(file), testutil.RTMR3ExtendedWithFileDigest(file), false},
	} {
		for _, v := range verifiers {
			t.Run(ev.name+"/"+v.name, func(t *testing.T) {
				r := operatorResult(ev.mrconfigid, hex.EncodeToString(ev.rtmr3))
				r.ReportDataMatch = new(true)
				if err := v.verify(t, r); (err == nil) != ev.wantAccepted {
					t.Errorf("verify = %v, want accepted %v", err, ev.wantAccepted)
				}
			})
		}
	}
}
