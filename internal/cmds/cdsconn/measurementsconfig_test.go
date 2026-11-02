package cdsconn

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

const nodePolicyPath = "../../../internal/testdata/node-identities.json"

func TestOperatorCLIConfigRejectsDowngrades(t *testing.T) {
	o := Options{URL: "https://cds.example", MeasurementsConfig: nodePolicyPath, OperatorKey: writeTestKey(t)}
	pins, err := o.loadPins()
	if err != nil || len(pins.Images) != 2 || len(pins.Images[0].Anchor) == 0 {
		t.Fatalf("full policy lost: %v", err)
	}
	if _, err := o.Signer(); err != nil {
		t.Fatalf("full policy did not satisfy write pinning requirement: %v", err)
	}
	for _, cfg := range []Options{
		{MeasurementsConfig: nodePolicyPath, Measurements: []string{"ab"}},
		{MeasurementsConfig: nodePolicyPath, MeasurementsFile: "measurements.txt"},
		{MeasurementsConfig: "missing-file"},
	} {
		if _, err := cfg.loadPins(); err == nil {
			t.Fatal("invalid or mixed config fell back to flat policy")
		}
	}
	o.URL, o.Insecure = "http://cds.example", true
	if _, err := o.HTTPClient(context.Background()); err == nil {
		t.Fatal("plaintext silently ignored the operator identity policy")
	}
}

func TestOperatorCLIVerifierRejectsAgentAndCrossedTuple(t *testing.T) {
	all, err := refvalues.Load(nodePolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	pins := refvalues.ReferenceValues{Family: all.Family, Images: all.Images[:1]}
	server := pins.Images[0]
	var report *teetypes.VerificationResult
	o := Options{MeasurementsConfig: nodePolicyPath, Verifier: testutil.VerifierStub(func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		return report, nil
	})}
	verify := o.pinVerifier(pins)
	for _, test := range []struct {
		name     string
		key      []byte
		register []byte
		accept   bool
	}{
		{"server", server.Anchor, server.Registers[1], true},
		{"agent same image", all.Images[1].Anchor, server.Registers[1], false},
		{"server wrong image registers", server.Anchor, server.Registers[2], false},
	} {
		t.Run(test.name, func(t *testing.T) {
			report = &teetypes.VerificationResult{Platform: teetypes.PlatformTDX, SignatureValid: true}
			report.Claims.LaunchDigest = hex.EncodeToString(server.Digest)
			report.Claims.InitData = testutil.TDXLaunchBinding(test.key)
			report.Claims.PlatformData = map[string]any{
				"rtmr_1": hex.EncodeToString(test.register),
				"rtmr_2": hex.EncodeToString(server.Registers[2]),
				"rtmr_3": hex.EncodeToString(runtimemeasure.Zero[:]),
			}
			_, err := verify.Verify(context.Background(), "tdx", nil, localverify.Params{})
			if (err == nil) != test.accept {
				t.Fatalf("accept=%v, error=%v", test.accept, err)
			}
		})
	}
	report = nil
	if _, err := verify.Verify(context.Background(), "tdx", nil, localverify.Params{}); err == nil {
		t.Fatal("nil verified claims accepted")
	}
}
