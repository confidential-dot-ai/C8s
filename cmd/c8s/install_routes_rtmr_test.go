//go:build !c8s_node

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
)

type resultVerifier struct{ result *teetypes.VerificationResult }

func (v resultVerifier) Verify(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
	return v.result, nil
}

func TestInstallCDSConnEnforcesRTMRs(t *testing.T) {
	launch := bytes.Repeat([]byte{0xa1}, 48)
	pinned := bytes.Repeat([]byte{0xb2}, 48)
	defer func(m, r []string) { installMeasurements, installRegisters = m, r }(installMeasurements, installRegisters)
	installMeasurements = []string{hex.EncodeToString(launch)}
	installRegisters = []string{"1=" + hex.EncodeToString(pinned)}

	o, err := installCDSConn("https://cds")
	if err != nil {
		t.Fatal(err)
	}
	pins, ok := o.Verifier.(registerPinVerifier)
	if !ok {
		t.Fatalf("installCDSConn verifier = %T, want registerPinVerifier", o.Verifier)
	}
	for _, tc := range []struct {
		name     string
		platform string
		rtmr1    []byte
		want     error
	}{
		{"matching RTMR", "tdx", pinned, nil},
		{"mismatched RTMR", "tdx", bytes.Repeat([]byte{0xc3}, 48), remote.ErrRegistersNotAllowed},
		{"SNP ignores RTMRs", "snp", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &teetypes.VerificationResult{Platform: teetypes.PlatformType(tc.platform), SignatureValid: true}
			result.Claims.LaunchDigest = hex.EncodeToString(launch)
			if tc.rtmr1 != nil {
				result.Claims.PlatformData = map[string]any{"rtmr_1": hex.EncodeToString(tc.rtmr1)}
			}
			pins.PinVerifier = resultVerifier{result}
			_, err := pins.Verify(context.Background(), tc.platform, nil, localverify.Params{})
			if !errors.Is(err, tc.want) {
				t.Errorf("Verify(%s) = %v, want %v", tc.name, err, tc.want)
			}
		})
	}
}
