package taconn

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/localverify"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/armtls"
)

// PinVerifier verifies evidence and enforces the endpoint's identity policy.
// Both discovery and direct armTLS connections use the same verifier.
type PinVerifier interface {
	Verify(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error)
}

// LocalVerifier verifies evidence in-process, including the launch-digest pins
// in Params. Operator clients do not trust a remote service's unsigned verdict.
type LocalVerifier struct{ TDXCollateralProfile string }

func (v LocalVerifier) Verify(ctx context.Context, platform string, evidence json.RawMessage, params localverify.Params) (*teetypes.VerificationResult, error) {
	params.TDXCollateralProfile = v.TDXCollateralProfile
	return localverify.Verify(ctx, platform, evidence, params)
}

// ImagePinVerifier requires a complete image tuple on the verified claims,
// preserving the launch digest, runtime registers, and launch-anchor binding.
// Before matching, it refuses pins that cannot identify a guest on the
// verified platform: a TDX launch digest covers the firmware alone.
type ImagePinVerifier struct {
	Verifier PinVerifier
	Images   []remote.ImagePin
}

func (v ImagePinVerifier) Verify(ctx context.Context, platform string, evidence json.RawMessage, params localverify.Params) (*teetypes.VerificationResult, error) {
	result, err := v.Verifier.Verify(ctx, platform, evidence, params)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("endpoint verifier returned no result")
	}
	if err := requireGuestIdentity(result.Platform.Family(), v.Images); err != nil {
		return nil, fmt.Errorf("endpoint identity: %w", err)
	}
	if err := armtls.EnforceImages(remote.VerifyResponse{Result: *result}, v.Images, teetypes.NormalizePlatform(platform), params.RuntimeExtensions); err != nil {
		return nil, fmt.Errorf("endpoint identity: %w", err)
	}
	return result, nil
}

// requireGuestIdentity refuses pins that leave a guest of the verified family
// unidentified, before any of them is matched.
func requireGuestIdentity(family teetypes.Family, images []remote.ImagePin) error {
	if len(images) == 0 {
		return fmt.Errorf("no image is pinned, so any attested guest would be accepted")
	}
	if err := armtls.RequireImageRegisters(family, images); err != nil {
		return fmt.Errorf("%w: pin it in --image-policy-file", err)
	}
	return nil
}
