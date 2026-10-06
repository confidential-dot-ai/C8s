package cdsconn

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
)

// PinVerifier verifies evidence and enforces the endpoint's identity policy.
// Both discovery and direct ARmTLS connections use the same verifier.
type PinVerifier interface {
	Verify(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error)
}

// LocalVerifier verifies evidence in-process, including the launch-digest pins
// in Params. Operator clients do not trust a remote service's unsigned verdict.
type LocalVerifier struct{}

func (LocalVerifier) Verify(ctx context.Context, platform string, evidence json.RawMessage, params localverify.Params) (*teetypes.VerificationResult, error) {
	return localverify.Verify(ctx, platform, evidence, params)
}

// ImagePinVerifier requires a complete image tuple on the verified claims,
// preserving the launch digest, runtime registers, and launch-anchor binding.
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
	if err := remote.EnforceImages(remote.VerifyResponse{Result: *result}, v.Images, teetypes.NormalizePlatform(platform)); err != nil {
		return nil, fmt.Errorf("endpoint identity: %w", err)
	}
	return result, nil
}
