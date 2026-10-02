// Package testutil provides shared helpers for C8s tests.
package testutil

import (
	"context"
	"encoding/json"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
)

// VerifierStub adapts a test callback to an evidence verifier's Verify method.
// It is intended only for tests that inject a cdsconn.PinVerifier.
type VerifierStub localverify.VerifyFunc

// Verify delegates to the stub callback without changing its inputs or results.
func (v VerifierStub) Verify(ctx context.Context, platform string, evidence json.RawMessage, params localverify.Params) (*teetypes.VerificationResult, error) {
	return v(ctx, platform, evidence, params)
}
