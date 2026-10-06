package verify

import (
	"context"
	"errors"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// verifyInProcess verifies already-gathered evidence with the shared engine
// (internal/localverify) and maps its error classes onto this command's exit
// codes: collateral unavailable = exit 3, any other rejection = a security
// verdict (exit 2). The --measurements pin is not passed down — newOutcome
// enforces it, so a pin failure still renders the rejected measurement.
// --init-data goes the other way: the engine binds it per platform (see
// internal/localverify Params.ExpectedInitDataHash), so it is passed down and
// a mismatch is the engine's refusal.
//
// MinTCB is passed here AND re-checked in newOutcome (enforceMinTCB): the
// engine consumes it on the SNP path only, and silently drops it on TDX.
func verifyInProcess(ctx context.Context, ev *evidence, policy *armtls.VerifyPolicy, initDataHash []byte, minTCB *teetypes.SnpTcb) (*teetypes.VerificationResult, error) {
	res, err := localverify.Verify(ctx, ev.platform, ev.rawEvidence, localverify.Params{
		ExpectedReportData:   ev.erd,
		ExpectedInitDataHash: initDataHash,
		AllowDebug:           policy.Policy.AllowDebug,
		MinTCB:               minTCB,
	})
	if err != nil {
		if _, ok := errors.AsType[*localverify.CollateralError](err); ok {
			return nil, &connectError{err: err}
		}
		return nil, &securityError{err: err}
	}
	return res, nil
}
