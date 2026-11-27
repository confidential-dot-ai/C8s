package verify

import (
	"context"
	"errors"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/localverify"
)

var verifyLocally = localverify.VerifyWithCollateralExpiry

// The CLI enforces launch pins after verification so it can report a rejected measurement.
func verifyInProcess(ctx context.Context, ev *evidence, plan *verifyPlan, minTCB *teetypes.SnpTcb) (*teetypes.VerificationResult, *time.Time, error) {
	res, expiresAt, err := verifyLocally(ctx, ev.platform, ev.rawEvidence, localverify.Params{
		ExpectedReportData:   ev.erd,
		ExpectedInitDataHash: plan.initDataHash,
		AllowDebug:           plan.policy.Policy.AllowDebug,
		MinTCB:               minTCB,
		TDXTCBStatuses:       plan.tdxTCBStatuses,
		TDXCollateralProfile: plan.tdxCollateralProfile,
	})
	if err != nil {
		if _, ok := errors.AsType[*localverify.CollateralError](err); ok {
			return nil, nil, &connectError{err: err}
		}
		return nil, nil, &securityError{err: err}
	}
	return res, expiresAt, nil
}
