package localverify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// IntelMediaDeadline verifies the candidate against a quote enrolled for this target.
func IntelMediaDeadline(ctx context.Context, quote []byte, getter trust.HTTPSGetter, at time.Time) (time.Time, error) {
	input := tdx.TdxEvidence{Quote: base64.StdEncoding.EncodeToString(quote)}
	evidence, err := json.Marshal(input)
	if err != nil {
		return time.Time{}, err
	}
	envelope := teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: evidence}
	policy := Params{TDXTCBStatuses: []teetypes.TdxTcbStatus{teetypes.TdxUpToDate}}
	_, expires, err := verifyTDXStatus(ctx, envelope, policy, getter, at)
	if err != nil {
		return time.Time{}, err
	}
	return pckDeadline(ctx, input, at, *expires)
}

// The initial verification establishes the start of the signed PCK validity window. DCAP exposes a
// verdict at a given instant, and X.509 NotAfter has one-second resolution.
func pckDeadline(ctx context.Context, evidence tdx.TdxEvidence, at, end time.Time) (time.Time, error) {
	valid := func(when time.Time) bool {
		_, err := tdx.VerifyEvidence(evidence, teetypes.VerifyParams{}, tdx.Options{Now: when})
		return err == nil
	}
	if valid(end) {
		return end, ctx.Err()
	}
	low, high := at.Unix(), end.Unix()+1
	for high-low > 1 {
		if err := ctx.Err(); err != nil {
			return time.Time{}, err
		}
		middle := low + (high-low)/2
		if valid(time.Unix(middle, 0)) {
			low = middle
		} else {
			high = middle
		}
	}
	return time.Unix(low, 0).UTC(), ctx.Err()
}
