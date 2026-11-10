package armtls

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/google/go-sev-guest/abi"
)

// NativeEvidenceVerifier is the cryptographic dependency of NativeVerifier.
// Its result still passes all native policy gates, including collateral,
// binding, nonmigration and caller pins. Production uses VerifyEnvelope.
type NativeEvidenceVerifier func(
	context.Context,
	teetypes.AttestationEvidence,
	teetypes.VerifyParams,
	teeverify.Options,
) (*teetypes.VerificationResult, error)

// NativeVerifier is immutable after construction and safe to share. It accepts
// only native VCEK SNP and TDX; no remote JSON verdict can authorize a peer.
type NativeVerifier struct {
	floor  teetypes.SnpTcb
	engine NativeEvidenceVerifier
	active chan struct{}
}

// ErrNativeVerifierBusy reports local admission pressure, not rejected evidence.
var ErrNativeVerifierBusy = errors.New("native attestation: verification capacity exhausted")

// ErrNativeCollateralUnavailable means vendor collateral could not be fetched.
// It is an availability failure, never evidence that a peer is authorized.
var ErrNativeCollateralUnavailable = errors.New("native attestation: collateral unavailable")

const nativeVerificationCapacity = 4

func NewNativeVerifier(floor teetypes.SnpTcb) (*NativeVerifier, error) {
	return NewNativeVerifierWithEngine(floor, teeverify.VerifyEnvelope)
}

// NewNativeVerifierWithEngine permits per-instance cryptographic fixtures in
// tests. It is never selected by launch configuration or environment variables.
func NewNativeVerifierWithEngine(
	floor teetypes.SnpTcb,
	engine NativeEvidenceVerifier,
) (*NativeVerifier, error) {
	if floor == (teetypes.SnpTcb{}) || floor.FMC != nil || engine == nil {
		return nil, errors.New("native attestation: explicit nonzero four-component SNP floor and verifier required")
	}
	return &NativeVerifier{
		floor:  floor,
		engine: engine,
		active: make(chan struct{}, nativeVerificationCapacity),
	}, nil
}

func (v *NativeVerifier) VerifyEvidence(
	ctx context.Context,
	evidence teetypes.AttestationEvidence,
	policy remote.Policy,
) (remote.VerifyResponse, error) {
	return v.VerifyEvidenceWithRuntimeLog(ctx, evidence, policy, nil)
}

func (v *NativeVerifier) VerifyEvidenceWithRuntimeLog(
	ctx context.Context,
	evidence teetypes.AttestationEvidence,
	policy remote.Policy,
	claimed []string,
) (remote.VerifyResponse, error) {
	if policy.AllowDebug || len(claimed) > MaxRuntimeExtensions {
		return remote.VerifyResponse{}, fmt.Errorf("%w: native policy forbids debug and unbounded runtime logs", ErrPolicyViolation)
	}
	if policy.MinTcb != nil && evidence.Platform != teetypes.PlatformSNP {
		return remote.VerifyResponse{}, remote.ErrMinTcbNotAllowed
	}
	response, err := v.verify(ctx, evidence, teetypes.VerifyParams{
		ExpectedReportData:   policy.ExpectedReportData,
		ExpectedInitDataHash: policy.ExpectedInitDataHash,
		MinTCB:               policy.MinTcb,
	})
	if err != nil {
		return remote.VerifyResponse{}, err
	}
	policy.Images = acceptReplayed(policy.Images)
	if err := remote.EnforcePinsWithRuntimeLog(response, policy, evidence, claimed); err != nil {
		return remote.VerifyResponse{}, err
	}
	return response, nil
}

func (v *NativeVerifier) VerifyEnforced(
	ctx context.Context,
	request remote.VerifyRequest,
) (remote.VerifyResponse, error) {
	params := teetypes.VerifyParams{}
	if request.Params != nil {
		p := request.Params
		if p.AllowDebug != nil && *p.AllowDebug {
			return remote.VerifyResponse{}, fmt.Errorf("%w: native debug policy forbidden", ErrPolicyViolation)
		}
		params.ExpectedReportData = p.ExpectedReportData
		params.ExpectedInitDataHash = p.ExpectedInitDataHash
		params.MinTCB = p.MinTcb
	}
	response, err := v.verify(ctx, teetypes.AttestationEvidence{
		Platform: request.Platform,
		Evidence: request.Evidence,
	}, params)
	if err != nil {
		return remote.VerifyResponse{}, err
	}
	if err := remote.EnforceVerdict(request, response); err != nil {
		return remote.VerifyResponse{}, err
	}
	return response, nil
}

func (v *NativeVerifier) verify(
	ctx context.Context,
	evidence teetypes.AttestationEvidence,
	params teetypes.VerifyParams,
) (remote.VerifyResponse, error) {
	var snpReport []byte
	if v == nil || v.engine == nil || v.active == nil || v.floor == (teetypes.SnpTcb{}) ||
		len(evidence.Evidence) > teeverify.MaxEvidenceSize || len(params.ExpectedReportData) != 48 {
		return remote.VerifyResponse{}, fmt.Errorf("%w: bounded native evidence, explicit floor and 48-byte binding required", ErrInvalidReport)
	}
	switch evidence.Platform {
	case teetypes.PlatformSNP:
		var err error
		snpReport, err = requireVCEK(evidence.Evidence)
		if err != nil {
			return remote.VerifyResponse{}, err
		}
		floor := v.floor
		if p := params.MinTCB; p != nil {
			if p.FMC != nil {
				return remote.VerifyResponse{}, remote.ErrMinTcbNotAllowed
			}
			floor.Bootloader = max(floor.Bootloader, p.Bootloader)
			floor.Tee = max(floor.Tee, p.Tee)
			floor.Snp = max(floor.Snp, p.Snp)
			floor.Microcode = max(floor.Microcode, p.Microcode)
		}
		params.MinTCB = &floor
	case teetypes.PlatformTDX:
		if params.MinTCB != nil {
			return remote.VerifyResponse{}, remote.ErrMinTcbNotAllowed
		}
	default:
		return remote.VerifyResponse{}, remote.ErrUnsupportedPlatform
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return remote.VerifyResponse{}, err
	}
	// Reject saturation without allocating a waiter or starting vendor I/O.
	// The owning cluster component retains this verifier across handshakes.
	select {
	case v.active <- struct{}{}:
		defer func() { <-v.active }()
	default:
		return remote.VerifyResponse{}, ErrNativeVerifierBusy
	}
	if err := ctx.Err(); err != nil {
		return remote.VerifyResponse{}, err
	}
	fetch := newNativeCollateral(ctx, time.Now())
	defer fetch.client.CloseIdleConnections()
	result, err := v.engine(ctx, evidence, params, teeverify.Options{
		SNP: snp.Options{CheckRevocations: true, Getter: nativeSNPFetch{fetch}},
		TDX: tdx.Options{
			CheckRevocations:    true,
			GetCollateral:       true,
			Getter:              nativeTDXFetch{fetch},
			Now:                 fetch.now,
			AcceptedTCBStatuses: []teetypes.TdxTcbStatus{teetypes.TdxUpToDate},
		},
	})
	if ctx.Err() != nil {
		return remote.VerifyResponse{}, ctx.Err()
	}
	if err != nil {
		// Some SDK layers format getter errors with %v. The per-verification
		// getter records transport failures so that loss cannot turn a vendor
		// outage into an evidence-rejection response.
		if fetch.unavailable.Load() {
			return remote.VerifyResponse{}, fmt.Errorf("%w: %v", ErrNativeCollateralUnavailable, err)
		}
		return remote.VerifyResponse{}, fmt.Errorf("%w: native hardware verification: %w", ErrInvalidReport, err)
	}
	if result == nil || !result.SignatureValid || result.Platform != evidence.Platform ||
		!result.CollateralVerified || result.ReportDataMatch == nil || !*result.ReportDataMatch ||
		(len(params.ExpectedInitDataHash) > 0 && (result.InitDataMatch == nil || !*result.InitDataMatch)) {
		return remote.VerifyResponse{}, fmt.Errorf("%w: complete native signature, collateral and binding required", ErrInvalidReport)
	}
	// The SDK floors REPORTED_TCB/CURRENT_TCB, but not the signed LAUNCH_TCB
	// at ABI 0x1f0. Updating firmware after an older launch must not clear it.
	if snpReport != nil {
		floor := params.MinTCB
		if snpReport[0x1f0] < floor.Bootloader || snpReport[0x1f1] < floor.Tee || snpReport[0x1f6] < floor.Snp || snpReport[0x1f7] < floor.Microcode {
			return remote.VerifyResponse{}, fmt.Errorf("%w: SNP launch firmware is below the approved floor", ErrPolicyViolation)
		}
	}
	if evidence.Platform == teetypes.PlatformTDX && (result.TCBStatus == nil ||
		result.TCBStatus.CollateralExpired || result.TCBStatus.TCBStatus != teetypes.TdxUpToDate) {
		return remote.VerifyResponse{}, fmt.Errorf("%w: fresh UpToDate TDX collateral required", ErrPolicyViolation)
	}
	if err := EnforceNonMigratable(result); err != nil {
		return remote.VerifyResponse{}, err
	}
	return remote.VerifyResponse{Result: *result}, nil
}

// The pinned SNP SDK selects the ASK CRL even for VLEK. Until its ASVK path is
// qualified, reject that signer rather than claim its revocation was checked.
func requireVCEK(evidence json.RawMessage) ([]byte, error) {
	var envelope snp.SnpEvidence
	if err := json.Unmarshal(evidence, &envelope); err != nil {
		return nil, fmt.Errorf("%w: SNP envelope", ErrInvalidReport)
	}
	raw, err := base64.StdEncoding.DecodeString(envelope.AttestationReport)
	if err != nil || len(raw) != abi.ReportSize {
		return nil, fmt.Errorf("%w: SNP report encoding", ErrInvalidReport)
	}
	// Four-component floors do not cover Turin's FMC component. V3+ reports
	// carry the CPU family at this ABI offset; the SDK also rejects Turin VCEKs.
	if raw[0] >= 3 && raw[0x188] >= 0x1a {
		return nil, fmt.Errorf("%w: SNP Turin/FMC is not qualified", ErrPolicyViolation)
	}
	info, err := abi.ReportSignerInfo(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: SNP signer", ErrInvalidReport)
	}
	signer, err := abi.ParseSignerInfo(info)
	if err != nil || signer.SigningKey != abi.VcekReportSigner {
		return nil, fmt.Errorf("%w: only native SNP VCEK endorsements are qualified", ErrPolicyViolation)
	}
	return raw, nil
}
