package localverify

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"
	sigsjson "sigs.k8s.io/json"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/attestation/teeverify"
)

var pcsGetter = func() tdxtrust.HTTPSGetter {
	return &tdxtrust.RetryHTTPSGetter{
		Timeout:       kdsMaxFetchTime,
		MaxRetryDelay: kdsMaxRetryDelay,
		Getter:        &tdxtrust.SimpleHTTPSGetter{},
	}
}

var tdxCollateralTime time.Time

// ParseTDXTCBStatus accepts Intel PCS status names that can appear in a verifier policy.
func ParseTDXTCBStatus(s string) (teetypes.TdxTcbStatus, error) {
	status, err := tdx.ParseTCBStatus(s)
	if err != nil {
		return "", err
	}
	if status == teetypes.TdxRevoked {
		return "", fmt.Errorf("TDX TCB status %s cannot be accepted", status)
	}
	return status, nil
}

type collateralFetch struct {
	ctx   context.Context
	inner tdxtrust.HTTPSGetter

	mu           sync.Mutex
	bodies       map[string][]byte
	lastFetchErr error
}

func verifyOnlineTDX(ctx context.Context, envelope teetypes.AttestationEvidence, p Params) (*teetypes.VerificationResult, *time.Time, error) {
	// Authenticate the quote before fetching collateral for it, so evidence
	// that fails on its own is a verdict and causes no request.
	if _, err := verifyEnvelope(ctx, envelope, p, teeverify.Options{}); err != nil {
		return nil, nil, err
	}
	fetch := &collateralFetch{ctx: ctx, inner: pcsGetter(), bodies: make(map[string][]byte)}
	res, err := verifyEnvelope(ctx, envelope, p, teeverify.Options{TDX: tdx.Options{
		GetCollateral:       true,
		CheckRevocations:    true,
		Getter:              fetch,
		Now:                 tdxCollateralTime,
		AcceptedTCBStatuses: p.TDXTCBStatuses,
	}})
	if err != nil {
		if fetchErr := fetch.failure(); fetchErr != nil {
			return nil, nil, &CollateralError{Err: fetchErr}
		}
		return nil, nil, err
	}
	if res.TCBStatus == nil || !slices.Contains(p.TDXTCBStatuses, res.TCBStatus.TCBStatus) {
		return nil, nil, fmt.Errorf("TDX TCB status not proven to be one of %v", p.TDXTCBStatuses)
	}
	expiresAt, err := fetch.earliestNextUpdate(res.TCBStatus.FMSPC)
	if err != nil {
		return nil, nil, err
	}
	return res, expiresAt, nil
}

// The upstream TDX verifier supplies a background context to its getter.
func (f *collateralFetch) Get(url string) (map[string][]string, []byte, error) {
	header, body, err := tdxtrust.GetWith(f.ctx, f.inner, url)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		f.lastFetchErr = fmt.Errorf("fetch Intel PCS collateral %s: %w", url, err)
		return nil, nil, err
	}
	f.lastFetchErr = nil
	if err := checkSignedEnvelope(url, body); err != nil {
		return nil, nil, err
	}
	f.bodies[url] = body
	return header, body, nil
}

// Intel PCS envelopes contain exactly one signed payload and one signature.
func checkSignedEnvelope(url string, body []byte) error {
	var signed string
	switch {
	case url == pcs.QeIdentityURL():
		signed = "enclaveIdentity"
	case strings.HasPrefix(url, pcs.TcbInfoURL("")):
		signed = "tcbInfo"
	default:
		return nil
	}
	var members map[string]json.RawMessage
	strictErrs, err := sigsjson.UnmarshalStrict(body, &members)
	if err != nil || len(strictErrs) != 0 || len(members) != 2 ||
		members[signed] == nil || members["signature"] == nil {
		return fmt.Errorf("Intel PCS response %s must contain exactly %q and %q once each", url, signed, "signature")
	}
	return nil
}

func (f *collateralFetch) failure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastFetchErr
}

// Read expiry only from the responses authenticated by this verification.
func (f *collateralFetch) earliestNextUpdate(fmspc string) (*time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var tcbInfo pcs.TdxTcbInfo
	tcbURL := pcs.TcbInfoURL(fmspc)
	if err := json.Unmarshal(f.bodies[tcbURL], &tcbInfo); err != nil {
		return nil, fmt.Errorf("read TDX TCB info expiry: %w", err)
	}
	var qeIdentity pcs.QeIdentity
	if err := json.Unmarshal(f.bodies[pcs.QeIdentityURL()], &qeIdentity); err != nil {
		return nil, fmt.Errorf("read TDX QE identity expiry: %w", err)
	}
	next := tcbInfo.TcbInfo.NextUpdate
	if qe := qeIdentity.EnclaveIdentity.NextUpdate; qe.Before(next) {
		next = qe
	}
	crls := 0
	for url, body := range f.bodies {
		if url == tcbURL || url == pcs.QeIdentityURL() {
			continue
		}
		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			return nil, fmt.Errorf("read TDX CRL expiry: %w", err)
		}
		if crl.NextUpdate.Before(next) {
			next = crl.NextUpdate
		}
		crls++
	}
	if crls != 2 {
		return nil, fmt.Errorf("TDX collateral carries %d CRLs, want PCK and root CRLs", crls)
	}
	if next.IsZero() {
		return nil, fmt.Errorf("TDX collateral carries no nextUpdate")
	}
	return &next, nil
}
