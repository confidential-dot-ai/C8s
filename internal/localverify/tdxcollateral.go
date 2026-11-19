package localverify

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

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

// checkSignedEnvelope requires a TCB info or QE identity response to hold
// exactly the signed object and its signature, each once. Only those two members are
// covered by Intel's signature, so nothing else may reach a decoder.
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
	malformed := fmt.Errorf("response %s from Intel PCS is not a signed %s object", url, signed)
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return malformed
	}
	seen := make(map[string]bool)
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return malformed
		}
		if (key != signed && key != "signature") || seen[key] {
			return fmt.Errorf("unexpected member %q in Intel PCS response %s", key, url)
		}
		seen[key] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return malformed
		}
	}
	if _, err := dec.Token(); err != nil || len(seen) != 2 {
		return malformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return malformed
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
