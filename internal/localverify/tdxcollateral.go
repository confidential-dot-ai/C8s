package localverify

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	tdxtrust "github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// pcsGetter builds the network getter for Intel PCS collateral; a variable so
// a test can serve recorded collateral and prove what reaches the network.
var pcsGetter = func() tdxtrust.HTTPSGetter {
	return &tdxtrust.RetryHTTPSGetter{
		Timeout:       kdsMaxFetchTime,
		MaxRetryDelay: kdsMaxRetryDelay,
		Getter:        &tdxtrust.SimpleHTTPSGetter{},
	}
}

// tdxCollateralTime is the time TDX collateral is checked at; zero means now.
// Tests pin it inside the validity window of recorded collateral.
var tdxCollateralTime time.Time

// TDXCollateral describes the Intel PCS collateral a TDX TCB status check
// matched the quote against.
type TDXCollateral struct {
	// NextUpdate is the earliest nextUpdate of the TCB info, QE identity,
	// PCK CRL and root CRL.
	NextUpdate time.Time
}

// ParseTDXTCBStatus returns the TCB status a TDX TCB status check may accept,
// in Intel PCS spelling. Revoked is never acceptable.
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

// collateralFetch fetches Intel PCS collateral within ctx, which
// attestation-go's TDX verifier does not pass to its getter. It keeps each
// response, so the collateral's expiry can be read once the verifier has
// checked its signatures, and the first failure, so an unreachable PCS is
// told apart from a rejected quote.
type collateralFetch struct {
	ctx   context.Context
	inner tdxtrust.HTTPSGetter

	mu     sync.Mutex
	bodies map[string][]byte
	err    error
}

func newCollateralFetch(ctx context.Context) *collateralFetch {
	return &collateralFetch{ctx: ctx, inner: pcsGetter(), bodies: make(map[string][]byte)}
}

// Get implements tdxtrust.HTTPSGetter. It deliberately does not implement
// GetContext: the verifier would call that with a background context.
func (f *collateralFetch) Get(url string) (map[string][]string, []byte, error) {
	header, body, err := tdxtrust.GetWith(f.ctx, f.inner, url)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		if f.err == nil {
			f.err = fmt.Errorf("fetch Intel PCS collateral %s: %w", url, err)
		}
		return nil, nil, err
	}
	f.bodies[url] = body
	return header, body, nil
}

// failure returns the first fetch error, nil when every fetch succeeded.
func (f *collateralFetch) failure() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

// collateral reads the earliest expiry of the four PCS responses: TCB info,
// QE identity, PCK CRL and root CRL. Call it only after verification succeeds.
func (f *collateralFetch) collateral(status *teetypes.DcapVerificationStatus) (*TDXCollateral, error) {
	if status == nil {
		return nil, fmt.Errorf("TDX verifier reported no TCB status")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var tcbInfo pcs.TdxTcbInfo
	if err := json.Unmarshal(f.bodies[pcs.TcbInfoURL(status.FMSPC)], &tcbInfo); err != nil {
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
		if url == pcs.TcbInfoURL(status.FMSPC) || url == pcs.QeIdentityURL() {
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
	return &TDXCollateral{NextUpdate: next}, nil
}

// tdxOptions configures attestation-go to check TDX evidence against fresh
// collateral fetched by fetch: TCB info, QE identity and both CRLs.
func tdxOptions(fetch *collateralFetch, accepted []teetypes.TdxTcbStatus) tdx.Options {
	return tdx.Options{
		GetCollateral:       true,
		CheckRevocations:    true,
		Getter:              fetch,
		Now:                 tdxCollateralTime,
		AcceptedTCBStatuses: accepted,
	}
}
