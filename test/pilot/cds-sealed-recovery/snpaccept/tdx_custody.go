//go:build linux

package snpaccept

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/google/go-tdx-guest/verify/trust"
)

// IntelCollateral carries public certificate/CRL/TCB responses only. The
// verifier retains its bundled Intel trust root and requires current collateral.
// HTTP headers are retained because Intel's certificate chains use them.
type IntelResponse struct {
	Headers map[string][]string `json:"headers"`
	Body    []byte              `json:"body"`
}
type IntelCollateral map[string]IntelResponse

func (c IntelCollateral) Get(url string) (map[string][]string, []byte, error) {
	r, ok := c[url]
	if !ok {
		return nil, nil, fmt.Errorf("missing Intel collateral for %s", url)
	}
	return r.Headers, r.Body, nil
}

func VerifyTDXCustody(q *CustodyRequest, launch []byte, pins runtimemeasure.ImageIdentity, collateral trust.HTTPSGetter) error {
	if q == nil || q.Family != "tdx" || len(q.Nonce) != overenc.SessionIDBytes || len(q.PublicKey) != overenc.XWingEKBytes || len(q.Report) == 0 || len(q.Report) > 64<<10 || len(launch) == 0 || pins == nil || pins.Family() != teetypes.FamilyTDX {
		return errors.New("bounded TDX recipient and independent image/launch pins required")
	}
	binding := custodyBinding(*q)
	result, err := tdx.VerifyQuoteBytes(q.Report, teetypes.VerifyParams{ExpectedReportData: binding[:]}, teetypes.PlatformTDX,
		tdx.Options{CheckRevocations: true, GetCollateral: true, Getter: collateral})
	if err != nil {
		return err
	}
	if err = pins.Verify(result); err != nil {
		return err
	}
	return runtimemeasure.VerifyBinding(result, launch, nil)
}

// DelegateTDX is enabled only by an independent TDX image manifest baked into
// this custodian's immutable image. The host request supplies no image policy,
// trusted root, verification clock, or relaxed TCB status. TDX has no sealing
// role: the existing SNP hardware root protects the durable custody copy.
func (h *Hardware) DelegateTDX(ctx context.Context, p Parameters, copy *CustodyCopy, q *CustodyRequest, collateral IntelCollateral) (*CustodyGrant, error) {
	if h.TDXRecipient == nil {
		return nil, errors.New("TDX delegation is not in this measured custodian image")
	}
	var signer ed25519.PrivateKey
	var wrap []byte
	var err error
	if copy == nil {
		signer, wrap, err = h.material(ctx, p)
	} else {
		signer, wrap, err = h.copyMaterial(ctx, *copy)
	}
	if err != nil {
		return nil, err
	}
	defer clear(signer)
	defer clear(wrap)
	launch, err := h.cdsLaunch(signer.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	if err = VerifyTDXCustody(q, launch, h.TDXRecipient, collateral); err != nil {
		return nil, err
	}
	return sealCustody(*q, signer, wrap)
}
