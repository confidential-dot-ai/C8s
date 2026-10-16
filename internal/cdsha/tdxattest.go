package cdsha

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// TDXAttestor produces evidence from the TD's own DCAP quote (configfs-tsm)
// and verifies peers' quotes with attestation-go: quote signature, PCK chain
// to the Intel root, and TCB collateral from Intel PCS.
//
// A replica's measurement is hex(SHA-384(MRTD || RTMR1 || RTMR2)): firmware,
// kernel and command line (which carries the dm-verity root). RTMR0 varies
// with the VM shape and is left out, as c8s pins do. RTMR3 holds the launch
// key the measured initrd extended into it; it is the Anchor, and peers must
// match ours exactly.
type TDXAttestor struct {
	Options tdx.Options
}

// DefaultTDXTCBStatuses are the platform TCB statuses accepted by default.
var DefaultTDXTCBStatuses = []string{string(teetypes.TdxUpToDate), string(teetypes.TdxSWHardeningNeeded)}

// NewTDXAttestor verifies with collateral fetched from Intel PCS, accepting
// the given TCB statuses (Revoked never is).
func NewTDXAttestor(statuses []string) (TDXAttestor, error) {
	var accepted []teetypes.TdxTcbStatus
	for _, s := range statuses {
		st, err := tdx.ParseTCBStatus(s)
		if err != nil {
			return TDXAttestor{}, err
		}
		accepted = append(accepted, st)
	}
	if len(accepted) == 0 {
		return TDXAttestor{}, errors.New("tdx: at least one accepted TCB status is required")
	}
	return TDXAttestor{Options: tdx.Options{
		GetCollateral:       true,
		Getter:              trust.DefaultHTTPSGetter(),
		AcceptedTCBStatuses: accepted,
	}}, nil
}

// Evidence implements Attestor: a raw quote whose REPORTDATA is rd followed
// by 16 zero bytes. Works only inside a TD.
func (TDXAttestor) Evidence(rd [48]byte) ([]byte, error) {
	qp, err := client.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("tdx quote provider: %w", err)
	}
	var full [64]byte
	copy(full[:], rd[:])
	return client.GetRawQuote(qp, full)
}

// Verify implements Attestor. The quote is verified before any field of it
// is read.
func (a TDXAttestor) Verify(ev []byte) (Claims, error) {
	res, err := tdx.VerifyQuoteBytes(ev, teetypes.VerifyParams{}, teetypes.PlatformTDX, a.Options)
	if err != nil {
		return Claims{}, err
	}
	return peerClaims(res.Claims)
}

func peerClaims(vc teetypes.Claims) (Claims, error) {
	rd := vc.ReportData
	if len(rd) != 64 || !bytes.Equal(rd[48:], make([]byte, 16)) {
		return Claims{}, errors.New("tdx report_data is not a 48-byte peer binding")
	}
	m, err := tdxMeasurement(vc)
	if err != nil {
		return Claims{}, err
	}
	rtmr3, err := vc.RTMR(3)
	if err != nil {
		return Claims{}, err
	}
	c := Claims{Measurement: m, Anchor: hex.EncodeToString(rtmr3)}
	copy(c.ReportData[:], rd[:48])
	return c, nil
}

func tdxMeasurement(c teetypes.Claims) (string, error) {
	mrtd, err := c.LaunchMeasurement()
	if err != nil {
		return "", err
	}
	h := sha512.New384()
	h.Write(mrtd)
	for i := 1; i <= 2; i++ {
		r, err := c.RTMR(i)
		if err != nil {
			return "", err
		}
		h.Write(r)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func init() {
	attestors["tdx"] = func(o AttestorOptions) (Attestor, error) { return NewTDXAttestor(o.TDXTCBStatuses) }
}
