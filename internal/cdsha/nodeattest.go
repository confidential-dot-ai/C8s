package cdsha

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// NodeAttestor uses the node's attestation-api (the same service every c8s
// component uses: attest-proxy socket or URL) to produce and verify TEE
// evidence. Evidence is the service's self-describing envelope
// {platform, evidence}. Verification is the service's /verify verdict,
// enforced fail-closed by remote.EnforceVerdict, plus report_data equality.
//
// The replica measurement is the platform's image identity as c8s pins it:
// TDX "mrtd:rtmr1:rtmr2" (RTMR0 varies with VM shape), SNP the launch
// digest. The Anchor is the launch-key binding: TDX RTMR3, SNP HOST_DATA.
type NodeAttestor struct {
	client remote.Client
}

// NewNodeAttestor talks to the attestation-api at url ("unix:///run/..." or
// "http://127.0.0.1:8400"), with timeout bounding each call. The client
// ignores HTTP_PROXY, which would otherwise choose who answers /verify.
func NewNodeAttestor(url string, timeout time.Duration) NodeAttestor {
	return NodeAttestor{client: remote.NewClientWithHTTP(url, armtls.NewDirectHTTPClient(timeout))}
}

// Evidence implements Attestor. report_data is the 48-byte peer binding, as
// the armTLS path sends it (SNP REPORT_DATA size; TDX zero-pads to 64).
func (a NodeAttestor) Evidence(rd [48]byte) ([]byte, error) {
	resp, err := a.client.Attest(context.Background(), remote.AttestRequest{ReportData: rd[:]})
	if err != nil {
		return nil, fmt.Errorf("attestation-api /attest: %w", err)
	}
	return json.Marshal(resp.Envelope())
}

// Verify implements Attestor. The verdict is checked before any claim is read.
func (a NodeAttestor) Verify(ev []byte) (Claims, error) {
	var env teetypes.AttestationEvidence
	if err := json.Unmarshal(ev, &env); err != nil {
		return Claims{}, fmt.Errorf("peer evidence: %w", err)
	}
	resp, err := a.client.VerifyEnforced(context.Background(), remote.NewVerifyRequest(env, nil, false))
	if err != nil {
		return Claims{}, fmt.Errorf("attestation-api /verify: %w", err)
	}
	return nodeClaims(resp.Result)
}

func nodeClaims(res teetypes.VerificationResult) (Claims, error) {
	if !res.SignatureValid {
		return Claims{}, errors.New("evidence signature not valid")
	}
	rd := res.Claims.ReportData
	if len(rd) < sha512.Size384 {
		return Claims{}, errors.New("report_data shorter than 48 bytes")
	}
	for _, b := range rd[sha512.Size384:] {
		if b != 0 {
			return Claims{}, errors.New("report_data tail is not zero")
		}
	}
	m, anchor, err := nodeIdentity(res.Platform, res.Claims)
	if err != nil {
		return Claims{}, err
	}
	c := Claims{Measurement: m, Anchor: anchor}
	copy(c.ReportData[:], rd[:sha512.Size384])
	return c, nil
}

// ImagePin is the pin-set string for a launch image as a cds-role node's
// launch document describes it: TDX "mrtd:rtmr1:rtmr2", SNP the launch
// digest. It is what NodeAttestor reports as Measurement.
func ImagePin(platform, measurement string, rtmrs map[int]string) (string, error) {
	switch teetypes.NormalizePlatform(platform).Family() {
	case teetypes.FamilyTDX:
		if rtmrs[1] == "" || rtmrs[2] == "" {
			return "", errors.New("TDX image pin needs RTMR[1] and RTMR[2]")
		}
		return strings.ToLower(strings.Join([]string{measurement, rtmrs[1], rtmrs[2]}, ":")), nil
	case teetypes.FamilySNP:
		return strings.ToLower(measurement), nil
	}
	return "", fmt.Errorf("unsupported platform %q", platform)
}

// nodeIdentity derives (measurement, anchor) from verified claims. The
// measurement is the image's ImagePin, so it matches the pins.
func nodeIdentity(platform teetypes.PlatformType, c teetypes.Claims) (string, string, error) {
	launch, err := c.LaunchMeasurement()
	if err != nil {
		return "", "", err
	}
	rtmrs := map[int]string{}
	anchor := hex.EncodeToString(c.InitData)
	if platform.Family() == teetypes.FamilyTDX {
		for i := 1; i <= 3; i++ {
			r, err := c.RTMR(i)
			if err != nil {
				return "", "", err
			}
			rtmrs[i] = hex.EncodeToString(r)
		}
		anchor = rtmrs[3]
	}
	m, err := ImagePin(string(platform), hex.EncodeToString(launch), rtmrs)
	return m, anchor, err
}
