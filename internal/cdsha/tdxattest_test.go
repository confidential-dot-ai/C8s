package cdsha

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// TestTDXAttestorRealQuote verifies a real DCAP quote captured on a TDX host.
// Quotes identify a platform, so none is committed: point
// CDSHA_TDX_EVIDENCE at a JSON list of {"evidence":{"quote":"<base64>"}}.
func TestTDXAttestorRealQuote(t *testing.T) {
	path := os.Getenv("CDSHA_TDX_EVIDENCE")
	if path == "" {
		t.Skip("CDSHA_TDX_EVIDENCE not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var batch []struct {
		Evidence struct {
			Quote string `json:"quote"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(raw, &batch); err != nil || len(batch) == 0 {
		t.Fatalf("parse %s: %v", path, err)
	}
	quote, err := base64.StdEncoding.DecodeString(batch[0].Evidence.Quote)
	if err != nil {
		t.Fatal(err)
	}
	// Offline: signature and PCK chain only (collateral needs Intel PCS).
	res, err := tdx.VerifyQuoteBytes(quote, teetypes.VerifyParams{}, teetypes.PlatformTDX, tdx.Options{})
	if err != nil {
		t.Fatalf("genuine quote rejected: %v", err)
	}
	m, err := tdxMeasurement(res.Claims)
	if err != nil || len(m) != 96 {
		t.Fatalf("measurement %q: %v", m, err)
	}
	t.Logf("replica measurement of the captured TD: %s", m)
	// report_data must be a 32-byte binding padded with zeros.
	if c, err := peerClaims(res.Claims); err == nil {
		if string(c.ReportData[:]) != string(res.Claims.ReportData[:48]) || c.Measurement != m {
			t.Fatalf("claims do not reflect the quote: %+v", c)
		}
	} else if !strings.Contains(err.Error(), "peer binding") {
		t.Fatal(err)
	}
	padded := res.Claims
	padded.ReportData = append(append(teetypes.HexBytes{}, res.Claims.ReportData[:48]...), make([]byte, 16)...)
	padded.ReportData[56] = 1
	if _, err := peerClaims(padded); err == nil {
		t.Fatal("report_data with a non-zero tail accepted")
	}
	// Online: Intel PCS collateral and TCB status, as replicas verify peers.
	if os.Getenv("CDSHA_TDX_ONLINE") != "" {
		strict, err := NewTDXAttestor(DefaultTDXTCBStatuses)
		if err != nil {
			t.Fatal(err)
		}
		_, err = strict.Verify(quote)
		t.Logf("default TCB policy: %v", err)
		lenient, err := NewTDXAttestor([]string{"UpToDate", "SWHardeningNeeded", "OutOfDate"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := lenient.Verify(quote); err != nil && !strings.Contains(err.Error(), "peer binding") {
			t.Fatalf("collateral verification: %v", err)
		}
	}
	// Any change to the signed body fails before a claim is read.
	att := TDXAttestor{}
	bad := append([]byte{}, quote...)
	bad[48+200] ^= 1 // inside the TD quote body
	if _, err := att.Verify(bad); err == nil {
		t.Fatal("tampered quote verified")
	}
}
