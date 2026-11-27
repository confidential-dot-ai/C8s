package localverify

import (
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/google/go-tdx-guest/abi"
	tdxverify "github.com/google/go-tdx-guest/verify"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
)

func TestPCKDeadline(t *testing.T) {
	raw, err := os.ReadFile("testdata/uptodate/quote.bin")
	if err != nil {
		t.Fatal(err)
	}
	quote, err := abi.QuoteToProto(raw)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := tdxverify.ExtractChainFromQuote(quote)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	beforeExpiry := at.Add(time.Hour)
	expires := chain.PCKCertificate.NotAfter
	for _, other := range []time.Time{chain.IntermediateCertificate.NotAfter, chain.RootCertificate.NotAfter} {
		if other.Before(expires) {
			expires = other
		}
	}
	for _, tc := range []struct{ end, want time.Time }{
		{beforeExpiry, beforeExpiry},
		{expires.Add(time.Hour), expires},
	} {
		evidence := tdx.TdxEvidence{Quote: base64.StdEncoding.EncodeToString(raw)}
		got, err := pckDeadline(context.Background(), evidence, at, tc.end)
		if err != nil || !got.Equal(tc.want) {
			t.Fatalf("pckDeadline ending %s = %s, %v; want %s", tc.end, got, err, tc.want)
		}
	}
}
