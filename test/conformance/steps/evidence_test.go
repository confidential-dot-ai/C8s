package steps

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/snp"
	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/cucumber/godog"
	"github.com/google/go-tdx-guest/testing/testdata"
)

func envelopeOf(t *testing.T, platform teetypes.PlatformType, evidence any) []byte {
	t.Helper()
	ev, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(teetypes.AttestationEvidence{Platform: platform, Evidence: ev})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// The edit changes the launch measurement and nothing else: the rest of the
// report or quote survives the round trip through its ABI byte for byte.
func TestWithMeasurementEditsOnlyTheMeasurement(t *testing.T) {
	mock := make([]byte, snp.ReportSize) // as the kind mock issues it
	mock[0], mock[0x0A] = 0x02, 0x03
	for _, tc := range []struct {
		name     string
		platform teetypes.PlatformType
		raw      []byte
		offset   int
		evidence func(b64 string) any
		read     func(t *testing.T, ev json.RawMessage) string
	}{
		{"snp", teetypes.PlatformSNP, mock, 0x90,
			func(b string) any { return snp.SnpEvidence{AttestationReport: b} },
			func(t *testing.T, ev json.RawMessage) string {
				var e snp.SnpEvidence
				if err := json.Unmarshal(ev, &e); err != nil {
					t.Fatal(err)
				}
				return e.AttestationReport
			}},
		{"tdx v4", teetypes.PlatformTDX, testdata.RawQuote, 48 + 136, tdxEvidence, tdxQuote},
		{"tdx v5", teetypes.PlatformTDX, testdata.RawQuoteV5, 48 + 6 + 136, tdxEvidence, tdxQuote},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := envelopeOf(t, tc.platform, tc.evidence(base64.StdEncoding.EncodeToString(tc.raw)))
			out, err := withMeasurement(env, func(m []byte) { m[0] ^= 0xFF })
			if err != nil {
				t.Fatal(err)
			}
			var got teetypes.AttestationEvidence
			if err := json.Unmarshal(out, &got); err != nil {
				t.Fatal(err)
			}
			edited, _ := base64.StdEncoding.DecodeString(tc.read(t, got.Evidence))
			want := bytes.Clone(tc.raw)
			want[tc.offset] ^= 0xFF
			if got.Platform != tc.platform || !bytes.Equal(edited, want) {
				t.Errorf("the edit changed other than byte %d of the %s evidence", tc.offset, tc.name)
			}
		})
	}
}

func tdxEvidence(b string) any { return tdx.TdxEvidence{Quote: b} }

func tdxQuote(t *testing.T, ev json.RawMessage) string {
	var e tdx.TdxEvidence
	if err := json.Unmarshal(ev, &e); err != nil {
		t.Fatal(err)
	}
	return e.Quote
}

func TestWithMeasurementSkipsOtherPlatforms(t *testing.T) {
	env := envelopeOf(t, teetypes.PlatformType("azure-snp"), map[string]string{"hcl_report": "AA=="})
	if _, err := withMeasurement(env, func([]byte) {}); !errors.Is(err, godog.ErrSkip) {
		t.Errorf("got %v, want a skip", err)
	}
}
