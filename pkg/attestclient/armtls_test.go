package attestclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// TestARMTLSEvidenceShapes pins which platforms embed a raw report and which
// keep their envelope. The split follows the vTPM boundary, not the tag: gcp-snp
// attests through the hardware report alone, so it embeds the raw report like
// bare-metal snp, while az-snp keeps the envelope its quote lives in.
func TestARMTLSEvidenceShapes(t *testing.T) {
	report := base64.StdEncoding.EncodeToString(make([]byte, armtls.SNPReportSize))
	for _, tc := range []struct {
		platform teetypes.PlatformType
		evidence string
		wantRaw  bool
	}{
		{teetypes.PlatformSNP, `{"attestation_report":"` + report + `"}`, true},
		{teetypes.PlatformGcpSNP, `{"attestation_report":"` + report + `"}`, true},
		{teetypes.PlatformAzSNP, `{"hcl_report":"AAAA"}`, false},
		{teetypes.PlatformTDX, `{"quote":"abc"}`, false},
		{teetypes.PlatformGcpTDX, `{"quote":"abc"}`, false},
	} {
		t.Run(string(tc.platform), func(t *testing.T) {
			out, err := ARMTLSEvidence(remote.AttestResponse{
				Platform: tc.platform,
				Evidence: json.RawMessage(tc.evidence),
			})
			if err != nil {
				t.Fatalf("ARMTLSEvidence: %v", err)
			}
			if gotRaw := len(out) == armtls.SNPReportSize; gotRaw != tc.wantRaw {
				t.Fatalf("raw report = %t (payload %d bytes), want %t", gotRaw, len(out), tc.wantRaw)
			}
		})
	}
}

// TestARMTLSEvidenceGcpTDXStripsEventlog: gcp-tdx attests through its hardware
// quote, so like bare-metal tdx it loses the event log that would push the
// certificate past a TLS handshake record.
func TestARMTLSEvidenceGcpTDXStripsEventlog(t *testing.T) {
	out, err := ARMTLSEvidence(remote.AttestResponse{
		Platform: teetypes.PlatformGcpTDX,
		Evidence: json.RawMessage(`{"quote":"abc","cc_eventlog":"AAAA"}`),
	})
	if err != nil {
		t.Fatalf("ARMTLSEvidence: %v", err)
	}
	if strings.Contains(out, "cc_eventlog") {
		t.Fatalf("cc_eventlog survived the strip: %s", out)
	}
}

// attestSpy is an attestation-api /attest stub that records the report_data it
// was asked to bind and returns a well-formed (all-zero) SNP report.
func attestSpy(t *testing.T, gotReportData *[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			http.NotFound(w, r)
			return
		}
		var req remote.AttestRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode attest request: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		*gotReportData = req.ReportData
		report := base64.StdEncoding.EncodeToString(make([]byte, armtls.SNPReportSize))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"platform": "snp",
			"evidence": json.RawMessage(`{"attestation_report":"` + report + `"}`),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAttestationExtension_BindsKeyAnchor(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var sentReportData []byte
	srv := attestSpy(t, &sentReportData)

	ext, err := NewClient("").AttestationExtension(context.Background(), srv.URL, &key.PublicKey)
	if err != nil {
		t.Fatalf("AttestationExtension: %v", err)
	}
	if !ext.Id.Equal(armtls.OIDARMTLSAttestation) {
		t.Fatalf("extension OID = %v, want %v", ext.Id, armtls.OIDARMTLSAttestation)
	}

	// The evidence must be bound to the nonce-free key anchor — that equality
	// is what makes the leaf re-verifiable at a relying party.
	want, err := armtls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(sentReportData) != string(want[:sha512.Size384]) {
		t.Fatalf("bound report data = %x, want key anchor %x", sentReportData, want[:sha512.Size384])
	}

	att, err := armtls.UnmarshalExtension(ext.Value)
	if err != nil {
		t.Fatalf("extension does not parse as an attestation: %v", err)
	}
	if att.Family != armtls.TEETypeSEVSNP {
		t.Fatalf("Family = %q, want %q", att.Family, armtls.TEETypeSEVSNP)
	}
}

// TestARMTLSEvidenceTDXStripsEventlog: bare-metal TDX evidence must be embedded
// as the envelope with cc_eventlog dropped and the quote kept.
func TestARMTLSEvidenceTDXStripsEventlog(t *testing.T) {
	resp := remote.AttestResponse{
		Platform: teetypes.PlatformTDX,
		Evidence: json.RawMessage(`{"quote":"abc","cc_eventlog":"AAAA"}`),
	}
	out, err := ARMTLSEvidence(resp)
	if err != nil {
		t.Fatalf("ARMTLSEvidence: %v", err)
	}
	var envelope struct {
		Platform string                     `json:"platform"`
		Evidence map[string]json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(out), &envelope); err != nil {
		t.Fatalf("unmarshal envelope %q: %v", out, err)
	}
	if envelope.Platform != string(teetypes.PlatformTDX) {
		t.Errorf("platform = %q, want tdx", envelope.Platform)
	}
	if got := string(envelope.Evidence["quote"]); got != `"abc"` {
		t.Errorf("quote = %s, want \"abc\"", got)
	}
	if _, ok := envelope.Evidence["cc_eventlog"]; ok {
		t.Error("cc_eventlog survived the strip")
	}
	if len(envelope.Evidence) != 1 {
		t.Errorf("evidence keys = %d, want only quote", len(envelope.Evidence))
	}
}

func TestARMTLSEvidenceTDXBadEvidence(t *testing.T) {
	resp := remote.AttestResponse{
		Platform: teetypes.PlatformTDX,
		Evidence: json.RawMessage(`not-json`),
	}
	if _, err := ARMTLSEvidence(resp); err == nil {
		t.Fatal("expected error for unparseable tdx evidence")
	}
}
