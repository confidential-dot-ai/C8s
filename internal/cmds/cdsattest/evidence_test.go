package cdsattest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// fixedEvidence returns the same SNP evidence whatever report_data it is asked to bind.
type fixedEvidence struct{}

func (fixedEvidence) Evidence(context.Context, []byte) (json.RawMessage, string, string, error) {
	return json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), "snp", "genoa", nil
}

func TestLiveEvidenceProvider(t *testing.T) {
	var gotReq remote.AttestRequest
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/attest" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotReq); err != nil {
			t.Error(err)
		}
		json.NewEncoder(w).Encode(remote.AttestResponse{
			Platform: "snp",
			Evidence: json.RawMessage(`{"attestation_report":"AAAA"}`),
		})
	}))
	defer api.Close()

	p := LiveEvidenceProvider{
		Client:     remote.NewClient(api.URL),
		Platform:   teetypes.PlatformSNP,
		Generation: "genoa",
	}
	ev, platform, generation, err := p.Evidence(context.Background(), []byte("report-data"))
	if err != nil {
		t.Fatal(err)
	}
	if string(ev) != `{"attestation_report":"AAAA"}` || platform != "snp" || generation != "genoa" {
		t.Fatalf("Evidence() = %q, %q, %q", ev, platform, generation)
	}
	if string(gotReq.ReportData) != "report-data" {
		t.Fatalf("report_data not forwarded: %q", gotReq.ReportData)
	}
}

func TestLiveEvidenceProviderPlatformFallback(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// No platform in the response: the provider must fall back to its own.
		json.NewEncoder(w).Encode(remote.AttestResponse{Evidence: json.RawMessage(`{}`)})
	}))
	defer api.Close()

	p := LiveEvidenceProvider{Client: remote.NewClient(api.URL), Platform: teetypes.PlatformSNP, Generation: "genoa"}
	_, platform, _, err := p.Evidence(context.Background(), []byte("rd"))
	if err != nil {
		t.Fatal(err)
	}
	if platform != string(teetypes.PlatformSNP) {
		t.Fatalf("platform = %q, want fallback %q", platform, teetypes.PlatformSNP)
	}
}

func TestLiveEvidenceProviderDropsGenerationOffSNP(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(remote.AttestResponse{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{}`)})
	}))
	defer api.Close()

	p := LiveEvidenceProvider{Client: remote.NewClient(api.URL), Platform: teetypes.PlatformTDX, Generation: "genoa"}
	_, platform, generation, err := p.Evidence(context.Background(), []byte("rd"))
	if err != nil {
		t.Fatal(err)
	}
	if platform != string(teetypes.PlatformTDX) || generation != "" {
		t.Fatalf("Evidence() platform, generation = %q, %q, want %q with no generation", platform, generation, teetypes.PlatformTDX)
	}
}

func TestLiveEvidenceProviderError(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer api.Close()

	p := LiveEvidenceProvider{Client: remote.NewClient(api.URL), Platform: teetypes.PlatformSNP}
	_, _, _, err := p.Evidence(context.Background(), []byte("rd"))
	if err == nil || !strings.Contains(err.Error(), "attestation-api") {
		t.Fatalf("expected attestation-api error, got %v", err)
	}
}
