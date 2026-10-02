package cdsattest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// EvidenceProvider yields TEE attestation evidence whose report_data equals
// the endpoint's transcript hash (overenc.IdentityTranscriptHash for
// attest-pq, overenc.LBTranscriptHash for attest-lb). The returned evidence is
// the platform's attestation-rs evidence JSON (SnpEvidence, AzSnpEvidence,
// TdxEvidence, …) the client verifier consumes verbatim.
type EvidenceProvider interface {
	Evidence(ctx context.Context, reportData []byte) (evidence json.RawMessage, platform, generation string, err error)
}

var _ EvidenceProvider = LiveEvidenceProvider{}

// LiveEvidenceProvider asks the local attestation-api for a fresh report
// bound to reportData. This is the production path; it requires a reachable
// attestation-api and runs inside the LB's CVM.
type LiveEvidenceProvider struct {
	Client   remote.Client
	Platform teetypes.PlatformType // e.g. teetypes.PlatformSNP
	// Generation is the AMD processor generation the browser's bare-SNP
	// verifier needs. It is meaningful only for PlatformSnp; the other
	// platforms auto-detect (az-snp) or have no generation concept (TDX),
	// and the bundle field is left empty for them.
	Generation string
}

// Evidence implements EvidenceProvider against the attestation-api.
func (p LiveEvidenceProvider) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, string, string, error) {
	resp, err := p.Client.Attest(ctx, remote.AttestRequest{
		ReportData: reportData,
		Platform:   p.Platform,
	})
	if err != nil {
		return nil, "", "", fmt.Errorf("attestation-api: %w", err)
	}
	platform := string(resp.Platform)
	if platform == "" {
		platform = string(p.Platform)
	}
	generation := p.Generation
	if platform != string(teetypes.PlatformSNP) {
		generation = ""
	}
	return resp.Evidence, platform, generation, nil
}

// FixtureEvidenceProvider serves a recorded evidence file. DEV/DEMO ONLY: the
// recorded report_data is fixed, so it cannot bind a live session key+nonce —
// clients must run with freshness enforcement downgraded. It exists so the LB
// can serve the full contract (and interoperate with the JS client) without a
// TEE, mirroring C8s's test/mock-cds.
type FixtureEvidenceProvider struct {
	Raw        json.RawMessage
	Platform   string
	Generation string
}

// LoadFixtureEvidence reads a recorded evidence JSON file. The file may be the
// bare SnpEvidence object or a {platform, evidence} envelope.
func LoadFixtureEvidence(path, platform, generation string) (FixtureEvidenceProvider, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return FixtureEvidenceProvider{}, fmt.Errorf("read evidence fixture: %w", err)
	}
	var env struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	evidence := json.RawMessage(raw)
	if err := json.Unmarshal(raw, &env); err == nil && len(env.Evidence) > 0 {
		evidence = env.Evidence
		if platform == "" {
			platform = env.Platform
		}
	}
	if platform == "" {
		platform = "snp"
	}
	if platform != string(teetypes.PlatformSNP) {
		generation = ""
	}
	return FixtureEvidenceProvider{Raw: evidence, Platform: platform, Generation: generation}, nil
}

// Evidence implements EvidenceProvider; reportData is ignored (see type doc).
func (p FixtureEvidenceProvider) Evidence(_ context.Context, _ []byte) (json.RawMessage, string, string, error) {
	return p.Raw, p.Platform, p.Generation, nil
}
