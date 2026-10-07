package armtls_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
)

// TestLiveSNPEntryEnforcement drives the delegated verification path
// VerifyPolicy.Policy.Images feeds against real SEV-SNP evidence: a config pinning
// the booted image is admitted, and one pinning any other image is refused.
// Set C8S_LIVE_ATTESTATION_URL to the attestation-api of a running CVM,
// C8S_LIVE_EVIDENCE to its evidence envelope and C8S_LIVE_CONFIG to the
// measurements config pinning the booted image.
func TestLiveSNPEntryEnforcement(t *testing.T) {
	apiURL := os.Getenv("C8S_LIVE_ATTESTATION_URL")
	evidencePath := os.Getenv("C8S_LIVE_EVIDENCE")
	if apiURL == "" || evidencePath == "" {
		t.Skip("set C8S_LIVE_ATTESTATION_URL and C8S_LIVE_EVIDENCE to run against a live CVM")
	}

	raw, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	var evidence teetypes.AttestationEvidence
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}

	configPath := os.Getenv("C8S_LIVE_CONFIG")
	if configPath == "" {
		t.Fatal("set C8S_LIVE_CONFIG to the measurements config pinning the booted image")
	}
	pinned, err := refvalues.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	client := remote.NewClient(apiURL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The evidence was requested with an all-zero REPORTDATA.
	policy := remote.Policy{Images: pinned.Images}
	if _, err := client.VerifyEvidence(ctx, evidence, policy); err != nil {
		t.Fatalf("rejected the image it was booted from: %v", err)
	}

	// Flip one byte of every pinned digest: same shape, different image.
	wrong := make([]remote.ImagePin, 0, len(pinned.Images))
	for _, e := range pinned.Images {
		d := append([]byte(nil), e.Digest...)
		d[0] ^= 0xff
		wrong = append(wrong, remote.ImagePin{Name: e.Name, Digest: d, Registers: e.Registers})
	}
	policy.Images = wrong
	_, err = client.VerifyEvidence(ctx, evidence, policy)
	if err == nil {
		t.Fatal("admitted a guest whose launch measurement is not pinned")
	}
	if !errors.Is(err, remote.ErrMeasurementNotAllowed) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
	t.Logf("unpinned image refused: %v", err)
}
