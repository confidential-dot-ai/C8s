package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// bareSnpEvidence strips cert_chain from the real Zen4c/Genoa fixture, yielding
// the {attestation_report}-only evidence a bare armTLS serving cert produces —
// the shape that forces the AMD KDS fetch.
func bareSnpEvidence(t *testing.T) *evidence {
	t.Helper()
	fixture, err := os.ReadFile("testdata/snp-evidence-genoa.json")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Platform string `json:"platform"`
		Evidence struct {
			AttestationReport string `json:"attestation_report"`
		} `json:"evidence"`
	}
	if err := json.Unmarshal(fixture, &env); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]string{"attestation_report": env.Evidence.AttestationReport})
	if err != nil {
		t.Fatal(err)
	}
	return &evidence{platform: env.Platform, rawEvidence: raw, source: "test"}
}

// TestVerifyInProcess_KDSFetchBoundedByContext is the regression test for the
// Siena hang: a bare report needs a KDS fetch, and an expired context must stop
// it promptly with a connectError (exit 3 — collateral unavailable, not a
// verdict). A cancelled context aborts http before any I/O, so no network is
// touched. Pre-fix this path ignored ctx entirely and retried KDS for minutes.
func TestVerifyInProcess_KDSFetchBoundedByContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := verifyInProcess(ctx, bareSnpEvidence(t), &armtls.VerifyPolicy{}, nil, nil)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("expired ctx took %v, want prompt return", elapsed)
	}
	if err == nil {
		t.Fatal("expired ctx must fail")
	}
	if !isConnectError(err) {
		t.Fatalf("KDS fetch failure must be a connectError (exit 3), got: %v", err)
	}
}

// TestVerifyEvidence_TimeoutBoundsCollateralFetch proves --timeout bounds the
// verification attempt itself: with a short timeout, a bare report's KDS fetch
// must fail promptly as collateral-unavailable (exit 3), not run unbounded.
func TestVerifyEvidence_TimeoutBoundsCollateralFetch(t *testing.T) {
	cfg := config{timeout: 50 * time.Millisecond, output: "text"}
	var out, errOut bytes.Buffer
	start := time.Now()
	code := verifyEvidence(context.Background(), cfg, &verifyPlan{policy: &armtls.VerifyPolicy{}}, bareSnpEvidence(t), nil, operatorKeysReport{}, measurementsReport{}, &out, &errOut)
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("verifyEvidence took %v, want the 50ms timeout enforced", elapsed)
	}
	if code != exitNoEvidence {
		t.Fatalf("exit = %d, want %d (collateral unavailable); stderr: %s", code, exitNoEvidence, errOut.String())
	}
}

// TestRun_BareEvidenceTimeoutExitsNoEvidence drives the full command path
// (--from-file, bare evidence) with a dead parent context standing in for an
// elapsed --timeout: the command must exit 3 promptly, with the collateral
// failure on stderr — not hang, and not report a verification verdict.
func TestRun_BareEvidenceTimeoutExitsNoEvidence(t *testing.T) {
	ev := bareSnpEvidence(t)
	doc, err := json.Marshal(map[string]any{
		"platform": ev.platform,
		"evidence": json.RawMessage(ev.rawEvidence),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bare.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg := config{
		fromFile:      path,
		kind:          "cds",
		timeout:       50 * time.Millisecond,
		expectedRDHex: "00", // bare evidence needs an anchor to parse; never reached
		output:        "text",
	}

	var out, errOut bytes.Buffer
	start := time.Now()
	code := run(ctx, cfg, &out, &errOut)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("run took %v, want prompt return", elapsed)
	}
	if code != exitNoEvidence {
		t.Fatalf("exit = %d, want %d (collateral unavailable); stderr: %s", code, exitNoEvidence, errOut.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("collateral")) {
		t.Fatalf("stderr should name the collateral failure, got: %s", errOut.String())
	}
}
