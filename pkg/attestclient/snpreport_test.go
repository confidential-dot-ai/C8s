package attestclient_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"testing"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// hclEnvelope builds an AKS HCL envelope wrapping the given hardware report:
// header(32) + report + var_data header(20) + var_data content, with trailing
// null padding bytes after the content.
func hclEnvelope(report []byte, trailing int) []byte {
	varData := []byte(`{"keys":[]}`)
	env := make([]byte, 32+len(report)+20+len(varData)+trailing)
	copy(env[:4], "HCLA")
	copy(env[32:], report)
	hdr := env[32+len(report):]
	binary.LittleEndian.PutUint32(hdr[8:12], 2) // report_type: SNP
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(varData)+trailing))
	copy(hdr[20:], varData)
	return env
}

func TestARMTLSEvidence_VTPMPreservesEnvelope(t *testing.T) {
	fakeHCLReport := hclEnvelope(make([]byte, armtls.SNPReportSize), 64)
	evidence := map[string]any{
		"version":    1,
		"hcl_report": base64.RawURLEncoding.EncodeToString(fakeHCLReport),
		"tpm_quote": map[string]any{
			"signature": "deadbeef",
			"message":   "cafebabe",
			"pcrs":      []string{},
		},
	}
	evidenceJSON, _ := json.Marshal(evidence)

	resp := remote.AttestResponse{Platform: teetypes.PlatformAzSNP, Evidence: evidenceJSON}
	payload, err := attestclient.ARMTLSEvidence(resp)
	if err != nil {
		t.Fatalf("ARMTLSEvidence failed: %v", err)
	}

	var embedded teetypes.AttestationEvidence
	if err := json.Unmarshal([]byte(payload), &embedded); err != nil {
		t.Fatalf("embedded evidence is not JSON: %v", err)
	}
	if embedded.Platform != teetypes.PlatformAzSNP {
		t.Fatalf("embedded platform = %q, want az-snp", embedded.Platform)
	}
	if !bytes.Equal(embedded.Evidence, evidenceJSON) {
		t.Fatal("embedded evidence was not preserved")
	}
}

// TestExtractSNPReportRealAKSEnvelope anchors the HCL parser to a captured AKS
// az-snp evidence dump. Regenerate testdata/aks_hcl_envelope.bin from a live
// `hcl_report` with a URL-safe base64 decoder, for example
// `python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.urlsafe_b64decode(sys.stdin.read().strip()+"=="))'`
// — NOT `base64 -d`, whose standard alphabet silently drops the `-`/`_`
// characters and corrupts the report (that mangled an earlier fixture).
func TestExtractSNPReportRealAKSEnvelope(t *testing.T) {
	envelope, err := os.ReadFile("testdata/aks_hcl_envelope.bin")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	evidenceJSON, _ := json.Marshal(map[string]any{
		"hcl_report": base64.RawURLEncoding.EncodeToString(envelope),
	})

	report, err := agarmtls.ExtractSNPReport(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformAzSNP,
		Evidence: evidenceJSON,
	})
	if err != nil {
		t.Fatalf("ExtractSNPReport on real AKS envelope: %v", err)
	}
	if len(report) != armtls.SNPReportSize {
		t.Fatalf("report length = %d, want %d", len(report), armtls.SNPReportSize)
	}
	// First 4 bytes of an AMD SEV-SNP report are the version field (uint32 LE).
	// Currently shipping versions are 2 and 3. Anything else means the slice
	// offsets are wrong, so reject it.
	if version := binary.LittleEndian.Uint32(report[:4]); version != 2 && version != 3 {
		t.Fatalf("SNP report version = %d, want 2 or 3", version)
	}
}
