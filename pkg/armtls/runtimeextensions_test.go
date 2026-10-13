package armtls

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func TestMarshalExtensionRuntimeExtensions(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	journal := filepath.Join(dir, "measured-policies")
	if err := os.WriteFile(journal, []byte(p+"\n"+q+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tdxReport, err := json.Marshal(teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{"quote":"AA=="}`)})
	if err != nil {
		t.Fatal(err)
	}
	tdx := Attestation{Family: TEETypeTDX, Report: tdxReport}
	own := tdx
	own.RuntimeExtensions = []string{q}
	snp := Attestation{Family: TEETypeSEVSNP, Report: fakeSNPReport([64]byte{})}

	orig := runtimeJournals
	t.Cleanup(func() { runtimeJournals = orig })
	for _, tc := range []struct {
		name     string
		att      Attestation
		journals []string
		want     []string
	}{
		{name: "TDX carries the first journal that exists", att: tdx, journals: []string{missing, journal}, want: []string{p, q}},
		{name: "TDX without a journal", att: tdx, journals: []string{missing}},
		{name: "TDX keeps its own list", att: own, journals: []string{journal}, want: []string{q}},
		{name: "SEV-SNP never", att: snp, journals: []string{journal}},
	} {
		runtimeJournals = tc.journals
		ext, err := MarshalExtension(&tc.att)
		if err != nil {
			t.Fatalf("%s: MarshalExtension: %v", tc.name, err)
		}
		got, err := UnmarshalExtension(ext.Value)
		if err != nil {
			t.Fatalf("%s: UnmarshalExtension: %v", tc.name, err)
		}
		if !slices.Equal(got.RuntimeExtensions, tc.want) {
			t.Errorf("%s: RuntimeExtensions = %v, want %v", tc.name, got.RuntimeExtensions, tc.want)
		}
	}
	if tdx.RuntimeExtensions != nil {
		t.Errorf("MarshalExtension set RuntimeExtensions on its argument: %v", tdx.RuntimeExtensions)
	}
}
