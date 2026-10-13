package armtls

import (
	"bytes"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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

// tdxClaims are the claims of a TDX node launched for anchor that extended
// RTMR[3] with extended.
func tdxClaims(mrtd, anchor []byte, extended ...string) teetypes.Claims {
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(anchor), extended)
	return teetypes.Claims{
		LaunchDigest: hex.EncodeToString(mrtd),
		PlatformData: map[string]any{"rtmr_3": hex.EncodeToString(reg[:])},
	}
}

func TestEnforceImagesRuntimeExtensions(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	q := "sha256:" + strings.Repeat("2", 64)
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)
	anchor := []byte("operator key")
	pins := []remote.ImagePin{{Name: "node", Digest: mrtd, Anchor: anchor}}
	tooMany := make([]string, 257)
	for i := range tooMany {
		tooMany[i] = p
	}
	for _, tc := range []struct {
		name    string
		claims  teetypes.Claims
		claimed []string
		wantErr bool
	}{
		{name: "bare seed, no list", claims: tdxClaims(mrtd, anchor)},
		{name: "bare seed, list ahead of the quote", claims: tdxClaims(mrtd, anchor), claimed: []string{p}},
		{name: "replaying prefix", claims: tdxClaims(mrtd, anchor, p), claimed: []string{p, q}},
		{name: "whole list", claims: tdxClaims(mrtd, anchor, p, q), claimed: []string{p, q}},
		{name: "extended, no list", claims: tdxClaims(mrtd, anchor, p), wantErr: true},
		{name: "list does not replay", claims: tdxClaims(mrtd, anchor, q), claimed: []string{p}, wantErr: true},
		{name: "wrong anchor", claims: tdxClaims(mrtd, []byte("other key"), p), claimed: []string{p}, wantErr: true},
		{name: "list too long", claims: tdxClaims(mrtd, anchor), claimed: tooMany, wantErr: true},
	} {
		resp := remote.VerifyResponse{Result: teetypes.VerificationResult{SignatureValid: true, Platform: teetypes.PlatformTDX, Claims: tc.claims}}
		err := EnforceImages(resp, pins, teetypes.PlatformTDX, tc.claimed)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: EnforceImages = %v, want error %v", tc.name, err, tc.wantErr)
		}
	}
	if pins[0].AcceptExtension != nil {
		t.Error("EnforceImages set AcceptExtension on the caller's pin")
	}
}

// A peer's certificate carries its list to VerifyCert, which replays it
// against an anchored pin.
func TestVerifyCertReplaysRuntimeExtensions(t *testing.T) {
	p := "sha256:" + strings.Repeat("1", 64)
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)
	anchor := []byte("operator key")
	stub := mockapi.New(t)
	verdict := mockapi.PassingVerdict("")
	verdict.Claims = tdxClaims(mrtd, anchor, p)
	stub.SetVerdict(verdict)
	policy := Pins{Images: []remote.ImagePin{{Name: "node", Digest: mrtd, Anchor: anchor}}}.VerifyPolicy(stub.URL())

	report, err := json.Marshal(teetypes.AttestationEvidence{Platform: teetypes.PlatformTDX, Evidence: json.RawMessage(`{"quote":"fake"}`)})
	if err != nil {
		t.Fatal(err)
	}
	orig := runtimeJournals
	t.Cleanup(func() { runtimeJournals = orig })
	runtimeJournals = nil
	for _, tc := range []struct {
		name    string
		list    []string
		wantErr bool
	}{
		{name: "replaying list", list: []string{p}},
		{name: "no list", wantErr: true},
	} {
		key, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		der, err := CreateAttestedCert(key, &Attestation{Family: TEETypeTDX, Report: report, RuntimeExtensions: tc.list}, nil)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyCert(cert, policy, nil); (err != nil) != tc.wantErr {
			t.Errorf("%s: VerifyCert = %v, want error %v", tc.name, err, tc.wantErr)
		}
	}
}
