package getkubeconfig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/guestverify"
)

// The fixed guest-image tuple the test manifests pin.
var (
	testMRTDHex  = strings.Repeat("1a", 48)
	testRTMR1Hex = strings.Repeat("2b", 48)
	testRTMR2Hex = strings.Repeat("3c", 48)

	// The per-SMP launch digests the SNP test manifests pin.
	testSNPSMP2Hex = strings.Repeat("4d", 48)
	testSNPSMP4Hex = strings.Repeat("5e", 48)
)

// tdxEnvelope is a minimal self-describing evidence envelope; the actual
// verification verdict comes from the stubbed guestverify.VerifyEnvelope.
const tdxEnvelope = `{"platform":"tdx","evidence":{}}`

// writeTestManifest writes a build-artifact manifest with the given body.
func writeTestManifest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// tdxManifest is the TDX tuple the test manifests pin.
func tdxManifest() string {
	return `{"mrtd":"` + testMRTDHex + `","rtmr1":"` + testRTMR1Hex + `","rtmr2":"` + testRTMR2Hex + `"}`
}

// snpManifest is a two-variant SNP manifest (smp2 + smp4) for one image.
func snpManifest() string {
	return `{"version":3,"snp_variants":[
	  {"smp":2,"measurement":{"snp_launch_digest":"` + testSNPSMP2Hex + `","algorithm":"sha384"}},
	  {"smp":4,"measurement":{"snp_launch_digest":"` + testSNPSMP4Hex + `","algorithm":"sha384"}}]}`
}

func mustKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// stubVerify replaces the in-process attestation-go verifier with one that
// returns the given result/error.
func stubVerify(t *testing.T, res *teetypes.VerificationResult, err error) {
	t.Helper()
	orig := guestverify.VerifyEnvelope
	guestverify.VerifyEnvelope = func([]byte, teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
		return res, err
	}
	t.Cleanup(func() { guestverify.VerifyEnvelope = orig })
}

// verifiedResultFor builds a passing TDX VerificationResult whose claims
// satisfy the policy for operatorPubPEM exactly. Tests break individual claims
// from here.
func verifiedResultFor(operatorPubPEM []byte) *teetypes.VerificationResult {
	rtmr3 := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(operatorPubPEM), nil)
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformTDX,
		ReportDataMatch: new(true),
		Claims: teetypes.Claims{
			LaunchDigest: testMRTDHex,
			PlatformData: map[string]any{
				"rtmr_1": testRTMR1Hex,
				"rtmr_2": testRTMR2Hex,
				"rtmr_3": hex.EncodeToString(rtmr3[:]),
			},
		},
	}
}

// snpResultFor builds a passing result for an smp4 guest of snpManifest
// launched for operatorPubPEM.
func snpResultFor(operatorPubPEM []byte) *teetypes.VerificationResult {
	hd := runtimemeasure.HostData(operatorPubPEM)
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformSNP,
		ReportDataMatch: new(true),
		Claims: teetypes.Claims{
			LaunchDigest: testSNPSMP4Hex,
			InitData:     teetypes.HexBytes(hd[:]),
		},
	}
}
