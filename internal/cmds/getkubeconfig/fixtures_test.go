package getkubeconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// testPolicy builds the full measured policy for the test tuple + operator
// key, with no workload images (bare-seed RTMR[3]).
func testPolicy(t *testing.T, operatorPubPEM []byte) guestverify.Policy {
	t.Helper()
	exp, err := guestverify.PolicyFor(writeTestManifest(t, tdxManifest()), operatorPubPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	return exp
}

// operatorPub is a throwaway operator public key PEM for the tests.
func operatorPub(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKeyPEMFromPrivate(mustKeyPEM(t, key))
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func mustKeyPEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// capturedVerify records one call to the stubbed verifier: the evidence
// envelope and the params production code asked it to enforce.
type capturedVerify struct {
	envelope []byte
	params   teetypes.VerifyParams
}

// verifyRecorder collects verifier calls; the armTLS dial can invoke the
// verifier off the test goroutine, so reads and writes go through the mutex.
type verifyRecorder struct {
	mu    sync.Mutex
	calls []capturedVerify
}

func (r *verifyRecorder) add(envelope []byte, params teetypes.VerifyParams) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, capturedVerify{envelope, params})
}

func (r *verifyRecorder) all() []capturedVerify {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]capturedVerify(nil), r.calls...)
}

// stubVerify replaces the in-process attestation-go verifier with one that
// returns the given result/error and records what it was asked to check, so
// tests can pin the request side (the report_data binding), not just the
// verdict.
func stubVerify(t *testing.T, res *teetypes.VerificationResult, err error) *verifyRecorder {
	t.Helper()
	rec := &verifyRecorder{}
	orig := guestverify.VerifyEnvelope
	guestverify.VerifyEnvelope = func(envelope []byte, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
		rec.add(envelope, params)
		return res, err
	}
	t.Cleanup(func() { guestverify.VerifyEnvelope = orig })
	return rec
}

// verifiedResultFor builds a passing TDX VerificationResult whose claims
// satisfy testPolicy(operatorPubPEM) exactly. Tests break individual claims
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
