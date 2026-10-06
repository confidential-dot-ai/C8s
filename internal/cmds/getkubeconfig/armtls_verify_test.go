package getkubeconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
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
func testPolicy(t *testing.T, operatorPubPEM []byte) measuredPolicy {
	t.Helper()
	exp, err := policyFor(writeTestManifest(t, tdxManifest()), operatorPubPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exp.platform() != teetypes.PlatformTDX {
		t.Fatalf("policy platform = %q, want tdx", exp.platform())
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

// attestedCert builds a genuine ARmTLS TDX cert carrying the given evidence
// envelope, bound to the cert's own key (as the real serving path does).
func attestedCert(t *testing.T, envelope teetypes.AttestationEvidence) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	report, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{Family: armtls.TEETypeTDX, Report: report}
	der, err := armtls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// capturedVerify records one call to the stubbed verifier: the evidence
// envelope and the params production code asked it to enforce.
type capturedVerify struct {
	envelope []byte
	params   teetypes.VerifyParams
}

// verifyRecorder collects verifier calls; the ARmTLS dial can invoke the
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
// verdict. Lets the tests drive verifyServerCert's post-verification logic
// deterministically without real hardware.
func stubVerify(t *testing.T, res *teetypes.VerificationResult, err error) *verifyRecorder {
	t.Helper()
	rec := &verifyRecorder{}
	orig := verifyEnvelope
	verifyEnvelope = func(envelope []byte, params teetypes.VerifyParams) (*teetypes.VerificationResult, error) {
		rec.add(envelope, params)
		return res, err
	}
	t.Cleanup(func() { verifyEnvelope = orig })
	return rec
}

// verifiedResultFor builds a passing VerificationResult whose claims satisfy
// exp exactly. Tests break individual claims from here.
func verifiedResultFor(exp measuredPolicy) *teetypes.VerificationResult {
	mrtd := exp.identity.LaunchDigests()[0].Digest
	rtmrs := exp.identity.RTMRs()
	rtmr1, rtmr2 := rtmrs[1], rtmrs[2]
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformTDX,
		ReportDataMatch: new(true),
		Claims: teetypes.Claims{
			LaunchDigest: hex.EncodeToString(mrtd[:]),
			PlatformData: map[string]any{
				"rtmr_1": hex.EncodeToString(rtmr1[:]),
				"rtmr_2": hex.EncodeToString(rtmr2[:]),
				"rtmr_3": hex.EncodeToString(expectedRTMR3(exp)),
			},
		},
	}
}

func TestVerifyEvidenceRejectsPlatformMismatch(t *testing.T) {
	// A node whose platform differs from the one the manifest describes can
	// never satisfy the gate; it must be named up front, before any
	// verification runs. (An SNP node IS acceptable against an SNP manifest —
	// see the snp_variants path — but never against a TDX tuple.)
	exp := testPolicy(t, operatorPub(t))
	stubVerify(t, verifiedResultFor(exp), nil) // must not be reached
	_, err := verifyEvidence([]byte(`{"platform":"snp","evidence":{}}`), nil, exp)
	if err == nil || !strings.Contains(err.Error(), "the platform the manifest describes") {
		t.Fatalf("want platform-mismatch error, got %v", err)
	}
}

func TestVerifyServerCertNoExtension(t *testing.T) {
	// A plain (non-ARmTLS) cert must be rejected before any verification.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)

	err = verifyServerCert(cert, testPolicy(t, operatorPub(t)))
	if err == nil || !strings.Contains(err.Error(), "armtls:") {
		t.Fatalf("want ARmTLS extraction error, got %v", err)
	}
}

func TestVerifyServerCertRejectsBadReportData(t *testing.T) {
	// The verifier reports the quote is valid but report_data isn't bound to
	// the cert key — a MITM presenting someone else's quote. Must fail closed.
	exp := testPolicy(t, operatorPub(t))
	res := verifiedResultFor(exp)
	res.ReportDataMatch = new(false)
	stubVerify(t, res, nil)
	cert := attestedCert(t, teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	err := verifyServerCert(cert, exp)
	if err == nil || !strings.Contains(err.Error(), "report_data") {
		t.Fatalf("want report_data binding failure, got %v", err)
	}
}

// The ARmTLS dial enforces the IDENTICAL policy as the attest gate: every
// register of the measured identity fails it independently.
func TestVerifyServerCertRejectsEachMismatchedRegister(t *testing.T) {
	pub := operatorPub(t)
	for _, tc := range []struct {
		name  string
		wreck func(res *teetypes.VerificationResult)
		want  string
	}{
		{"wrong MRTD", func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = strings.Repeat("00", 48)
		}, "MRTD mismatch"},
		{"wrong rtmr1", func(r *teetypes.VerificationResult) {
			r.Claims.PlatformData["rtmr_1"] = strings.Repeat("00", 48)
		}, "RTMR[1] does not match"},
		{"wrong rtmr2", func(r *teetypes.VerificationResult) {
			r.Claims.PlatformData["rtmr_2"] = strings.Repeat("00", 48)
		}, "RTMR[2] does not match"},
		{"wrong rtmr3", func(r *teetypes.VerificationResult) {
			r.Claims.PlatformData["rtmr_3"] = strings.Repeat("00", 48)
		}, "not bound to the expected anchor"},
		{"absent MRTD", func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = ""
		}, "no launch digest"},
		{"absent rtmr3", func(r *teetypes.VerificationResult) {
			delete(r.Claims.PlatformData, "rtmr_3")
		}, "no rtmr_3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := testPolicy(t, pub)
			res := verifiedResultFor(exp)
			tc.wreck(res)
			stubVerify(t, res, nil)
			cert := attestedCert(t, teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

			err := verifyServerCert(cert, exp)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
}

func TestVerifyServerCertAccepts(t *testing.T) {
	// Genuine quote, bound to the cert key, full measured identity: accept.
	exp := testPolicy(t, operatorPub(t))
	rec := stubVerify(t, verifiedResultFor(exp), nil)
	cert := attestedCert(t, teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})

	if err := verifyServerCert(cert, exp); err != nil {
		t.Fatalf("want accept, got %v", err)
	}
	// The verifier must be asked to bind the quote to THIS cert's public key —
	// the check that ties the ARmTLS channel to the attested guest.
	want, err := armtls.ReportDataForKey(cert.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := rec.all()
	if len(calls) != 1 {
		t.Fatalf("verifier calls = %d, want 1", len(calls))
	}
	if !bytes.Equal(calls[0].params.ExpectedReportData, want[:]) {
		t.Errorf("report_data binding = %x, want SHA-384(cert key) %x", calls[0].params.ExpectedReportData, want[:])
	}
}

// mintServingCert builds a self-issued ARmTLS-shaped cert with chosen
// validity, embedded key from holder, and signature from signer.
func mintServingCert(t *testing.T, holder *ecdsa.PublicKey, signer *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	report, err := json.Marshal(teetypes.AttestationEvidence{Platform: "tdx", Evidence: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	att := &armtls.Attestation{Family: armtls.TEETypeTDX, Report: report}
	ext, err := armtls.MarshalExtension(att)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(9),
		Subject:         pkix.Name{CommonName: "cred-release"},
		NotBefore:       notBefore,
		NotAfter:        notAfter,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, holder, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The presented cert's body is authenticated before its quote is trusted:
// validity within the shared skew bound, and the self-signature under the
// cert's own key.
func TestVerifyServerCertAuthenticatesBody(t *testing.T) {
	now := time.Now()
	exp := testPolicy(t, operatorPub(t))
	stubVerify(t, verifiedResultFor(exp), nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("expired serving cert rejected", func(t *testing.T) {
		cert := mintServingCert(t, &key.PublicKey, key, now.Add(-2*time.Hour), now.Add(-time.Minute))
		if err := verifyServerCert(cert, exp); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("want expiry rejection, got %v", err)
		}
	})

	t.Run("future serving cert rejected", func(t *testing.T) {
		cert := mintServingCert(t, &key.PublicKey, key, now.Add(time.Hour), now.Add(2*time.Hour))
		if err := verifyServerCert(cert, exp); err == nil || !strings.Contains(err.Error(), "not yet valid") {
			t.Fatalf("want NotBefore rejection, got %v", err)
		}
	})

	t.Run("re-signed body rejected", func(t *testing.T) {
		other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := mintServingCert(t, &key.PublicKey, other, now.Add(-time.Hour), now.Add(time.Hour))
		if err := verifyServerCert(cert, exp); err == nil ||
			!strings.Contains(err.Error(), "does not verify with its own key") {
			t.Fatalf("want self-signature rejection, got %v", err)
		}
	})

	t.Run("valid body accepted", func(t *testing.T) {
		cert := mintServingCert(t, &key.PublicKey, key, now.Add(-time.Hour), now.Add(time.Hour))
		if err := verifyServerCert(cert, exp); err != nil {
			t.Fatalf("want accept, got %v", err)
		}
	})
}

// snpTestPolicy builds an SNP gate from a two-variant manifest.
func snpTestPolicy(t *testing.T, operatorPubPEM []byte) measuredPolicy {
	t.Helper()
	exp, err := policyFor(writeTestManifest(t, snpManifest()), operatorPubPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exp.platform() != teetypes.PlatformSNP {
		t.Fatalf("policy platform = %q, want snp", exp.platform())
	}
	return exp
}

// smpDigest is the launch digest exp pins for an smp-vCPU guest.
func smpDigest(t *testing.T, exp measuredPolicy, smp int) [runtimemeasure.Size]byte {
	t.Helper()
	label := fmt.Sprintf("smp%d", smp)
	for _, v := range exp.identity.LaunchDigests() {
		if v.Label == label {
			return v.Digest
		}
	}
	t.Fatalf("manifest pins no %s variant", label)
	return [runtimemeasure.Size]byte{}
}

func snpResultFor(t *testing.T, exp measuredPolicy, smp int) *teetypes.VerificationResult {
	t.Helper()
	digest := smpDigest(t, exp, smp)
	return &teetypes.VerificationResult{
		SignatureValid:  true,
		Platform:        teetypes.PlatformSNP,
		ReportDataMatch: new(true),
		Claims: teetypes.Claims{
			LaunchDigest: hex.EncodeToString(digest[:]),
			InitData:     teetypes.HexBytes(expectedHostData(exp)),
		},
	}
}

// Either pinned vCPU variant of the same image satisfies the gate: SNP's
// MEASUREMENT covers initial vCPU state, so one image has one digest per SMP.
func TestSNPGateAcceptsEveryPinnedVariant(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	for _, smp := range []int{2, 4} {
		if err := exp.checkIdentity(snpResultFor(t, exp, smp)); err != nil {
			t.Errorf("smp%d: %v", smp, err)
		}
	}
}

// Every way the SNP gate must fail closed.
func TestSNPGateFailsClosed(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	other := snpTestPolicy(t, operatorPub(t)) // a different operator key

	cases := map[string]func(*teetypes.VerificationResult){
		"unpinned launch digest (different image)": func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = strings.Repeat("ab", runtimemeasure.Size)
		},
		"no launch digest": func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = ""
		},
		"malformed launch digest": func(r *teetypes.VerificationResult) {
			r.Claims.LaunchDigest = "not-hex"
		},
		"keyless launch (all-zero HOSTDATA)": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = teetypes.HexBytes(make([]byte, runtimemeasure.HostDataSize))
		},
		"HOSTDATA of a different operator key": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = teetypes.HexBytes(expectedHostData(other))
		},
		"no HOSTDATA": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = nil
		},
		"TDX-width MRCONFIGID must not truncate": func(r *teetypes.VerificationResult) {
			r.Claims.InitData = teetypes.HexBytes(make([]byte, runtimemeasure.Size))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			res := snpResultFor(t, exp, 2)
			mutate(res)
			if err := exp.checkIdentity(res); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// SNP has no runtime-extend register, so claiming workload enforcement is a
// usage error rather than a silently-ignored flag.
func TestSNPPolicyRejectsWorkloadImages(t *testing.T) {
	p := writeTestManifest(t, snpManifest())
	_, err := policyFor(p, operatorPub(t), []string{"repo@sha256:" + strings.Repeat("c", 64)})
	if err == nil || !strings.Contains(err.Error(), "requires a TDX node") {
		t.Fatalf("want workload-image rejection, got %v", err)
	}
}

// stubSNPARMTLS replaces the localverify call the SNP dial uses, so the arm is
// testable without AMD KDS. Records the params it was asked to enforce.
func stubSNPARMTLS(t *testing.T, res *teetypes.VerificationResult, err error) *localverify.Params {
	t.Helper()
	var got localverify.Params
	orig := verifySNPARMTLS
	verifySNPARMTLS = func(_ context.Context, _ string, _ json.RawMessage, p localverify.Params) (*teetypes.VerificationResult, error) {
		got = p
		return res, err
	}
	t.Cleanup(func() { verifySNPARMTLS = orig })
	return &got
}

// snpAttestedCert builds an ARmTLS cert carrying a RAW SNP report — the shape
// bare-metal SNP guests actually present (no JSON envelope), which is why the
// dial has its own arm.
func snpAttestedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rd, err := armtls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Minimal raw report: REPORTDATA at its fixed offset is what CertEnvelope
	// reads; the rest stays zero (the stubbed verifier supplies the verdict).
	report := make([]byte, 1184)
	copy(report[0x50:], rd[:])
	att := &armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: report}
	der, err := armtls.CreateAttestedCert(key, att, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// The SNP dial must enforce the SAME two pins as the attest gate — this is
// the leg that silently could not run before, since bare-metal SNP certs
// carry no embedded envelope.
func TestVerifyServerCertSNPEnforcesBothPins(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	params := stubSNPARMTLS(t, snpResultFor(t, exp, 2), nil)

	if err := verifyServerCert(snpAttestedCert(t), exp); err != nil {
		t.Fatalf("verifyServerCert: %v", err)
	}
	// Both pins must have been handed to the verifier, not just checked after.
	if len(params.Measurements) != len(exp.identity.LaunchDigests()) {
		t.Errorf("passed %d measurements, want %d (every pinned SMP variant)", len(params.Measurements), len(exp.identity.LaunchDigests()))
	}
	if !bytes.Equal(params.ExpectedInitDataHash, expectedHostData(exp)) {
		t.Errorf("ExpectedInitDataHash = %x, want the operator-key binding %x", params.ExpectedInitDataHash, expectedHostData(exp))
	}
	if len(params.ExpectedReportData) == 0 {
		t.Error("ExpectedReportData empty: the quote would not be bound to this TLS channel")
	}
}

// A verdict that contradicts the pins must be refused even if the engine
// returned success (defense in depth).
func TestVerifyServerCertSNPRejectsContradictoryClaims(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	other := snpTestPolicy(t, operatorPub(t))

	for name, res := range map[string]*teetypes.VerificationResult{
		"wrong HOSTDATA": func() *teetypes.VerificationResult {
			r := snpResultFor(t, exp, 2)
			r.Claims.InitData = teetypes.HexBytes(expectedHostData(other))
			return r
		}(),
		"unpinned launch digest": func() *teetypes.VerificationResult {
			r := snpResultFor(t, exp, 2)
			r.Claims.LaunchDigest = strings.Repeat("ab", runtimemeasure.Size)
			return r
		}(),
		"signature not valid": func() *teetypes.VerificationResult {
			r := snpResultFor(t, exp, 2)
			r.SignatureValid = false
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			stubSNPARMTLS(t, res, nil)
			if err := verifyServerCert(snpAttestedCert(t), exp); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// A verifier refusal (bad evidence, KDS failure) must fail the dial closed.
func TestVerifyServerCertSNPPropagatesVerifierError(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	stubSNPARMTLS(t, nil, fmt.Errorf("collateral unavailable"))
	if err := verifyServerCert(snpAttestedCert(t), exp); err == nil {
		t.Fatal("expected error, got nil")
	}
}

// The attest gate must accept bare-metal SNP evidence whose cert_chain is
// null — the shape the guest attestation-api actually serves (c8s#415). It
// used to go through attestation-go's offline path, which requires the VCEK
// inline and fetches nothing, so every real SNP node failed the gate with
// "evidence is missing cert_chain.vcek" while the ARmTLS dial arm (already on
// localverify) would have accepted the same node.
func TestAttestGateAcceptsSNPEvidenceWithoutInlineVCEK(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	params := stubSNPARMTLS(t, snpResultFor(t, exp, 2), nil)

	// Exactly what the guest serves: a raw report and cert_chain: null.
	envelope := []byte(`{"platform":"snp","evidence":{"attestation_report":"AAAA","cert_chain":null}}`)
	nonce := []byte("nonce-bound-to-this-request")

	if _, err := verifyEvidence(envelope, nonce, exp); err != nil {
		t.Fatalf("verifyEvidence on VCEK-less SNP evidence: %v", err)
	}
	// The gate must hand the collateral-fetching verifier the same two pins
	// the dial arm passes, and the caller's nonce as the binding anchor.
	if len(params.Measurements) != len(exp.identity.LaunchDigests()) {
		t.Errorf("passed %d measurements, want %d", len(params.Measurements), len(exp.identity.LaunchDigests()))
	}
	if !bytes.Equal(params.ExpectedInitDataHash, expectedHostData(exp)) {
		t.Errorf("ExpectedInitDataHash = %x, want %x", params.ExpectedInitDataHash, expectedHostData(exp))
	}
	if !bytes.Equal(params.ExpectedReportData, nonce) {
		t.Errorf("ExpectedReportData = %q, want the caller's nonce %q", params.ExpectedReportData, nonce)
	}
}

// The SNP gate keeps failing closed on every claim that contradicts the policy.
func TestAttestGateSNPFailsClosed(t *testing.T) {
	exp := snpTestPolicy(t, operatorPub(t))
	other := snpTestPolicy(t, operatorPub(t))
	envelope := []byte(`{"platform":"snp","evidence":{"attestation_report":"AAAA","cert_chain":null}}`)

	cases := map[string]func() (*teetypes.VerificationResult, error){
		"verifier refuses (bad evidence / KDS down)": func() (*teetypes.VerificationResult, error) {
			return nil, fmt.Errorf("collateral unavailable")
		},
		"report_data not bound": func() (*teetypes.VerificationResult, error) {
			r := snpResultFor(t, exp, 2)
			r.ReportDataMatch = new(false)
			return r, nil
		},
		"another operator key's HOSTDATA": func() (*teetypes.VerificationResult, error) {
			r := snpResultFor(t, exp, 2)
			r.Claims.InitData = teetypes.HexBytes(expectedHostData(other))
			return r, nil
		},
		"unpinned launch digest": func() (*teetypes.VerificationResult, error) {
			r := snpResultFor(t, exp, 2)
			r.Claims.LaunchDigest = strings.Repeat("ab", runtimemeasure.Size)
			return r, nil
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := mk()
			stubSNPARMTLS(t, res, err)
			if _, gotErr := verifyEvidence(envelope, []byte("nonce"), exp); gotErr == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// expectedRTMR3 is the register a node satisfying exp must report: the
// operator-key seed extended by exp's workload chain. VerifyBinding derives
// the same value inside the gate; here it builds the claims to feed it.
func expectedRTMR3(exp measuredPolicy) []byte {
	reg := runtimemeasure.FromDigestsSeeded(runtimemeasure.Seed(exp.operatorPubPEM), exp.workloadDigests)
	return reg[:]
}

// expectedHostData is the HOSTDATA a node satisfying exp must report.
func expectedHostData(exp measuredPolicy) []byte {
	hd := runtimemeasure.HostData(exp.operatorPubPEM)
	return hd[:]
}
