package armtls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
)

// fakeSNPReport creates a minimal fake SEV-SNP attestation report (1184 bytes)
// with the given reportData at the correct offset. This is for testing only —
// real reports are signed by AMD hardware.
func fakeSNPReport(reportData [64]byte) []byte {
	// AMD SEV-SNP report is exactly 0x4A0 (1184) bytes.
	// REPORT_DATA is at offset 0x50, 64 bytes.
	// MEASUREMENT is at offset 0x90, 48 bytes.
	// See: AMD SEV-SNP ABI Specification, Table 21.
	report := make([]byte, SNPReportSize)

	// Version (offset 0x00): must be >= 2 for SNP
	report[0] = 0x02

	// POLICY (offset 0x08): 8 bytes, little-endian
	// Bit 16 = SMT allowed; bit 17 = reserved/must-be-one. Minimum: 0x30000
	// (ABI major=0, minor=0, SMT=1)
	report[0x08] = 0x00
	report[0x09] = 0x00
	report[0x0A] = 0x03 // SMT bit set

	// REPORT_DATA (offset 0x50): 64 bytes
	copy(report[0x50:0x90], reportData[:])

	// MEASUREMENT (offset 0x90): 48 bytes
	for i := range 48 {
		report[0x90+i] = byte(i) // deterministic fake measurement
	}

	return report
}

// testKeyAndAttestation generates a keypair and matching attestation for tests.
func testKeyAndAttestation(t *testing.T) (*ecdsa.PrivateKey, *Attestation) {
	t.Helper()
	key, reportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	att := &Attestation{
		Family: TEETypeSEVSNP,
		Report: fakeSNPReport(reportData),
	}
	return key, att
}

// testAttestedCert generates a keypair, attestation, and parsed certificate.
func testAttestedCert(t *testing.T, opts *CertOptions) (*ecdsa.PrivateKey, *Attestation, *x509.Certificate) {
	t.Helper()
	key, att := testKeyAndAttestation(t)
	certDER, err := CreateAttestedCert(key, att, opts)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return key, att, cert
}

// requireARMTLSExtension asserts that the certificate contains the ARmTLS
// attestation extension.
func requireARMTLSExtension(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDARMTLSAttestation) {
			return
		}
	}
	t.Error("ARmTLS attestation extension not found in certificate")
}

func TestGenerateKeyPair(t *testing.T) {
	key, reportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	if key == nil {
		t.Fatal("key is nil")
	}

	expected, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reportData != expected {
		t.Error("reportData does not match key")
	}
}

func TestCreateAttestedCert(t *testing.T) {
	_, _, cert := testAttestedCert(t, &CertOptions{
		TTL:      1 * time.Hour,
		DNSNames: []string{"test.local"},
	})

	requireARMTLSExtension(t, cert)

	if cert.Subject.CommonName != "ARmTLS Workload" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "ARmTLS Workload")
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "test.local" {
		t.Errorf("DNSNames = %v, want [test.local]", cert.DNSNames)
	}
}

func TestCreateAttestedCertDefaultOpts(t *testing.T) {
	_, _, cert := testAttestedCert(t, nil)

	actualDuration := cert.NotAfter.Sub(cert.NotBefore)
	if actualDuration < DefaultCertTTL-time.Minute || actualDuration > DefaultCertTTL+time.Minute {
		t.Errorf("cert duration = %v, want ~%v", actualDuration, DefaultCertTTL)
	}
}

func TestSentinelErrors(t *testing.T) {
	t.Run("ErrNoAttestation", func(t *testing.T) {
		// Certificate without ARmTLS extension.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// A currently valid certificate, so the missing extension — not the
		// validity window — is what VerifyCert rejects.
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}

		_, err = VerifyCert(cert, nil, nil)
		if !errors.Is(err, ErrNoAttestation) {
			t.Errorf("got %v, want errors.Is ErrNoAttestation", err)
		}
	})
}

func TestSNPMeasurementSizeConstant(t *testing.T) {
	if SNPMeasurementSize != 48 {
		t.Errorf("SNPMeasurementSize = %d, want 48", SNPMeasurementSize)
	}
}

// embeddedEnvelopeCert builds an ARmTLS certificate whose attestation extension
// carries an AttestationEvidence envelope for the given platform. Returns the
// parsed cert and the SHA-384(pubkey) that the attestation-api would expect to
// see bound through the report.
func embeddedEnvelopeCert(t *testing.T, platform teetypes.PlatformType, evidence json.RawMessage) (*x509.Certificate, [64]byte) {
	t.Helper()
	key, expectedReportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := json.Marshal(teetypes.AttestationEvidence{Platform: platform, Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	teeType := TEETypeSEVSNP
	if platform == teetypes.PlatformTDX || platform == teetypes.PlatformAzTDX {
		teeType = TEETypeTDX
	}
	certDER, err := CreateAttestedCert(key, &Attestation{Family: teeType, Report: embedded}, nil)
	if err != nil {
		t.Fatalf("CreateAttestedCert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, expectedReportData
}

// embeddedAzureCert builds an ARmTLS certificate whose attestation extension
// carries an az-snp envelope (the post-PR-98 wire shape).
func embeddedAzureCert(t *testing.T) (*x509.Certificate, [64]byte) {
	t.Helper()
	return embeddedEnvelopeCert(t, teetypes.PlatformAzSNP, json.RawMessage(`{"hcl_report":"fake","tpm_quote":{"message":"fake"}}`))
}

func TestVerifyCertEmbeddedAzureEvidenceUsesAttestationApi(t *testing.T) {
	key, expectedReportData, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	evidenceJSON := json.RawMessage(`{"hcl_report":"fake","tpm_quote":{"message":"fake"}}`)
	embedded, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformAzSNP,
		Evidence: evidenceJSON,
	})
	if err != nil {
		t.Fatal(err)
	}

	certDER, err := CreateAttestedCert(key, &Attestation{Family: TEETypeSEVSNP, Report: embedded}, nil)
	if err != nil {
		t.Fatalf("CreateAttestedCert: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	stub := mockapi.New(t)
	verdict := mockapi.PassingVerdict(hex.EncodeToString(measurement))
	verdict.Claims.PlatformData = map[string]any{"source": "test"}
	stub.SetVerdict(verdict)

	result, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: stub.URL(),
		Policy: remote.Policy{
			Measurements: [][]byte{measurement},
		},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatal("attestation-api /verify was not called")
	}
	req := reqs[0]
	// attestation-api wants platform at the top level and Evidence as the
	// platform-specific evidence, not a nested AttestationEvidence envelope.
	if req.Platform != teetypes.PlatformAzSNP {
		t.Fatalf("platform = %q, want az-snp", req.Platform)
	}
	if string(req.Evidence) != string(evidenceJSON) {
		t.Fatalf("evidence = %s, want the platform-specific evidence %s (not a nested envelope)", req.Evidence, evidenceJSON)
	}
	if req.Params == nil || len(req.Params.ExpectedReportData) == 0 {
		t.Fatal("missing expected report data")
	}
	// az-snp binds via a TPM quote whose nonce is the 48-byte SHA-384 digest,
	// so exactly those 48 bytes must be sent — not the zero-padded 64-byte
	// form, which fails attestation-api with a nonce-length error.
	if got := req.Params.ExpectedReportData; !bytes.Equal(got, expectedReportData[:sha512.Size384]) {
		t.Fatalf("expected_report_data = %x (%d bytes), want %x (%d bytes)", got, len(got), expectedReportData[:sha512.Size384], sha512.Size384)
	}
	if !bytes.Equal(result.ReportData[:], expectedReportData[:]) {
		t.Fatalf("ReportData = %x, want %x", result.ReportData, expectedReportData)
	}
	if !bytes.Equal(result.Measurement[:], measurement) {
		t.Fatalf("Measurement = %x, want %x", result.Measurement, measurement)
	}
}

func TestVerifyCertEmbeddedTDXEvidenceEnforcesMRTD(t *testing.T) {
	cert, expectedReportData := embeddedEnvelopeCert(t, teetypes.PlatformTDX, json.RawMessage(`{"quote":"fake"}`))
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)

	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(mrtd)))

	// A TCB floor names SEV-SNP components, so TDX evidence is refused rather
	// than verified under no floor.
	if _, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: stub.URL(),
		Policy: remote.Policy{
			Measurements: [][]byte{mrtd},
			MinTcb:       &teetypes.SnpTcb{Bootloader: 1},
		},
	}, nil); err == nil {
		t.Fatal("a TCB floor against TDX evidence must be refused")
	}

	result, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: stub.URL(),
		Policy: remote.Policy{
			Measurements: [][]byte{mrtd},
		},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify calls = %d, want 1", len(reqs))
	}
	observed := reqs[0]
	if observed.Platform != teetypes.PlatformTDX {
		t.Fatalf("platform = %q, want tdx", observed.Platform)
	}
	if observed.Params == nil || len(observed.Params.ExpectedReportData) == 0 {
		t.Fatal("missing expected report data")
	}
	if got := observed.Params.ExpectedReportData; !bytes.Equal(got, expectedReportData[:sha512.Size384]) {
		t.Fatalf("expected_report_data = %x, want %x", got, expectedReportData[:sha512.Size384])
	}
	if observed.Params.MinTcb != nil {
		t.Fatal("min_tcb must not be sent on the TDX path")
	}
	if result.TEEType != TEETypeTDX {
		t.Fatalf("TEEType = %v, want TDX", result.TEEType)
	}
	if !bytes.Equal(result.ReportData[:], expectedReportData[:]) {
		t.Fatalf("ReportData = %x, want %x", result.ReportData, expectedReportData)
	}
	if !bytes.Equal(result.Measurement[:], mrtd) {
		t.Fatalf("Measurement = %x, want MRTD %x", result.Measurement, mrtd)
	}

	wrongMRTD := bytes.Repeat([]byte{0x99}, sha512.Size384)
	_, err = VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: stub.URL(),
		Policy: remote.Policy{
			Measurements: [][]byte{wrongMRTD},
		},
	}, nil)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("wrong MRTD: got %v, want ErrPolicyViolation", err)
	}
}

// TestVerifyCertEmbeddedGcpSnpEvidenceUsesAttestationApi mirrors the az-snp
// online path for GKE SEV-SNP: a gcp-snp evidence envelope passes the platform
// gate and is forwarded to the attestation-api /verify endpoint, not rejected
// as an unsupported TEE. (Evidence unwrapping is covered by the az-snp test.)
func TestVerifyCertEmbeddedGcpSnpEvidenceUsesAttestationApi(t *testing.T) {
	cert, _ := embeddedEnvelopeCert(t, teetypes.PlatformGcpSNP, json.RawMessage(`{"attestation_report":"fake"}`))

	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(measurement)))

	if _, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: stub.URL(),
		Policy: remote.Policy{
			Measurements: [][]byte{measurement},
		},
	}, nil); err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify calls = %d, want 1", len(reqs))
	}
	if reqs[0].Platform != teetypes.PlatformGcpSNP {
		t.Fatalf("platform = %q, want gcp-snp", reqs[0].Platform)
	}
}

// TestVerifyCertEmbeddedAzureNegativePaths covers the online-verification
// failure modes. Each case mutates either the policy or the mocked /verify
// response and asserts that the verifier maps it to the expected sentinel
// error. A bug that flipped any of these to a "pass" would be silent
// downgrade of the attestation policy.
func TestVerifyCertEmbeddedAzureNegativePaths(t *testing.T) {
	cert, _ := embeddedAzureCert(t)
	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	allowedMeasurements := [][]byte{measurement}

	t.Run("422 verification_failed is refused", func(t *testing.T) {
		stub := mockapi.New(t)
		stub.SetVerifyError(mockapi.VerificationFailed("report signature does not verify"))
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		var apiErr *remote.APIError
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnprocessableEntity {
			t.Fatalf("got %v, want a 422 *remote.APIError", err)
		}
	})

	// Defense in depth: a self-contradicting 200 must still be refused. The
	// production refusal shape is the 422 above (mockapi.Verdict).
	t.Run("signature_valid=false maps to ErrSignatureInvalid", func(t *testing.T) {
		stub := mockapi.New(t)
		verdict := mockapi.PassingVerdict(hex.EncodeToString(measurement))
		verdict.SignatureValid = false
		stub.SetVerdict(verdict)
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("got %v, want ErrSignatureInvalid", err)
		}
	})

	t.Run("report_data_match=nil maps to ErrKeyBinding", func(t *testing.T) {
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.Verdict{
			SignatureValid: true,
			Claims:         teetypes.Claims{LaunchDigest: hex.EncodeToString(measurement)},
		})
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrKeyBinding) {
			t.Fatalf("got %v, want ErrKeyBinding", err)
		}
	})

	// Defense in depth: a self-contradicting 200 must still be refused. The
	// production refusal shape is the 422 above (mockapi.Verdict).
	t.Run("report_data_match=false maps to ErrKeyBinding", func(t *testing.T) {
		stub := mockapi.New(t)
		verdict := mockapi.PassingVerdict(hex.EncodeToString(measurement))
		match := false
		verdict.ReportDataMatch = &match
		stub.SetVerdict(verdict)
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrKeyBinding) {
			t.Fatalf("got %v, want ErrKeyBinding", err)
		}
	})

	t.Run("empty attestation-api URL rejects embedded evidence", func(t *testing.T) {
		_, err := VerifyCert(cert, &VerifyPolicy{Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})

	t.Run("launch_digest missing with pinned measurements is rejected", func(t *testing.T) {
		stub := mockapi.New(t)
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("launch_digest not in allowed set is rejected", func(t *testing.T) {
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(bytes.Repeat([]byte{0x99}, SNPMeasurementSize))))
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrPolicyViolation) {
			t.Fatalf("got %v, want ErrPolicyViolation", err)
		}
	})

	t.Run("launch_digest not hex is rejected", func(t *testing.T) {
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.PassingVerdict("not-hex"))
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})

	t.Run("launch_digest wrong length is rejected", func(t *testing.T) {
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(bytes.Repeat([]byte{0x11}, 32))))
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})

	t.Run("attestation-api HTTP 500 surfaces an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		_, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: srv.URL, Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if err == nil {
			t.Fatal("expected error from 500 response")
		}
	})

	t.Run("AttestationVerifyTimeout bounds the call", func(t *testing.T) {
		match := true
		slow := remote.VerifyResponse{Result: teetypes.VerificationResult{
			Platform:        teetypes.PlatformAzSNP,
			SignatureValid:  true,
			ReportDataMatch: &match,
			Claims:          teetypes.Claims{LaunchDigest: hex.EncodeToString(measurement)},
		}}
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(200 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(slow)
		}))
		defer srv.Close()
		start := time.Now()
		_, err := VerifyCert(cert, &VerifyPolicy{
			AttestationApiURL:        srv.URL,
			AttestationVerifyTimeout: 25 * time.Millisecond,
			Policy: remote.Policy{
				Measurements: allowedMeasurements,
			},
		}, nil)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("expected timeout error")
		}
		if elapsed > 150*time.Millisecond {
			t.Fatalf("verify took %s, expected <150ms (timeout not enforced)", elapsed)
		}
	})

	t.Run("the TCB floor reaches /verify", func(t *testing.T) {
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(measurement)))
		floor := teetypes.SnpTcb{Bootloader: 0x11, Tee: 0x22, Snp: 0x33, Microcode: 0x44}
		_, err := VerifyCert(cert, &VerifyPolicy{
			AttestationApiURL: stub.URL(),
			Policy: remote.Policy{
				Measurements: allowedMeasurements,
				MinTcb:       &floor,
			},
		}, nil)
		if err != nil {
			t.Fatalf("VerifyCert: %v", err)
		}
		reqs := stub.VerifyRequests()
		if len(reqs) != 1 {
			t.Fatalf("/verify calls = %d, want 1", len(reqs))
		}
		observed := reqs[0]
		if observed.Params == nil || observed.Params.MinTcb == nil {
			t.Fatal("MinTcb was not forwarded to /verify")
		}
		if *observed.Params.MinTcb != floor {
			t.Fatalf("MinTcb = %+v, want %+v", *observed.Params.MinTcb, floor)
		}
	})

	t.Run("az-tdx evidence with a mismatched SEV-SNP TEE type is rejected", func(t *testing.T) {
		// az-tdx is a TDX-family platform; carrying it in a cert that declares
		// the SEV-SNP TEE type is a family mismatch and must fail closed at
		// parse time rather than be verified under SNP rules.
		key, _, err := GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := json.Marshal(teetypes.AttestationEvidence{
			Platform: teetypes.PlatformAzTDX,
			Evidence: json.RawMessage(`{"any":"shape"}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		certDER, err := CreateAttestedCert(key, &Attestation{Family: TEETypeSEVSNP, Report: embedded}, nil)
		if err != nil {
			t.Fatalf("CreateAttestedCert: %v", err)
		}
		tdxCert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatalf("ParseCertificate: %v", err)
		}
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(measurement)))
		_, err = VerifyCert(tdxCert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: allowedMeasurements}}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})
}

// TestVerifyCertEmbeddedAzTdxEvidence covers the Azure-vTPM TDX (az-tdx) online
// path: the vTPM HCL report wraps a TD quote, the mesh peer presents an az-tdx
// envelope under the TDX TEE type, and the verifier binds the key through the
// 48-byte vTPM nonce (like az-snp) while enforcing the MRTD as launch digest.
func TestVerifyCertEmbeddedAzTdxEvidence(t *testing.T) {
	cert, expectedReportData := embeddedEnvelopeCert(t, teetypes.PlatformAzTDX,
		json.RawMessage(`{"hcl_report":"fake","td_quote":"fake","tpm_quote":{"message":"fake"}}`))
	mrtd := bytes.Repeat([]byte{0x42}, sha512.Size384)

	stub := mockapi.New(t)
	stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(mrtd)))

	result, err := VerifyCert(cert, &VerifyPolicy{
		AttestationApiURL: stub.URL(),
		Policy: remote.Policy{
			Measurements: [][]byte{mrtd},
		},
	}, nil)
	if err != nil {
		t.Fatalf("VerifyCert: %v", err)
	}
	reqs := stub.VerifyRequests()
	if len(reqs) != 1 {
		t.Fatalf("/verify calls = %d, want 1", len(reqs))
	}
	observed := reqs[0]
	// az-tdx binds via the 48-byte vTPM nonce, not the full 64-byte REPORTDATA.
	if got := observed.Params.ExpectedReportData; !bytes.Equal(got, expectedReportData[:sha512.Size384]) {
		t.Fatalf("expected_report_data = %x (%d bytes), want the 48-byte digest %x", got, len(got), expectedReportData[:sha512.Size384])
	}
	if result.TEEType != TEETypeTDX {
		t.Fatalf("TEEType = %v, want TDX", result.TEEType)
	}
	if !bytes.Equal(result.Measurement[:], mrtd) {
		t.Fatalf("Measurement = %x, want MRTD %x", result.Measurement, mrtd)
	}

	wrongMRTD := bytes.Repeat([]byte{0x99}, sha512.Size384)
	_, err = VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: [][]byte{wrongMRTD}}}, nil)
	if !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("wrong MRTD: got %v, want ErrPolicyViolation", err)
	}
}

// TestVerifyCertBareSNPUsesAttestationApi covers the bare-metal SNP shape:
// the ARmTLS extension carries a raw report, which the verifier must wrap in
// the "snp" evidence envelope for attestation-api /verify. There is no
// in-process verification, so without an AttestationApiURL the verifier must
// fail closed rather than fall back.
func TestVerifyCertBareSNPUsesAttestationApi(t *testing.T) {
	key, att, cert := testAttestedCert(t, nil)
	expectedReportData, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	report := att.Report
	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)

	t.Run("raw report is wrapped in the snp envelope", func(t *testing.T) {
		stub := mockapi.New(t)
		stub.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(measurement)))

		result, err := VerifyCert(cert, &VerifyPolicy{AttestationApiURL: stub.URL(), Policy: remote.Policy{Measurements: [][]byte{measurement}}}, nil)
		if err != nil {
			t.Fatalf("VerifyCert: %v", err)
		}
		reqs := stub.VerifyRequests()
		if len(reqs) != 1 {
			t.Fatalf("/verify calls = %d, want 1", len(reqs))
		}
		observed := reqs[0]
		if observed.Platform != teetypes.PlatformSNP {
			t.Fatalf("platform = %q, want snp", observed.Platform)
		}
		var inner struct {
			AttestationReport string `json:"attestation_report"`
		}
		if err := json.Unmarshal(observed.Evidence, &inner); err != nil {
			t.Fatalf("decode snp evidence: %v", err)
		}
		sent, err := base64.StdEncoding.DecodeString(inner.AttestationReport)
		if err != nil {
			t.Fatalf("decode attestation_report: %v", err)
		}
		if !bytes.Equal(sent, report) {
			t.Fatal("attestation_report does not round-trip the raw report")
		}
		if observed.Params == nil || len(observed.Params.ExpectedReportData) == 0 {
			t.Fatal("missing expected report data")
		}
		if got := observed.Params.ExpectedReportData; !bytes.Equal(got, expectedReportData[:sha512.Size384]) {
			t.Fatalf("expected_report_data = %x, want %x", got, expectedReportData[:sha512.Size384])
		}
		if !bytes.Equal(result.Measurement[:], measurement) {
			t.Fatalf("Measurement = %x, want %x", result.Measurement, measurement)
		}
	})

	t.Run("no attestation-api URL fails closed", func(t *testing.T) {
		_, err := VerifyCert(cert, &VerifyPolicy{Policy: remote.Policy{Measurements: [][]byte{measurement}}}, nil)
		if !errors.Is(err, ErrInvalidReport) {
			t.Fatalf("got %v, want ErrInvalidReport", err)
		}
	})
}

func TestPublicKeyFromCertCurves(t *testing.T) {
	makeCert := func(t *testing.T, curve elliptic.Curve) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	tests := []struct {
		name    string
		curve   elliptic.Curve
		wantErr bool
	}{
		{"P-256 accepted", elliptic.P256(), false},
		{"P-384 accepted", elliptic.P384(), false},
		{"P-521 rejected", elliptic.P521(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := publicKeyFromCert(makeCert(t, tt.curve))
			if (err != nil) != tt.wantErr {
				t.Fatalf("publicKeyFromCert err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyAttestationUnsupportedKey(t *testing.T) {
	_, att := testKeyAndAttestation(t)
	stub := mockapi.New(t)

	_, err := VerifyAttestation("not-a-key", att, &VerifyPolicy{AttestationApiURL: stub.URL()}, nil)
	if err == nil || !strings.Contains(err.Error(), "compute expected REPORTDATA") {
		t.Fatalf("got %v, want REPORTDATA computation error", err)
	}
}

func TestVerifyResultPlatformInfo(t *testing.T) {
	measurement := bytes.Repeat([]byte{0x42}, SNPMeasurementSize)
	newPolicy := func(url string) *VerifyPolicy {
		return &VerifyPolicy{AttestationApiURL: url, Policy: remote.Policy{Measurements: [][]byte{measurement}}}
	}
	stubWithPlatformData := func(t *testing.T, platformData map[string]any) *mockapi.Stub {
		t.Helper()
		stub := mockapi.New(t)
		verdict := mockapi.PassingVerdict(hex.EncodeToString(measurement))
		verdict.Claims.PlatformData = platformData
		stub.SetVerdict(verdict)
		return stub
	}

	t.Run("SNP platform data is surfaced", func(t *testing.T) {
		cert, _ := embeddedAzureCert(t)
		srv := stubWithPlatformData(t, map[string]any{"source": "unit"})
		result, err := VerifyCert(cert, newPolicy(srv.URL()), nil)
		if err != nil {
			t.Fatalf("VerifyCert: %v", err)
		}
		var pd struct {
			Source string `json:"source"`
		}
		if err := json.Unmarshal(result.PlatformInfo, &pd); err != nil {
			t.Fatalf("PlatformInfo = %q: %v", result.PlatformInfo, err)
		}
		if pd.Source != "unit" {
			t.Fatalf("PlatformInfo source = %q, want %q", pd.Source, "unit")
		}
	})

	t.Run("null SNP platform data is dropped", func(t *testing.T) {
		cert, _ := embeddedAzureCert(t)
		srv := stubWithPlatformData(t, nil)
		result, err := VerifyCert(cert, newPolicy(srv.URL()), nil)
		if err != nil {
			t.Fatalf("VerifyCert: %v", err)
		}
		if result.PlatformInfo != nil {
			t.Fatalf("PlatformInfo = %q, want nil", result.PlatformInfo)
		}
	})

	t.Run("TDX platform data is not surfaced", func(t *testing.T) {
		cert, _ := embeddedEnvelopeCert(t, teetypes.PlatformTDX, json.RawMessage(`{"quote":"fake"}`))
		srv := stubWithPlatformData(t, map[string]any{"source": "unit"})
		result, err := VerifyCert(cert, newPolicy(srv.URL()), nil)
		if err != nil {
			t.Fatalf("VerifyCert: %v", err)
		}
		if result.PlatformInfo != nil {
			t.Fatalf("PlatformInfo = %q, want nil on the TDX path", result.PlatformInfo)
		}
	})
}
