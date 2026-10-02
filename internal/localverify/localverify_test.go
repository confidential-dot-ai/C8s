package localverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-sev-guest/verify/trust"

	"github.com/confidential-dot-ai/c8s/pkg/ratls"
)

// envelopeFixture loads a real captured {platform, evidence} fixture (vendored
// from attestation-go / c8s-verify-js testdata; also used by the verify
// command's tests).
func envelopeFixture(t *testing.T, name string) (platform string, evidence json.RawMessage) {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Platform string          `json:"platform"`
		Evidence json.RawMessage `json:"evidence"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	return env.Platform, env.Evidence
}

// TestVerifyRealAzSnpEvidence_MeasurementPin drives real az-snp evidence (vTPM
// quote extraData = ASCII "challenge", VCEK inline, so it verifies fully
// offline) through the engine and exercises the launch-digest pin — the policy
// this package enforces on attestation-go's claims.
func TestVerifyRealAzSnpEvidence_MeasurementPin(t *testing.T) {
	platform, evidence := envelopeFixture(t, "azsnp-evidence-v1.json")
	if platform != "az-snp" {
		t.Fatalf("platform = %q, want az-snp", platform)
	}
	anchor := Params{ExpectedReportData: []byte("challenge")}

	res, err := Verify(context.Background(), platform, evidence, anchor)
	if err != nil {
		t.Fatalf("az-snp evidence with its bound nonce must verify: %v", err)
	}
	digest, err := hex.DecodeString(res.Claims.LaunchDigest)
	if err != nil || len(digest) == 0 {
		t.Fatalf("verified evidence must report a launch digest, got %q", res.Claims.LaunchDigest)
	}

	pinned := anchor
	pinned.Measurements = [][]byte{digest}
	if _, err := Verify(context.Background(), platform, evidence, pinned); err != nil {
		t.Fatalf("the evidence's own launch digest must satisfy the pin: %v", err)
	}

	mismatched := anchor
	mismatched.Measurements = [][]byte{bytes.Repeat([]byte{0xAA}, len(digest))}
	if _, err := Verify(context.Background(), platform, evidence, mismatched); !errors.Is(err, ErrMeasurementNotAllowed) {
		t.Fatalf("want ErrMeasurementNotAllowed, got: %v", err)
	}

	wrongAnchor := Params{ExpectedReportData: []byte("not-the-nonce")}
	if _, err := Verify(context.Background(), platform, evidence, wrongAnchor); err == nil {
		t.Fatal("a wrong binding anchor must fail closed")
	}
}

func TestDefaultKDSCacheDir_EnvOverrideAndDisable(t *testing.T) {
	t.Setenv(kdsCacheDirEnv, "/tmp/c8s-kds-test")
	if got := defaultKDSCacheDir(); got != "/tmp/c8s-kds-test" {
		t.Fatalf("override: got %q", got)
	}
	t.Setenv(kdsCacheDirEnv, "")
	if got := defaultKDSCacheDir(); got != "" {
		t.Fatalf("empty override must disable the cache, got %q", got)
	}
}

type kdsGetterFunc func(string) ([]byte, error)

func (f kdsGetterFunc) Get(url string) ([]byte, error) { return f(url) }

// Verify must reuse collateral across calls when C8s configures the shared cache.
func TestVerify_ReusesCachedVCEK(t *testing.T) {
	parts := loadGenoaParts(t)
	vcek := parts.vcek
	parts.vcek = nil
	evidence := parts.evidence(t)
	t.Setenv(kdsCacheDirEnv, t.TempDir())

	calls := 0
	orig := kdsGetter
	t.Cleanup(func() { kdsGetter = orig })
	kdsGetter = func() trust.HTTPSGetter {
		return kdsGetterFunc(func(string) ([]byte, error) {
			calls++
			if calls > 1 {
				return nil, errors.New("KDS unavailable")
			}
			return vcek, nil
		})
	}

	for attempt := 1; attempt <= 2; attempt++ {
		res, err := Verify(context.Background(), "snp", evidence, Params{})
		if err != nil {
			t.Fatalf("verification %d: %v", attempt, err)
		}
		if !res.SignatureValid {
			t.Fatalf("verification %d: signature_valid must be true", attempt)
		}
	}
	if calls != 1 {
		t.Fatalf("KDS fetched %d times, want 1", calls)
	}
}

// TestVerify_KDSFailureIsCollateralError proves a bare SNP report (cert_chain
// stripped, forcing the AMD KDS fetch) under an expired context classifies as
// CollateralError — no verdict — and returns promptly. A cancelled context
// aborts http before any I/O, so no network is touched.
func TestVerify_KDSFailureIsCollateralError(t *testing.T) {
	// This test needs a fetch even if the user already cached the fixture's VCEK.
	t.Setenv(kdsCacheDirEnv, "")
	platform, evidence := envelopeFixture(t, "snp-evidence-genoa.json")
	var inner struct {
		AttestationReport string `json:"attestation_report"`
	}
	if err := json.Unmarshal(evidence, &inner); err != nil {
		t.Fatal(err)
	}
	bare, err := json.Marshal(map[string]string{"attestation_report": inner.AttestationReport})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err = Verify(ctx, platform, bare, Params{})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("expired ctx took %v, want prompt return", elapsed)
	}
	if _, ok := errors.AsType[*CollateralError](err); !ok {
		t.Fatalf("KDS fetch failure must classify as CollateralError, got: %v", err)
	}
}

// TestVerify_NoAnchorSkipsBindingCheck: with no ExpectedReportData the binding
// defense-in-depth must not fire (ReportDataMatch stays nil), so anchor-less
// verification of otherwise-good evidence succeeds.
func TestVerify_NoAnchorSkipsBindingCheck(t *testing.T) {
	platform, evidence := envelopeFixture(t, "azsnp-evidence-v1.json")
	res, err := Verify(context.Background(), platform, evidence, Params{})
	if err != nil {
		t.Fatalf("anchor-less verification must succeed: %v", err)
	}
	if !res.SignatureValid {
		t.Fatal("signature_valid must be true")
	}
}

// TestVerify_InlineVcekVerifiesOffline: evidence that ships its VCEK must take
// the offline envelope path, never the KDS-fetch path. A cancelled context
// proves it: the KDS path would classify as CollateralError, the offline path
// verifies instantly.
func TestVerify_InlineVcekVerifiesOffline(t *testing.T) {
	platform, evidence := envelopeFixture(t, "snp-evidence-genoa.json")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	res, err := Verify(ctx, platform, evidence, Params{})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("inline-VCEK verification took %v, want offline (no KDS fetch)", elapsed)
	}
	if err != nil {
		t.Fatalf("inline-VCEK evidence must verify offline: %v", err)
	}
	if !res.SignatureValid {
		t.Fatal("signature_valid must be true")
	}
}

func TestCertEnvelope(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("attested cert yields envelope and key-bound anchor", func(t *testing.T) {
		att := &ratls.Attestation{Family: ratls.TEETypeSEVSNP, Report: make([]byte, ratls.SNPReportSize)}
		der, err := ratls.CreateAttestedCert(key, att, nil)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		platform, evidence, erd, err := CertEnvelope(cert)
		if err != nil {
			t.Fatalf("CertEnvelope: %v", err)
		}
		if platform != "snp" {
			t.Errorf("platform = %q, want snp", platform)
		}
		if !bytes.Contains(evidence, []byte("attestation_report")) {
			t.Errorf("evidence object missing the report: %s", evidence)
		}
		rd, err := ratls.ReportDataForKey(cert.PublicKey, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(erd, rd[:48]) {
			t.Errorf("erd = %x, want the unpadded key anchor %x", erd, rd[:48])
		}
	})

	t.Run("cert without attestation extension is rejected", func(t *testing.T) {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := CertEnvelope(cert); err == nil {
			t.Fatal("expected an error for a plain certificate")
		}
	})

	t.Run("raw TDX cert is rejected", func(t *testing.T) {
		att := &ratls.Attestation{Family: ratls.TEETypeTDX, Report: []byte{1}}
		der, err := ratls.CreateAttestedCert(key, att, nil)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := CertEnvelope(cert); err == nil {
			t.Fatal("expected an error for a raw TDX report in a cert")
		}
	})
}
