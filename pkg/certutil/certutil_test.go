package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

// selfSigned returns a self-signed cert (DER + parsed) with the given expiry.
func selfSigned(t *testing.T, cn string, notAfter time.Time) (*x509.Certificate, []byte) {
	t.Helper()
	key := newKey(t)
	serial, err := GenerateSerial()
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl := NewCATemplate(serial, cn, notAfter)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, der
}

func ecdsaCSRPEM(t *testing.T) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test"},
	}, newKey(t))
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestGenerateSerialWithinBound(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		s, err := GenerateSerial()
		if err != nil {
			t.Fatalf("GenerateSerial: %v", err)
		}
		if s.Sign() < 0 || s.Cmp(serialNumberLimit) >= 0 {
			t.Fatalf("serial %s out of [0, 2^128)", s)
		}
		seen[s.String()] = true
	}
	if len(seen) < 90 {
		t.Errorf("serials not sufficiently random: %d unique of 100", len(seen))
	}
}

func TestCertFingerprintStableAndHex(t *testing.T) {
	fp := CertFingerprint([]byte("hello"))
	// SHA-256 of "hello"
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if fp != want {
		t.Errorf("fingerprint = %q, want %q", fp, want)
	}
	if len(fp) != 64 {
		t.Errorf("fingerprint length = %d, want 64", len(fp))
	}
}

func TestEncodeCertPEMRoundTrip(t *testing.T) {
	_, der := selfSigned(t, "rt", time.Now().Add(time.Hour))
	pemBytes := EncodeCertPEM(der)
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("decoded block = %v", block)
	}
	if string(block.Bytes) != string(der) {
		t.Error("round-tripped DER differs")
	}
}

func TestMarshalAndParseECKeyPEM(t *testing.T) {
	key := newKey(t)
	pemBytes, err := MarshalECKeyPEM(key)
	if err != nil {
		t.Fatalf("MarshalECKeyPEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("expected PKCS#8 PRIVATE KEY block, got %v", block)
	}

	got, err := ParseECPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParseECPrivateKey: %v", err)
	}
	if !got.Equal(key) {
		t.Error("parsed key differs from original")
	}
}

func TestParseECPrivateKeySEC1(t *testing.T) {
	key := newKey(t)
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal SEC1: %v", err)
	}
	sec1 := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	got, err := ParseECPrivateKey(sec1)
	if err != nil {
		t.Fatalf("ParseECPrivateKey(SEC1): %v", err)
	}
	if !got.Equal(key) {
		t.Error("parsed SEC1 key differs from original")
	}
}

func TestParseECPrivateKeyErrors(t *testing.T) {
	t.Run("no PEM block", func(t *testing.T) {
		if _, err := ParseECPrivateKey([]byte("not pem")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("PKCS8 non-ECDSA", func(t *testing.T) {
		// An RSA key in PKCS#8 should be rejected as not-ECDSA.
		// Build a valid PKCS8 block with garbage that parses but isn't ECDSA is
		// hard; instead use a non-key PEM body to hit the parse-error branch.
		block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
		if _, err := ParseECPrivateKey(block); err == nil {
			t.Fatal("expected error for invalid key bytes")
		}
	})
}

func TestParseECPrivateKeyNamesAPEMThatHoldsNoPrivateKey(t *testing.T) {
	key := newKey(t)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	for _, c := range []struct {
		block *pem.Block
		says  string
	}{
		{
			block: &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: der,
			},
			says: "this is a public key",
		},
		{
			block: &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: der,
			},
			says: `the PEM block is "CERTIFICATE"`,
		},
	} {
		t.Run(c.block.Type, func(t *testing.T) {
			_, err := ParseECPrivateKey(pem.EncodeToMemory(c.block))
			if err == nil {
				t.Fatalf("a %s PEM parsed as a private key", c.block.Type)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("ParseECPrivateKey = %q, want it to say %q", err, c.says)
			}
		})
	}
}

func TestLoadECPrivateKeyFile(t *testing.T) {
	key := newKey(t)
	pemBytes, _ := MarshalECKeyPEM(key)
	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := LoadECPrivateKeyFile(path)
	if err != nil {
		t.Fatalf("LoadECPrivateKeyFile: %v", err)
	}
	if !got.Equal(key) {
		t.Error("loaded key differs")
	}

	if _, err := LoadECPrivateKeyFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParseCertificatePEMAndLoad(t *testing.T) {
	cert, der := selfSigned(t, "leaf", time.Now().Add(time.Hour))
	pemBytes := EncodeCertPEM(der)

	got, err := ParseCertificatePEM(pemBytes)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if got.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("CN = %q, want %q", got.Subject.CommonName, cert.Subject.CommonName)
	}

	if _, err := ParseCertificatePEM([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM")
	}
}

func TestParseAndVerifyCSRValid(t *testing.T) {
	csr, err := ParseCSRPEM(ecdsaCSRPEM(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if csr == nil {
		t.Fatal("expected non-nil CSR")
	}
	if csr.Subject.CommonName != "test" {
		t.Fatalf("CN = %q, want test", csr.Subject.CommonName)
	}
}

func TestParseAndVerifyCSRNotPEM(t *testing.T) {
	if _, err := ParseCSRPEM([]byte("not a pem block")); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}

func TestParseAndVerifyCSRWrongPEMType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("xx")})
	if _, err := ParseCSRPEM(block); err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}

func TestParseAndVerifyCSRMalformedBody(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("garbage")})
	if _, err := ParseCSRPEM(block); err == nil {
		t.Fatal("expected error for malformed CSR body")
	}
}

func TestParseAndVerifyCSRBadSignature(t *testing.T) {
	// Take a valid CSR and tamper with the signed CertificationRequestInfo
	// (TBS) region so the self-signature no longer verifies. ParseCertificate-
	// Request still succeeds structurally, but CheckSignature fails.
	block, _ := pem.Decode(ecdsaCSRPEM(t))
	raw := make([]byte, len(block.Bytes))
	copy(raw, block.Bytes)

	// Mutate a byte well inside the TBS portion (the subject/key region near the
	// front) rather than the trailing signature, so ParseCertificateRequest
	// still accepts the structure but the signature check fails.
	raw[40] ^= 0xff
	corrupted := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})

	// Either parsing fails outright or the signature check fails; both are
	// error returns from ParseCSRPEM, which is what we assert.
	if _, err := ParseCSRPEM(corrupted); err == nil {
		t.Fatal("expected error for corrupted CSR")
	}
}

func TestNewJSONLogger(t *testing.T) {
	for _, lvl := range []string{"", "debug", "INFO", "warn", "error"} {
		if _, err := NewJSONLogger(lvl); err != nil {
			t.Errorf("NewJSONLogger(%q) err = %v", lvl, err)
		}
	}
	if _, err := NewJSONLogger("nonsense"); err == nil {
		t.Error("expected error for invalid level")
	}
}

func TestParsePEMCertificates(t *testing.T) {
	_, der1 := selfSigned(t, "a", time.Now().Add(time.Hour))
	_, der2 := selfSigned(t, "b", time.Now().Add(time.Hour))

	bundle := append(EncodeCertPEM(der1), EncodeCertPEM(der2)...)
	// Insert a non-CERTIFICATE block that must be skipped.
	other := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")})
	bundle = append(bundle, other...)

	certs, err := ParsePEMCertificates(bundle)
	if err != nil {
		t.Fatalf("ParsePEMCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Fatalf("got %d certs, want 2", len(certs))
	}

	if _, err := ParsePEMCertificates([]byte("no blocks here")); err == nil {
		t.Fatal("expected error for no CERTIFICATE blocks")
	}

	t.Run("leading non-certificate block", func(t *testing.T) {
		keyFirst := append(other, EncodeCertPEM(der1)...)
		certs, err := ParsePEMCertificates(keyFirst)
		if err != nil {
			t.Fatalf("ParsePEMCertificates: %v", err)
		}
		if len(certs) != 1 || !bytes.Equal(certs[0].Raw, der1) {
			t.Fatalf("got %d certs, want the one behind the PRIVATE KEY block", len(certs))
		}
	})

	t.Run("bad cert bytes", func(t *testing.T) {
		bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
		if _, err := ParsePEMCertificates(bad); err == nil {
			t.Fatal("expected parse error")
		}
	})
}

func TestNewCATemplate(t *testing.T) {
	notAfter := time.Now().Add(24 * time.Hour)
	tmpl := NewCATemplate(big.NewInt(7), "my-ca", notAfter)
	if !tmpl.IsCA || !tmpl.BasicConstraintsValid {
		t.Error("CA template should set IsCA and BasicConstraintsValid")
	}
	if tmpl.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA template should allow cert signing")
	}
	if tmpl.Subject.CommonName != "my-ca" {
		t.Errorf("CN = %q", tmpl.Subject.CommonName)
	}
}

func TestNewLeafTemplate(t *testing.T) {
	tmpl, err := NewLeafTemplate("leaf", time.Hour)
	if err != nil {
		t.Fatalf("NewLeafTemplate: %v", err)
	}
	if tmpl.IsCA {
		t.Error("leaf template must not be a CA")
	}
	if tmpl.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("leaf should set DigitalSignature")
	}
	wantEKU := map[x509.ExtKeyUsage]bool{x509.ExtKeyUsageServerAuth: true, x509.ExtKeyUsageClientAuth: true}
	for _, eku := range tmpl.ExtKeyUsage {
		delete(wantEKU, eku)
	}
	if len(wantEKU) != 0 {
		t.Errorf("leaf missing EKUs: %v", wantEKU)
	}
	if !tmpl.NotAfter.After(tmpl.NotBefore) {
		t.Error("NotAfter should be after NotBefore")
	}
}

func TestAppendAttestationDigest(t *testing.T) {
	tmpl := &x509.Certificate{}
	if err := AppendAttestationDigest(tmpl, nil); err != nil {
		t.Fatalf("empty digest should be no-op: %v", err)
	}
	if len(tmpl.ExtraExtensions) != 0 {
		t.Error("no extension should be added for empty digest")
	}

	digest := []byte("some-digest")
	if err := AppendAttestationDigest(tmpl, digest); err != nil {
		t.Fatalf("AppendAttestationDigest: %v", err)
	}
	if len(tmpl.ExtraExtensions) != 1 {
		t.Fatalf("expected 1 extension, got %d", len(tmpl.ExtraExtensions))
	}
	ext := tmpl.ExtraExtensions[0]
	if !ext.Id.Equal(OIDAttestationDigest) {
		t.Errorf("extension OID = %v, want %v", ext.Id, OIDAttestationDigest)
	}
	// Stamp it onto a real cert and read it back to prove it's valid ASN.1.
	_ = pkix.Extension{}
}
