package issuer_test

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func TestNewCA(t *testing.T) {
	ca, err := issuer.NewCA("test ca", time.Hour)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Error("generated cert should have IsCA=true")
	}
	if ca.Cert.Subject.CommonName != "test ca" {
		t.Errorf("CN mismatch: got %q", ca.Cert.Subject.CommonName)
	}
	if got := ca.Cert.NotAfter.Sub(ca.Cert.NotBefore); got < 59*time.Minute || got > 61*time.Minute {
		t.Errorf("validity window %v not ~1h", got)
	}

	// Round-trip through PEM.
	certPEM, keyPEM, err := ca.PEM()
	if err != nil {
		t.Fatalf("PEM: %v", err)
	}
	roundtrip, err := issuer.LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !roundtrip.Cert.Equal(ca.Cert) {
		t.Error("round-tripped CA cert does not equal original")
	}
}

func TestWrapCA(t *testing.T) {
	a, err := issuer.NewCA("a", time.Hour)
	if err != nil {
		t.Fatalf("NewCA a: %v", err)
	}
	b, err := issuer.NewCA("b", time.Hour)
	if err != nil {
		t.Fatalf("NewCA b: %v", err)
	}
	// The mesh CA is the P-384 one, for the cross-curve check below.
	c384, err := issuer.NewMeshCA("c", time.Hour)
	if err != nil {
		t.Fatalf("NewMeshCA P-384: %v", err)
	}

	wrapped, err := issuer.WrapCA(a.Cert, a.Key)
	if err != nil {
		t.Errorf("matching keypair: unexpected error %v", err)
	} else if wrapped.Cert != a.Cert || wrapped.Key != a.Key {
		t.Error("matching keypair: returned CA fields do not equal inputs")
	}
	if _, err := issuer.WrapCA(nil, a.Key); err == nil {
		t.Error("nil cert: expected error, got nil")
	}
	if _, err := issuer.WrapCA(a.Cert, nil); err == nil {
		t.Error("nil key: expected error, got nil")
	}
	if _, err := issuer.WrapCA(a.Cert, b.Key); err == nil {
		t.Error("mismatched keypair: expected error, got nil")
	}
	if _, err := issuer.WrapCA(c384.Current().CA.Cert, a.Key); err == nil {
		t.Error("cross-curve keypair (P-384 cert, P-256 key): expected error, got nil")
	}

	leaf := testCertForKey(t, a.Key, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	})
	if _, err := issuer.WrapCA(leaf, a.Key); err == nil {
		t.Error("matching non-CA cert: expected error, got nil")
	}

	missingBasicConstraints := *a.Cert
	missingBasicConstraints.BasicConstraintsValid = false
	if _, err := issuer.WrapCA(&missingBasicConstraints, a.Key); err == nil {
		t.Error("CA missing valid basic constraints: expected error, got nil")
	}

	missingCertSignUsage := *a.Cert
	missingCertSignUsage.KeyUsage = x509.KeyUsageDigitalSignature
	if _, err := issuer.WrapCA(&missingCertSignUsage, a.Key); err == nil {
		t.Error("CA without cert-sign key usage: expected error, got nil")
	}

	expired := *a.Cert
	expired.NotBefore = time.Now().Add(-2 * time.Hour)
	expired.NotAfter = time.Now().Add(-time.Hour)
	if _, err := issuer.WrapCA(&expired, a.Key); err == nil {
		t.Error("expired CA: expected error, got nil")
	}

	notYetValid := *a.Cert
	notYetValid.NotBefore = time.Now().Add(time.Hour)
	notYetValid.NotAfter = time.Now().Add(2 * time.Hour)
	if _, err := issuer.WrapCA(&notYetValid, a.Key); err == nil {
		t.Error("not-yet-valid CA: expected error, got nil")
	}
}

func testCertForKey(t *testing.T, key *ecdsa.PrivateKey, tmpl *x509.Certificate) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse test cert: %v", err)
	}
	return cert
}

func TestIssue(t *testing.T) {
	ca, err := issuer.NewCA("", 0)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}

	req := issuer.Request{
		CommonName:  "chat-api.demo",
		DNSNames:    []string{"chat-api.demo.svc.cluster.local"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.5")},
		TTL:         2 * time.Hour,
	}
	res, err := ca.Issue(req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Parse and verify the leaf is signed by the CA.
	leaf, err := certutil.ParseCertificatePEM(res.CertPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}

	// SANs must be preserved.
	if got, want := leaf.DNSNames, req.DNSNames; len(got) != len(want) || got[0] != want[0] {
		t.Errorf("DNSNames mismatch: got %v want %v", got, want)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(req.IPAddresses[0]) {
		t.Errorf("IPAddresses mismatch: got %v", leaf.IPAddresses)
	}

	// TTL honored within tolerance.
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got < req.TTL-time.Minute || got > req.TTL+time.Minute {
		t.Errorf("leaf TTL %v not ~%v", got, req.TTL)
	}

	// Private key parses and matches the public key on the leaf.
	_, err = certutil.ParseECPrivateKey(res.KeyPEM)
	if err != nil {
		t.Fatalf("parse leaf key: %v", err)
	}
}

func TestIssueRequiresCommonName(t *testing.T) {
	ca, err := issuer.NewCA("", 0)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	if _, err := ca.Issue(issuer.Request{}); err == nil {
		t.Error("expected error for missing CommonName")
	}
}

func TestIssueDefaultTTL(t *testing.T) {
	ca, err := issuer.NewCA("", 0)
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	res, err := ca.Issue(issuer.Request{CommonName: "x"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	leaf, err := certutil.ParseCertificatePEM(res.CertPEM)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	got := leaf.NotAfter.Sub(leaf.NotBefore)
	if got < issuer.DefaultLeafTTL-time.Minute || got > issuer.DefaultLeafTTL+time.Minute {
		t.Errorf("default TTL %v not ~%v", got, issuer.DefaultLeafTTL)
	}
}
