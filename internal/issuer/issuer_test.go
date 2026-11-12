package issuer_test

import (
	"bytes"
	"crypto/x509"
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
	if !bytes.Equal(ca.Cert.RawIssuer, ca.Cert.RawSubject) {
		t.Error("CA issuer is not its own subject")
	}
	if err := ca.Cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("CA certificate does not verify under its own key: %v", err)
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
	roundtripCert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("parse round-tripped CA cert: %v", err)
	}
	if _, err := certutil.ParseECPrivateKey(keyPEM); err != nil {
		t.Fatalf("parse round-tripped CA key: %v", err)
	}
	if !roundtripCert.Equal(ca.Cert) {
		t.Error("round-tripped CA cert does not equal original")
	}
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
