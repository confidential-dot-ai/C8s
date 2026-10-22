package armtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func selfSignedCA(t *testing.T, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(700),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// caSignedLeafOn issues a CA-signed leaf on the given curve, TLS purposes and
// NotBefore, valid for an hour from notBefore.
func caSignedLeafOn(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, curve elliptic.Curve, usages []x509.ExtKeyUsage, notBefore time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(701),
		Subject:      pkix.Name{CommonName: "peer"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.Add(time.Hour),
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// caSignedIntermediate issues a CA-signed intermediate restricted to the given
// TLS purposes.
func caSignedIntermediate(t *testing.T, caKey *ecdsa.PrivateKey, caCert *x509.Certificate, usages []x509.ExtKeyUsage) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(702),
		Subject:               pkix.Name{CommonName: "intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func TestVerifyChain(t *testing.T) {
	caKey, ca := selfSignedCA(t, "mesh")
	_, other := selfSignedCA(t, "other")
	leaf := caSignedLeafDER(t, caKey, ca)
	now := time.Now()
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	clientOnly := caSignedLeafOn(t, caKey, ca, elliptic.P256(), []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now.Add(-time.Hour))
	clientOnlyIssuerKey, clientOnlyIssuer := caSignedIntermediate(t, caKey, ca, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	underClientOnlyIssuer := caSignedLeafOn(t, clientOnlyIssuerKey, clientOnlyIssuer, elliptic.P256(), both, now.Add(-time.Minute))
	p521 := caSignedLeafOn(t, caKey, ca, elliptic.P521(), both, now.Add(-time.Hour))
	notYetValid := caSignedLeafOn(t, caKey, ca, elliptic.P256(), both, now.Add(2*time.Minute))
	pool := func(certs ...*x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range certs {
			p.AddCert(c)
		}
		return p
	}
	tests := []struct {
		name    string
		raw     [][]byte
		roots   *x509.CertPool
		purpose x509.ExtKeyUsage
		now     time.Time
		wantErr string
	}{
		{"chain to root", [][]byte{leaf}, pool(ca), x509.ExtKeyUsageServerAuth, now, ""},
		{"chain to root as a client", [][]byte{leaf}, pool(ca), x509.ExtKeyUsageClientAuth, now, ""},
		{"chain to another CA", [][]byte{leaf}, pool(other), x509.ExtKeyUsageServerAuth, now, "peer chain"},
		{"nil roots", [][]byte{leaf}, nil, x509.ExtKeyUsageServerAuth, now, "no trust anchors"},
		{"no certificate", nil, pool(ca), x509.ExtKeyUsageServerAuth, now, "no peer certificate"},
		{"garbage leaf", [][]byte{{0x30, 0x01}}, pool(ca), x509.ExtKeyUsageServerAuth, now, "parse peer cert"},
		{"garbage intermediate", [][]byte{leaf, {0x30, 0x01}}, pool(ca), x509.ExtKeyUsageServerAuth, now, "parse peer intermediate"},
		{"expired leaf", [][]byte{leaf}, pool(ca), x509.ExtKeyUsageServerAuth, now.Add(2 * time.Hour), "is after"},
		{"leaf without the purpose", [][]byte{clientOnly}, pool(ca), x509.ExtKeyUsageServerAuth, now, "does not permit serverAuth"},
		{"leaf on an unsupported curve", [][]byte{p521}, pool(ca), x509.ExtKeyUsageServerAuth, now, "want P-256 or P-384"},
		{"leaf not yet valid", [][]byte{notYetValid}, pool(ca), x509.ExtKeyUsageServerAuth, now, "is before"},
		{"issuer without the purpose", [][]byte{underClientOnlyIssuer, clientOnlyIssuer.Raw}, pool(ca), x509.ExtKeyUsageServerAuth, now, "peer chain"},
		{"issuer with the purpose", [][]byte{underClientOnlyIssuer, clientOnlyIssuer.Raw}, pool(ca), x509.ExtKeyUsageClientAuth, now, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifyChain(tc.raw, tc.roots, tc.purpose, tc.now)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("VerifyChain() error = %v, want the parsed leaf", err)
				}
				if got == nil {
					t.Fatal("VerifyChain() = nil leaf, want the parsed leaf")
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("VerifyChain() error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}
