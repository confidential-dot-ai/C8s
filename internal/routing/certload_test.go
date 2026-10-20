package routing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// leafPEM mints a CA-signed leaf valid over [notBefore, notAfter].
func leafPEM(t *testing.T, ca *issuer.CA, notBefore, notAfter time.Time) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "router"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	if leaf, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	if keyPEM, err = certutil.MarshalECKeyPEM(key); err != nil {
		t.Fatal(err)
	}
	return certutil.EncodeCertPEM(der), keyPEM, leaf
}

// TestClientCertReloadsAndEnforcesValidity covers B4 across rotation: the
// mesh credential is get-cert-managed and rotates under a long-lived process.
func TestClientCertReloadsAndEnforcesValidity(t *testing.T) {
	ca := newCA(t, "mesh")
	now := time.Now()
	certPEM, keyPEM, _ := leafPEM(t, ca, now.Add(-2*time.Hour), now.Add(-time.Hour))
	certFile := writeFile(t, "cert.pem", certPEM)
	keyFile := writeFile(t, "key.pem", keyPEM)

	// Startup tolerates an expired but well-formed pair, so a restart during
	// a CDS outage still comes up.
	loader, err := NewClientCert(certFile, keyFile)
	if err != nil {
		t.Fatalf("NewClientCert(expired pair) = %v, want nil", err)
	}
	if _, err := loader.GetClientCertificate(nil); err == nil {
		t.Fatal("GetClientCertificate() with an expired credential = nil error, want one")
	}

	certPEM, keyPEM, fresh := leafPEM(t, ca, now.Add(-time.Minute), now.Add(time.Hour))
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loader.GetClientCertificate(nil)
	if err != nil {
		t.Fatalf("GetClientCertificate() after rotation = %v, want nil", err)
	}
	if !got.Leaf.Equal(fresh) {
		t.Fatal("GetClientCertificate() served a leaf other than the rotated one")
	}
}
