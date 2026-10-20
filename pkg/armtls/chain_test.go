package armtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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

func TestVerifyChain(t *testing.T) {
	caKey, ca := selfSignedCA(t, "mesh")
	_, other := selfSignedCA(t, "other")
	leaf := caSignedLeafDER(t, caKey, ca)
	pool := func(certs ...*x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		for _, c := range certs {
			p.AddCert(c)
		}
		return p
	}
	now := time.Now()
	tests := []struct {
		name    string
		raw     [][]byte
		roots   *x509.CertPool
		now     time.Time
		wantErr bool
	}{
		{"chain to root", [][]byte{leaf}, pool(ca), now, false},
		{"chain to another CA", [][]byte{leaf}, pool(other), now, true},
		{"nil roots", [][]byte{leaf}, nil, now, true},
		{"no certificate", nil, pool(ca), now, true},
		{"garbage leaf", [][]byte{{0x30, 0x01}}, pool(ca), now, true},
		{"expired leaf", [][]byte{leaf}, pool(ca), now.Add(2 * time.Hour), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := VerifyChain(tc.raw, tc.roots, tc.now)
			if (err != nil) != tc.wantErr {
				t.Fatalf("VerifyChain() error = %v, want error %v", err, tc.wantErr)
			}
			if err == nil && got == nil {
				t.Fatal("VerifyChain() = nil leaf, want the parsed leaf")
			}
		})
	}
}
