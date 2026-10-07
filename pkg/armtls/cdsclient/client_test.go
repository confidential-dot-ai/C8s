package cdsclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func TestNewClientDefaultTransport(t *testing.T) {
	c := NewClient(&Config{
		CDSURL:            "https://cds.invalid",
		AttestationApiURL: "http://as.invalid",
		CDSCAURL:          "https://cds.invalid",
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		CDSMeasurements:   [][]byte{make([]byte, armtls.SNPMeasurementSize)},
	})

	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", c.httpClient.Timeout)
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.httpClient.Transport)
	}
	if tr.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("ResponseHeaderTimeout = %v, want 10s", tr.ResponseHeaderTimeout)
	}
	if tr.IdleConnTimeout != 30*time.Second {
		t.Errorf("IdleConnTimeout = %v, want 30s", tr.IdleConnTimeout)
	}
	if tr.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil: CDS would be dialed without armTLS peer verification")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", tr.TLSClientConfig.MinVersion)
	}
	if tr.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Error("VerifyPeerCertificate is nil: CDS peer attestation would not be checked")
	}
}

func TestCreateCSRDNSSAN(t *testing.T) {
	as := mockapi.New(t)

	tests := []struct {
		name   string
		dnssan string
		want   []string
	}{
		{"dns san set", "node.mesh.internal", []string{"node.mesh.internal"}},
		{"no dns san", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(&Config{
				CDSURL:            "http://unused.invalid",
				AttestationApiURL: as.URL(),
				CDSCAURL:          "http://unused.invalid",
				NodeIP:            "10.0.0.1",
				TEEType:           armtls.TEETypeSEVSNP,
				DNSSAN:            tt.dnssan,
				HTTPClient:        plainHTTPClient(),
			})
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			csrPEM, err := c.createCSR(context.Background(), key)
			if err != nil {
				t.Fatalf("createCSR: %v", err)
			}
			block, _ := pem.Decode([]byte(csrPEM))
			if block == nil {
				t.Fatal("no PEM block in CSR")
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if len(csr.DNSNames) != len(tt.want) {
				t.Fatalf("DNSNames = %v, want %v", csr.DNSNames, tt.want)
			}
			for i := range tt.want {
				if csr.DNSNames[i] != tt.want[i] {
					t.Fatalf("DNSNames = %v, want %v", csr.DNSNames, tt.want)
				}
			}
			if len(csr.IPAddresses) != 0 {
				t.Errorf("IPAddresses = %v, want none", csr.IPAddresses)
			}
		})
	}
}

func TestIsUsableCAKeyUsage(t *testing.T) {
	now := time.Now()
	makeCA := func(t *testing.T, ku x509.KeyUsage) *x509.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "ku-ca"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              ku,
		}
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
		name string
		ku   x509.KeyUsage
		want bool
	}{
		{"no key usage set", 0, true},
		{"cert-sign", x509.KeyUsageCertSign, true},
		{"digital-signature only", x509.KeyUsageDigitalSignature, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isUsableCA(makeCA(t, tt.ku), now); got != tt.want {
				t.Fatalf("isUsableCA = %v, want %v", got, tt.want)
			}
		})
	}
}
