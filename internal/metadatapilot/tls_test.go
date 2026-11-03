package metadatapilot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func pilotTLS(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "pilot root"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestMeasuredMetadataTrustVerifiesCAAndHostname(t *testing.T) {
	cert, root := pilotTLS(t)
	_, otherRoot := pilotTLS(t)
	var requests atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	for _, tc := range []struct {
		name, root, hostname string
		ok                   bool
	}{
		{"measured root", root, "", true},
		{"wrong root", otherRoot, "", false},
		{"wrong hostname", root, "other.example", false},
		{"system trust", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport, err := Transport(tc.root)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			if tc.hostname != "" {
				transport.TLSClientConfig.ServerName = tc.hostname
			}
			client := &http.Client{Transport: transport, Timeout: time.Second}
			before := requests.Load()
			response, err := client.Get(server.URL)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != tc.ok {
				t.Fatalf("TLS accepted=%v, want %v: %v", err == nil, tc.ok, err)
			}
			if !tc.ok && requests.Load() != before {
				t.Fatal("untrusted endpoint received an HTTP request")
			}
		})
	}
	for _, invalid := range []string{"not a certificate", root + root, strings.Repeat("x", 8193)} {
		if _, err := Transport(invalid); err == nil {
			t.Fatal("accepted invalid CA input")
		}
	}
}
