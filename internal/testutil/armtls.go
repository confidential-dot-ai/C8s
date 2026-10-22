package testutil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// TestMeasurement is a syntactically valid SHA-384 launch measurement, the one
// ApproveAll reports.
const TestMeasurement = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// ApproveAll is a verifier that accepts any evidence as an AzSNP report at
// TestMeasurement, so a test exercises what a command does with a verified
// endpoint.
func ApproveAll() VerifierStub {
	return func(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
		match := true
		result := &teetypes.VerificationResult{Platform: teetypes.PlatformAzSNP, SignatureValid: true, ReportDataMatch: &match}
		result.Claims.LaunchDigest = TestMeasurement
		return result, nil
	}
}

// MeshCA mints a self-signed CA certificate standing in for one CDS's mesh CA
// and returns its DER. Two calls produce two distinct CAs.
func MeshCA(t testing.TB, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
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
	return der
}

// PEMCerts renders DER certificates as a PEM bundle, as CDS serves /ca.
func PEMCerts(ders ...[]byte) []byte {
	var buf bytes.Buffer
	for _, der := range ders {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	return buf.Bytes()
}

// ARMTLSServingCert mints the self-signed armTLS serving certificate a direct
// CDS presents. Each call has a fresh key, so two servers are two peers that
// attest identically.
func ARMTLSServingCert(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	embedded, err := json.Marshal(teetypes.AttestationEvidence{
		Platform: teetypes.PlatformAzSNP,
		Evidence: json.RawMessage(`{"hcl_report":"fake"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, err := armtls.MarshalExtension(&armtls.Attestation{Family: armtls.TEETypeSEVSNP, Report: embedded})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "cds"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:        []string{"localhost"},
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// NewARMTLSServer serves h over TLS with a fresh armTLS serving certificate.
func NewARMTLSServer(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{ARMTLSServingCert(t)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// ReroutingProxy forwards TCP connections to one server until Reroute names
// another: a client that redials after Reroute lands on a different peer at the
// same address, as it would behind a host that reroutes it.
type ReroutingProxy struct {
	// URL is the https address clients dial.
	URL string

	mu     sync.Mutex
	target *httptest.Server
}

// NewReroutingProxy starts a proxy whose connections reach target.
func NewReroutingProxy(t testing.TB, target *httptest.Server) *ReroutingProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &ReroutingProxy{URL: "https://" + l.Addr().String(), target: target}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.mu.Lock()
			addr := strings.TrimPrefix(p.target.URL, "https://")
			p.mu.Unlock()
			go pipe(c, addr)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return p
}

// Reroute sends connections accepted from now on to target. Connections
// already open stay where they are.
func (p *ReroutingProxy) Reroute(target *httptest.Server) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.target = target
}

func pipe(c net.Conn, addr string) {
	defer c.Close()
	up, err := net.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer up.Close()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}
