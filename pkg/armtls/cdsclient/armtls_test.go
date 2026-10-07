package cdsclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// TestProviderARMTLSRejectsUnattestedCDS proves the cdsclient's default
// (no HTTPClient override) http.Client refuses to talk to an CDS server
// whose serving cert lacks an armTLS attestation extension. This is the
// safety net that closes the bootstrap-channel MITM gap: an on-path attacker
// cannot present a TEE-attested cert with an allowed measurement, so the TLS
// handshake fails before any cert-issuance bytes flow.
func TestProviderARMTLSRejectsUnattestedCDS(t *testing.T) {
	as := mockapi.New(t)

	// Plain HTTPS server with a regular self-signed cert (no armTLS extension).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to unattested CDS: %s", r.URL.Path)
	}))
	defer srv.Close()

	p, err := NewProvider(&Config{
		CDSURL:            srv.URL,
		AttestationApiURL: as.URL(),
		CDSCAURL:          "http://unused.invalid",
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		CDSMeasurements:   [][]byte{make([]byte, armtls.SNPMeasurementSize)},
		// HTTPClient deliberately nil so NewClient builds the armTLS transport.
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = p.Provision(context.Background())
	if err == nil {
		t.Fatal("Provision succeeded against unattested CDS")
	}
	if !errors.Is(err, armtls.ErrNoAttestation) {
		t.Fatalf("Provision error = %v, want ErrNoAttestation", err)
	}
}

// TestProviderARMTLSRejectsCertWithoutAttestationExtension is a tighter test
// than the previous one: it stands up an HTTPS server whose cert is issued by
// a well-known x509 path (not self-signed by httptest), and confirms the
// cdsclient still rejects it because the cert lacks the armTLS extension.
func TestProviderARMTLSRejectsCertWithoutAttestationExtension(t *testing.T) {
	as := mockapi.New(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rogue-cds"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"127.0.0.1", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request: %s", r.URL.Path)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS13,
	}
	srv.StartTLS()
	defer srv.Close()

	p, err := NewProvider(&Config{
		CDSURL:            srv.URL,
		AttestationApiURL: as.URL(),
		CDSCAURL:          "http://unused.invalid",
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		CDSMeasurements:   [][]byte{make([]byte, armtls.SNPMeasurementSize)},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Provision(context.Background()); err == nil {
		t.Fatal("Provision accepted CDS cert without an armTLS attestation extension")
	}
}

// TestProviderARMTLSRejectsCDSWithUnpinnedMeasurement proves the measurement
// pin closes the bootstrap-channel MITM gap: a real armTLS listener whose
// evidence verifies but whose launch digest is not in CDSMeasurements must
// fail the handshake with ErrPolicyViolation before any CDS request flows.
func TestProviderARMTLSRejectsCDSWithUnpinnedMeasurement(t *testing.T) {
	as := mockapi.New(t)
	served := bytes.Repeat([]byte{0x42}, armtls.SNPMeasurementSize)
	as.SetVerdict(mockapi.PassingVerdict(hex.EncodeToString(served)))

	serverTLS, _, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:   "sev-snp",
		AttestFunc: attestclient.MakeSNPARMTLSAttestFunc(attestclient.NewClient(""), as.URL()),
		CertTTL:    time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	var reached atomic.Int64
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go http.Serve(tls.NewListener(ln, serverTLS), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Add(1)
	}))

	pinned := bytes.Repeat([]byte{0x99}, armtls.SNPMeasurementSize)
	p, err := NewProvider(&Config{
		CDSURL:            "https://" + ln.Addr().String(),
		AttestationApiURL: as.URL(),
		CDSCAURL:          "http://unused.invalid",
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		CDSMeasurements:   [][]byte{pinned},
		// HTTPClient deliberately nil so NewClient builds the armTLS transport.
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = p.Provision(context.Background())
	if !errors.Is(err, armtls.ErrPolicyViolation) {
		t.Fatalf("Provision error = %v, want ErrPolicyViolation", err)
	}
	if got := reached.Load(); got != 0 {
		t.Fatalf("CDS handler reached %d time(s); the measurement pin must fail the handshake first", got)
	}
}
