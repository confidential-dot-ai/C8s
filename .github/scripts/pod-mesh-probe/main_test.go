package main

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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func testEndpoint(t *testing.T, requireClient, plaintext bool, badSigner ...bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	ext, err := armtls.MarshalSandboxIDExtension("pcvm-test")
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{ext}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(badSigner) > 0 && badSigner[0] {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{armtls.MeshALPN}, Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}}, ClientCAs: pool}
	if requireClient {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan struct{})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
		var conn net.Conn = raw
		if !plaintext {
			secured := tls.Server(raw, cfg)
			if secured.Handshake() != nil {
				return
			}
			conn = secured
		}
		data := make([]byte, 512)
		if _, err = conn.Read(data); err != nil {
			return
		}
		if len(badSigner) > 1 && badSigner[1] {
			time.Sleep(500 * time.Millisecond)
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nOK"))
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return listener.Addr().String(), path
}

func TestRejectingMeshSuppliesVerifiedLeafWithoutAuthorizingProbe(t *testing.T) {
	for _, mode := range []string{"certless", "wrong-ca"} {
		t.Run(mode, func(t *testing.T) {
			address, ca := testEndpoint(t, true, false)
			got, err := probe(address, ca, mode)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Denied || got.SandboxID != "pcvm-test" || got.Serial == "" || got.SPKI == "" {
				t.Fatalf("incomplete result: %+v", got)
			}
		})
	}
}

func TestMeshThatAdmitsUnauthorizedAppBytesFails(t *testing.T) {
	for _, mode := range []string{"certless", "wrong-ca"} {
		t.Run(mode, func(t *testing.T) {
			address, ca := testEndpoint(t, false, false)
			if _, err := probe(address, ca, mode); err == nil {
				t.Fatal("accepted an endpoint exposing application bytes")
			}
		})
	}
}

func TestPlaintextApplicationDoesNotCountAsDenial(t *testing.T) {
	address, ca := testEndpoint(t, false, true)
	if _, err := probe(address, ca, "plaintext"); err == nil {
		t.Fatal("accepted plaintext HTTP")
	}
}

func TestUntrustedServerDoesNotCountAsClientRejection(t *testing.T) {
	address, _ := testEndpoint(t, true, false)
	_, foreignCA := testEndpoint(t, true, false)
	if _, err := probe(address, foreignCA, "certless"); err == nil {
		t.Fatal("untrusted server counted as successful rejection")
	}
}

func TestCopiedLeafWithoutServerPrivateKeyCannotBeObserved(t *testing.T) {
	address, ca := testEndpoint(t, true, false, true)
	got, err := probe(address, ca, "certless")
	if err == nil || got.SandboxID != "" {
		t.Fatalf("copied certificate counted as verified identity: %+v, %v", got, err)
	}
}

func TestTimeoutDoesNotCountAsExplicitRejection(t *testing.T) {
	for _, mode := range []string{"certless", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			address, ca := testEndpoint(t, false, mode == "plaintext", false, true)
			if _, err := probeWithTimeout(address, ca, mode, 100*time.Millisecond); err == nil {
				t.Fatal("timed out endpoint counted as denial")
			}
		})
	}
}
