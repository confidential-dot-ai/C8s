package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// endpointOptions shapes the test server the probe is pointed at.
type endpointOptions struct {
	// requireClient demands a client certificate and verifies it against the
	// test CA, the way a stock Go server does.
	requireClient bool
	// meshShaped demands any client certificate and judges it in
	// VerifyPeerCertificate, the way the mesh endpoint does.
	meshShaped bool
	// plaintext serves HTTP without TLS.
	plaintext bool
	// copiedLeaf serves the leaf with a key that is not the leaf's.
	copiedLeaf bool
	// slow waits half a second before answering.
	slow bool
	// closeAfterRequest reads the request and closes without answering.
	closeAfterRequest bool
	// reset closes with a TCP reset instead of a FIN.
	reset bool
}

func testEndpoint(t *testing.T, o endpointOptions) (string, string) {
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
	if o.copiedLeaf {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{armtls.MeshALPN}, Certificates: []tls.Certificate{{Certificate: [][]byte{der, ca.Raw}, PrivateKey: key}}, ClientCAs: pool}
	if o.requireClient {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	if o.meshShaped {
		cfg.ClientAuth = tls.RequireAnyClientCert
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			peer, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if _, err = peer.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
				return err
			}
			return errors.New("peer assigned workload differs")
		}
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
		conn := raw
		if !o.plaintext {
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
		if o.slow {
			time.Sleep(500 * time.Millisecond)
		}
		if o.closeAfterRequest {
			if o.reset {
				_ = raw.(*net.TCPConn).SetLinger(0)
			}
			return
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length:2\r\n\r\nOK"))
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return listener.Addr().String(), path
}

func TestRejectingMeshSuppliesVerifiedLeafWithoutAuthorizingProbe(t *testing.T) {
	for _, mode := range []string{"certless", "wrong-ca"} {
		t.Run(mode, func(t *testing.T) {
			address, ca := testEndpoint(t, endpointOptions{requireClient: true})
			got, err := probe(address, ca, mode)
			if err != nil {
				t.Fatal(err)
			}
			if !got.Denied || got.SandboxID != "pcvm-test" || got.Serial == "" || got.SPKI == "" {
				t.Fatalf("incomplete result: %+v", got)
			}
			want := "certificate required"
			if mode == "wrong-ca" {
				want = "unknown certificate authority"
			}
			if got.Rejection != want {
				t.Fatalf("rejection %q, want %q", got.Rejection, want)
			}
		})
	}
}

// TestMeshShapedRejectionIsExplicit points the probe at a server built like the
// mesh endpoint: any certificate is demanded and judged in VerifyPeerCertificate,
// so a certless client is refused with certificate_required and every other
// credential failure, wrong CA or wrong tenant alike, with bad_certificate.
func TestMeshShapedRejectionIsExplicit(t *testing.T) {
	for _, mode := range []string{"certless", "wrong-ca"} {
		t.Run(mode, func(t *testing.T) {
			address, ca := testEndpoint(t, endpointOptions{meshShaped: true})
			got, err := probe(address, ca, mode)
			if err != nil {
				t.Fatal(err)
			}
			want := "certificate required"
			if mode == "wrong-ca" {
				want = "bad certificate"
			}
			if !got.Denied || got.Rejection != want || got.SandboxID != "pcvm-test" {
				t.Fatalf("mesh-shaped rejection not recorded: %+v", got)
			}
		})
	}
}

// TestServerThatClosesAfterTheRequestIsNotRejection: a server that admitted the
// unauthorized client, read its request and then went away, by FIN or by
// reset, has demonstrated no credential check at all.
func TestServerThatClosesAfterTheRequestIsNotRejection(t *testing.T) {
	for _, mode := range []string{"certless", "wrong-ca"} {
		for _, reset := range []bool{false, true} {
			name := mode + "/close"
			if reset {
				name = mode + "/reset"
			}
			t.Run(name, func(t *testing.T) {
				address, ca := testEndpoint(t, endpointOptions{closeAfterRequest: true, reset: reset})
				got, err := probe(address, ca, mode)
				if err == nil || got.Denied {
					t.Fatalf("a server that accepted the request counted as credential rejection: %+v", got)
				}
			})
		}
	}
}

func TestMeshThatAdmitsUnauthorizedAppBytesFails(t *testing.T) {
	for _, mode := range []string{"certless", "wrong-ca"} {
		t.Run(mode, func(t *testing.T) {
			address, ca := testEndpoint(t, endpointOptions{})
			if _, err := probe(address, ca, mode); err == nil {
				t.Fatal("accepted an endpoint exposing application bytes")
			}
		})
	}
}

func TestPlaintextApplicationDoesNotCountAsDenial(t *testing.T) {
	address, ca := testEndpoint(t, endpointOptions{plaintext: true})
	if _, err := probe(address, ca, "plaintext"); err == nil {
		t.Fatal("accepted plaintext HTTP")
	}
}

func TestUntrustedServerDoesNotCountAsClientRejection(t *testing.T) {
	address, _ := testEndpoint(t, endpointOptions{requireClient: true})
	_, foreignCA := testEndpoint(t, endpointOptions{requireClient: true})
	if _, err := probe(address, foreignCA, "certless"); err == nil {
		t.Fatal("untrusted server counted as successful rejection")
	}
}

func TestCopiedLeafWithoutServerPrivateKeyCannotBeObserved(t *testing.T) {
	address, ca := testEndpoint(t, endpointOptions{requireClient: true, copiedLeaf: true})
	got, err := probe(address, ca, "certless")
	if err == nil || got.SandboxID != "" {
		t.Fatalf("copied certificate counted as verified identity: %+v, %v", got, err)
	}
}

func TestTimeoutDoesNotCountAsExplicitRejection(t *testing.T) {
	for _, mode := range []string{"certless", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			address, ca := testEndpoint(t, endpointOptions{plaintext: mode == "plaintext", slow: true})
			if _, err := probeWithTimeout(address, ca, mode, 100*time.Millisecond); err == nil {
				t.Fatal("timed out endpoint counted as denial")
			}
		})
	}
}
