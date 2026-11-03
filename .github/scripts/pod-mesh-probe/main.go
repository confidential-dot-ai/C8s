// pod-mesh-probe observes public credentials and negative access only.
// Positive application traffic originates inside the two measured Pod guests.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

type report struct {
	Mode      string    `json:"mode"`
	Serial    string    `json:"serial"`
	SPKI      string    `json:"spki"`
	SandboxID string    `json:"sandboxID"`
	Workload  string    `json:"workload"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Denied    bool      `json:"denied"`
}

func roots(path string) (*x509.CertPool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, errors.New("empty mesh CA")
	}
	return pool, nil
}

func verify(raw [][]byte, pool *x509.CertPool, out *report) error {
	if len(raw) == 0 {
		return errors.New("missing peer leaf")
	}
	leaf, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, der := range raw[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(cert)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return err
	}
	id, err := armtls.SandboxIDFromCert(leaf)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(id, "pcvm-") {
		return errors.New("peer is not a Pod instance")
	}
	matched, err := armtls.MatchedWorkloadFromCert(leaf)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	out.NotBefore = leaf.NotBefore
	out.Serial, out.SPKI, out.SandboxID, out.NotAfter = leaf.SerialNumber.Text(16), hex.EncodeToString(sum[:]), id, leaf.NotAfter
	if matched != nil {
		out.Workload = matched.Name
	}
	return nil
}

func wrongCertificate() (tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "disposable wrong mesh CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	ext, err := armtls.MarshalSandboxIDExtension("pcvm-wrong-ca-test")
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: []pkix.Extension{ext}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: leafKey}, nil
}

func probe(address, caPath, mode string) (report, error) {
	return probeWithTimeout(address, caPath, mode, 8*time.Second)
}

func probeWithTimeout(address, caPath, mode string, timeout time.Duration) (report, error) {
	out := report{Mode: mode}
	pool, err := roots(caPath)
	if err != nil {
		return out, err
	}
	raw, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return out, err
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		return out, err
	}
	if mode == "plaintext" {
		if _, err = raw.Write([]byte("GET /id HTTP/1.1\r\nHost: acceptance\r\nConnection: close\r\n\r\n")); err != nil {
			return out, err
		}
		data := make([]byte, 256)
		n, readErr := raw.Read(data)
		if n > 0 && (n < 3 || data[0] != 21 || data[1] != 3) {
			return out, errors.New("plaintext returned non-TLS application bytes")
		}
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			return out, errors.New("plaintext probe timed out without rejection")
		}
		if n == 0 && readErr == nil {
			return out, errors.New("plaintext probe had no conclusion")
		}
		out.Denied = true
		return out, nil
	}
	if mode != "certless" && mode != "wrong-ca" {
		return out, errors.New("unsupported probe mode")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{armtls.MeshALPN},
		// The mesh identity is a CA-vouched SandboxID, not a DNS name. Verify it below.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error { return verify(raw, pool, &out) },
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != armtls.MeshALPN {
				return errors.New("wrong ALPN")
			}
			return nil
		},
	}
	if mode == "wrong-ca" {
		cert, err := wrongCertificate()
		if err != nil {
			return out, err
		}
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }
	}
	conn := tls.Client(raw, cfg)
	err = conn.Handshake()
	if err != nil {
		return report{Mode: mode}, fmt.Errorf("server possession was not verified: %w", err)
	}
	if out.SandboxID == "" {
		return out, fmt.Errorf("no verified mesh leaf: %v", err)
	}
	if conn.ConnectionState().NegotiatedProtocol != armtls.MeshALPN {
		return out, errors.New("wrong mesh ALPN")
	}
	if err == nil {
		_, _ = conn.Write([]byte("GET /id HTTP/1.1\r\nHost: acceptance\r\nConnection: close\r\n\r\n"))
		data := make([]byte, 256)
		n, readErr := conn.Read(data)
		if n != 0 || readErr == nil {
			return out, errors.New("unauthorized peer received application bytes")
		}
		var netErr net.Error
		if errors.As(readErr, &netErr) && netErr.Timeout() {
			return out, errors.New("peer did not reject unauthorized TLS before deadline")
		}
	}
	out.Denied = true
	return out, nil
}

func main() {
	address := flag.String("address", "", "Pod mesh TCP endpoint")
	ca := flag.String("ca", "", "independently attested CDS CA PEM")
	mode := flag.String("mode", "certless", "certless, wrong-ca or plaintext")
	flag.Parse()
	result, err := probe(*address, *ca, *mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}
