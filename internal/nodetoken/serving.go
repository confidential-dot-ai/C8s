package nodetoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Serving is the TLS identity of the issuer's discovery listener: a CA of its
// own, never the mesh CA, so nothing it signs can pass as a mesh identity, and
// a server-only leaf for the issuer's host. A Kubernetes API server can pin
// only a CA, so the customer reads this CA from CDS over armTLS, where CDS's
// attestation vouches for it, and pins its fingerprint in each pool policy.
type Serving struct {
	host    string
	ca      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   []byte
	leafTTL time.Duration
	now     func() time.Time

	mu   sync.Mutex
	leaf *tls.Certificate
}

// Serving certificate lifetimes. The leaf is renewed under the same CA a
// third of its lifetime before it ends, so the pinned CA outlives every leaf.
const (
	servingCAValidity   = 5 * 365 * 24 * time.Hour
	servingLeafValidity = 30 * 24 * time.Hour
)

// NewServing generates the discovery listener's CA and its first leaf for
// host.
func NewServing(host string) (*Serving, error) {
	if host == "" {
		return nil, fmt.Errorf("node token serving host must not be empty")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate issuer CA key: %w", err)
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "c8s node token issuer CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(servingCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		// The CA can only ever name the issuer's host, never an address, and
		// only ever serve.
		PermittedDNSDomainsCritical: true,
		PermittedDNSDomains:         []string{host},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("sign issuer CA: %w", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	s := &Serving{
		host: host, ca: ca, caKey: key, leafTTL: servingLeafValidity, now: time.Now,
		caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
	if _, err := s.certificate(); err != nil {
		return nil, err
	}
	return s, nil
}

// CAPEM is the CA a pool policy pins.
func (s *Serving) CAPEM() []byte { return s.caPEM }

// Fingerprint is the CA's SHA-256 fingerprint, as a pool policy names it.
func (s *Serving) Fingerprint() string {
	sum := sha256.Sum256(s.ca.Raw)
	return hex.EncodeToString(sum[:])
}

// TLSConfig serves the current leaf, renewing it when due.
func (s *Serving) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return s.certificate()
		},
	}
}

func (s *Serving) certificate() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.leaf != nil && now.Before(s.leaf.Leaf.NotAfter.Add(-s.leafTTL/3)) {
		return s.leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate issuer serving key: %w", err)
	}
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: s.host},
		DNSNames:     []string{s.host},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(s.leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, s.ca, &key.PublicKey, s.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign issuer serving leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	s.leaf = &tls.Certificate{Certificate: [][]byte{der, s.ca.Raw}, PrivateKey: key, Leaf: leaf}
	return s.leaf, nil
}
