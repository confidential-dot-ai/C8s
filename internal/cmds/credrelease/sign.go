package credrelease

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// Default CA paths: where RKE2 (the C8s node image's distribution) keeps its
// CAs. client-ca signs the kube client certs the apiserver trusts; server-ca
// signs the apiserver SERVING cert and is what the released kubeconfig must
// carry as certificate-authority-data — RKE2 keeps them distinct, so releasing
// the client CA there fails kubectl with "certificate signed by unknown
// authority". The mechanism is not RKE2-specific: kubeadm signs both with one
// ca.crt, so all three flags point at the same file there.
const (
	defaultClientCACert = "/var/lib/rancher/rke2/server/tls/client-ca.crt"
	defaultClientCAKey  = "/var/lib/rancher/rke2/server/tls/client-ca.key"
	defaultServerCACert = "/var/lib/rancher/rke2/server/tls/server-ca.crt"
)

// clusterCA holds the cluster's client-signing CA plus the serving-CA PEM the
// released kubeconfig anchors apiserver verification to.
type clusterCA struct {
	cert *x509.Certificate
	key  crypto.Signer
	pem  []byte // the SERVING CA cert PEM — the kubeconfig's trust anchor
}

// loadClusterCA reads the cluster client-CA cert+key and the serving-CA cert.
func loadClusterCA(certPath, keyPath, serverCAPath string) (*clusterCA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read client CA key: %w", err)
	}
	serverCAPEM, err := os.ReadFile(serverCAPath)
	if err != nil {
		return nil, fmt.Errorf("read server CA cert: %w", err)
	}

	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s is not a CERTIFICATE PEM", certPath)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse client CA cert: %w", err)
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("%s is not PEM", keyPath)
	}
	key, err := parseCAKey(kb.Bytes, kb.Type)
	if err != nil {
		return nil, fmt.Errorf("parse client CA key: %w", err)
	}
	sb, _ := pem.Decode(serverCAPEM)
	if sb == nil || sb.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s is not a CERTIFICATE PEM", serverCAPath)
	}
	return &clusterCA{cert: cert, key: key, pem: serverCAPEM}, nil
}

// parseCAKey handles the PEM encodings the supported distributions emit:
// SEC1 "EC PRIVATE KEY" (RKE2), PKCS#1 "RSA PRIVATE KEY" (kubeadm), or PKCS#8
// "PRIVATE KEY".
func parseCAKey(der []byte, pemType string) (crypto.Signer, error) {
	switch pemType {
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("key is %T, which cannot sign", k)
		}
		return s, nil
	default:
		return nil, fmt.Errorf("unsupported key PEM type %q", pemType)
	}
}

// signOperatorCert signs csr with the cluster CA, producing a kube CLIENT
// certificate with the requested identity. The caller sets group/CN via
// signParams; what that identity may do is the cluster's RBAC, not the
// signer's concern. TTL is short so the operator re-releases.
type signParams struct {
	csr      *x509.CertificateRequest
	org      string // certificate Subject O -> maps to a Kubernetes group
	cn       string // Subject CN -> the Kubernetes user
	ttl      time.Duration
	serialFn func() (*big.Int, error) // injectable for tests; nil -> crypto/rand
}

func (ca *clusterCA) signOperatorCert(p signParams, now time.Time) (certPEM []byte, err error) {
	if p.csr == nil {
		return nil, fmt.Errorf("nil CSR")
	}
	if err := p.csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR self-signature invalid: %w", err)
	}
	serialFn := p.serialFn
	if serialFn == nil {
		serialFn = randSerial
	}
	serial, err := serialFn()
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   p.cn,
			Organization: []string{p.org},
		},
		NotBefore: now.Add(-1 * time.Minute), // small backdate for clock skew
		NotAfter:  now.Add(p.ttl),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		// Client auth only — this is a kube client cert, not a serving cert.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, p.csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func randSerial() (*big.Int, error) {
	// 128-bit random serial (RFC 5280 recommends >= 64-bit, unpredictable).
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
