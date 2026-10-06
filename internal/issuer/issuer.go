// Package issuer generates CA keypairs and signs workload X.509 certificates
// in-process. The operator calls this directly during ConfidentialWorkload
// reconciliation; no HTTP surface is exposed.
package issuer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// DefaultCACommonName is the CN for the cluster-wide mesh CA when the caller
// does not override it.
const DefaultCACommonName = "c8s Mesh CA"

// DefaultCAValidity is how long a freshly generated CA is valid for.
const DefaultCAValidity = 365 * 24 * time.Hour

// DefaultLeafTTL is the fallback leaf cert TTL when a request omits it.
const DefaultLeafTTL = 24 * time.Hour

// MaxLeafTTL is the upper bound on any leaf-cert lifetime, regardless of
// caller-supplied TTL. Short TTL + fast rotation is a core part of the
// mesh CA's blast-radius containment.
const MaxLeafTTL = 24 * time.Hour

// MaxNamedLeafTTL is the upper bound on a leaf carrying a matched-workload
// stamp. A named leaf can outlive its match by at most its remaining lifetime
// (the high-water inventory makes a foreign admission permanent, but an
// already-issued leaf stays usable until replacement or expiry), so the named
// bound is deliberately shorter than MaxLeafTTL — it is the documented
// stale-identity bound (docs/armtls.md, "Matched workload").
const MaxNamedLeafTTL = 6 * time.Hour

// CapTTL clamps a requested TTL. Zero or negative falls back to
// DefaultLeafTTL; anything above max clips to max. max <= 0 disables
// the clip (tests only).
func CapTTL(requested, max time.Duration) time.Duration {
	if requested <= 0 {
		requested = DefaultLeafTTL
	}
	if max > 0 && requested > max {
		return max
	}
	return requested
}

// CA holds a loaded CA keypair.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA generates a fresh self-signed ECDSA P-256 CA.
func NewCA(commonName string, validity time.Duration) (*CA, error) {
	return NewCAWithCurve(commonName, validity, elliptic.P256())
}

// NewCAWithCurve generates a fresh self-signed ECDSA CA on the given curve.
// Use NewCA for the default P-256 mesh CA.
func NewCAWithCurve(commonName string, validity time.Duration, curve elliptic.Curve) (*CA, error) {
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		commonName = DefaultCACommonName
	}
	if validity <= 0 {
		validity = DefaultCAValidity
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, fmt.Errorf("generate ca serial: %w", err)
	}

	tmpl := certutil.NewCATemplate(serial, commonName, time.Now().Add(validity))
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse freshly-signed ca: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// NewCAWithParent generates a fresh ECDSA CA certificate on the given curve,
// signed by parentCert/parentKey. This is used for rolling CA rotation: clients
// that already trust the parent can authenticate the replacement CA before
// adding it as a trust anchor.
func NewCAWithParent(commonName string, validity time.Duration, curve elliptic.Curve, parentCert *x509.Certificate, parentKey *ecdsa.PrivateKey) (*CA, error) {
	if parentCert == nil {
		return nil, fmt.Errorf("parent ca certificate is required")
	}
	if parentKey == nil {
		return nil, fmt.Errorf("parent ca key is required")
	}
	parentPub, ok := parentCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parent ca certificate has non-ECDSA public key: %T", parentCert.PublicKey)
	}
	if !parentKey.PublicKey.Equal(parentPub) {
		return nil, fmt.Errorf("parent ca key does not match certificate")
	}
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		commonName = DefaultCACommonName
	}
	if validity <= 0 {
		validity = DefaultCAValidity
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, fmt.Errorf("generate ca serial: %w", err)
	}

	tmpl := certutil.NewCATemplate(serial, commonName, time.Now().Add(validity))
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		return nil, fmt.Errorf("sign ca with parent: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse freshly-signed ca: %w", err)
	}
	return &CA{Cert: cert, Key: key}, nil
}

// WrapCA wraps a pre-parsed certificate and private key as a CA suitable for
// SignCSR. It verifies the certificate is currently usable for CA signing and
// that the key matches the cert's public key so a misconfigured bundle surfaces
// here rather than producing an unverifiable leaf on the first signing request.
// Prefer this constructor over &CA{...} so any future field that participates
// in signing is propagated in one place.
func WrapCA(cert *x509.Certificate, key *ecdsa.PrivateKey) (*CA, error) {
	if cert == nil {
		return nil, fmt.Errorf("wrap ca: cert is required")
	}
	if key == nil {
		return nil, fmt.Errorf("wrap ca: key is required")
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("wrap ca: cert has non-ECDSA public key: %T", cert.PublicKey)
	}
	if !key.PublicKey.Equal(certPub) {
		return nil, fmt.Errorf("wrap ca: key does not match cert public key")
	}
	if err := validateUsableCA(cert, time.Now()); err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

func validateUsableCA(cert *x509.Certificate, now time.Time) error {
	if !cert.IsCA {
		return fmt.Errorf("wrap ca: certificate is not a CA")
	}
	if !cert.BasicConstraintsValid {
		return fmt.Errorf("wrap ca: CA certificate basic constraints are invalid")
	}
	if cert.NotBefore.After(now) {
		return fmt.Errorf("wrap ca: CA certificate is not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if cert.NotAfter.Before(now) {
		return fmt.Errorf("wrap ca: CA certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("wrap ca: CA certificate key usage does not allow certificate signing")
	}
	return nil
}

// LoadCA reconstructs a CA from PEM-encoded cert and key bytes.
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	key, err := certutil.ParseECPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	return WrapCA(cert, key)
}

// PEM returns the CA cert and key as PEM bytes.
func (c *CA) PEM() (certPEM, keyPEM []byte, err error) {
	certPEM = certutil.EncodeCertPEM(c.Cert.Raw)
	keyPEM, err = certutil.MarshalECKeyPEM(c.Key)
	return
}

// Request is a leaf certificate issuance request where the issuer generates
// the keypair. Used by the in-process reconciler.
type Request struct {
	CommonName  string
	DNSNames    []string
	IPAddresses []net.IP
	TTL         time.Duration

	// AttestationDigest, when non-nil, is embedded as an X.509 extension
	// (certutil.OIDAttestationDigest) for audit trail.
	AttestationDigest []byte
}

// Result is a newly issued leaf certificate.
type Result struct {
	CertPEM    []byte
	KeyPEM     []byte
	CAChainPEM []byte
	NotBefore  time.Time
	NotAfter   time.Time
}

// Issue generates a fresh ECDSA P-256 keypair and signs a leaf certificate
// against this CA. The caller is responsible for enforcing policy on
// req.DNSNames / req.IPAddresses before calling — the issuer trusts them.
func (c *CA) Issue(req Request) (*Result, error) {
	if req.CommonName == "" {
		return nil, fmt.Errorf("issue: CommonName required")
	}
	if req.TTL <= 0 {
		req.TTL = DefaultLeafTTL
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}

	tmpl, err := certutil.NewLeafTemplate(req.CommonName, req.TTL)
	if err != nil {
		return nil, err
	}
	tmpl.DNSNames = req.DNSNames
	tmpl.IPAddresses = req.IPAddresses
	if err := certutil.AppendAttestationDigest(tmpl, req.AttestationDigest); err != nil {
		return nil, err
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &leafKey.PublicKey, c.Key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}

	leafKeyPEM, err := certutil.MarshalECKeyPEM(leafKey)
	if err != nil {
		return nil, fmt.Errorf("encode leaf key: %w", err)
	}

	return &Result{
		CertPEM:    certutil.EncodeCertPEM(leafDER),
		KeyPEM:     leafKeyPEM,
		CAChainPEM: certutil.EncodeCertPEM(c.Cert.Raw),
		NotBefore:  tmpl.NotBefore,
		NotAfter:   tmpl.NotAfter,
	}, nil
}
