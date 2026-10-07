// Package certutil provides common helper functions shared across the armtls
// project: serial number generation, fingerprinting, PEM encoding, and more.
package certutil

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"time"
)

// serialNumberLimit is 2^128, the upper bound for X.509 serial numbers.
var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// LeafValiditySkew is the single bounded clock-skew allowance every
// certificate-sourced verification path grants NotBefore: a leaf issued up to
// this long in the verifier's future is accepted, anything further is not.
// NotAfter gets no allowance — an expired certificate is expired. 5 minutes
// covers realistic clock drift between an issuing TEE and a verifying
// operator machine without meaningfully extending a stolen-cert window.
const LeafValiditySkew = 5 * time.Minute

// BodyAuthentication classifies what AuthenticateLeafBody proved about a
// certificate's body fields. It is a named type rather than a bool because
// the zero value — "nothing here authenticated it" — is the one a caller must
// never treat as a pass: x509.ParseCertificate verifies no signature at all,
// so an Issuer DN that differs from the Subject by one byte is enough to skip
// the self-signature check with an arbitrary Signature field.
type BodyAuthentication int

const (
	// BodyCAVouched means the certificate is not self-issued: its body is
	// vouched only by whoever signed it, and NOTHING in AuthenticateLeafBody
	// checked that signature. Until the caller verifies the issuing chain (or
	// holds live proof the presenter controls the attested key), every body
	// field — subject, serial, NotAfter, the CA-vouched extensions — is
	// attacker-choosable under a genuine attestation extension. This is the
	// zero value so a discarded classification fails closed.
	BodyCAVouched BodyAuthentication = iota
	// BodySelfSigned means the certificate is self-issued and its body
	// verified under its own embedded (attested) key, so the attestation that
	// binds the key transitively covers the whole body.
	BodySelfSigned
)

func (b BodyAuthentication) String() string {
	if b == BodySelfSigned {
		return "self-signed"
	}
	return "ca-vouched"
}

// CheckValidity enforces the validity window every certificate-sourced trust
// decision shares: NotBefore may sit up to LeafValiditySkew in now's future
// (clock drift between issuer and verifier), NotAfter gets no allowance. It
// is the single implementation of that window — call it rather than
// re-deriving the comparison, so the skew policy cannot drift between sites.
func CheckValidity(cert *x509.Certificate, now time.Time) error {
	if now.Add(LeafValiditySkew).Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid: NotBefore %s is beyond the %s clock-skew allowance",
			cert.NotBefore.Format(time.RFC3339), LeafValiditySkew)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired at NotAfter %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// AuthenticateLeafBody enforces the certificate-body checks shared by every
// path that verifies a certificate-embedded attestation:
//
//   - validity: NotBefore within LeafValiditySkew, NotAfter with no
//     allowance. A nonce-free attested certificate is replayable for as long
//     as it validates, so once the body is authenticated the validity window
//     is the only freshness bound these paths have — skipping it would make
//     the replay window unbounded. Note the ordering: the window bounds
//     nothing on its own, since an unauthenticated body's NotAfter is chosen
//     by whoever wrote the bytes.
//   - self-issued certificates (RawIssuer == RawSubject) must verify their
//     own signature with their embedded key. The attestation extension binds
//     only the public key, so without this check any field outside the key —
//     subject, serial, validity, other extensions — could be rewritten under
//     a genuine attestation and still verify.
//
// The returned BodyAuthentication says which of those two states the caller
// is in. BodyCAVouched is NOT a pass: it means the caller still owes the body
// an authentication step (a verified chain, or proof of possession of the
// attested key) before trusting anything the body says.
//
// The validity window is CheckValidity's, so the skew policy has one
// implementation shared with every other certificate-sourced trust decision.
func AuthenticateLeafBody(cert *x509.Certificate, now time.Time) (BodyAuthentication, error) {
	if err := CheckValidity(cert, now); err != nil {
		return BodyCAVouched, err
	}
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return BodyCAVouched, nil
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		return BodyCAVouched, fmt.Errorf("self-signed certificate body does not verify with its own key (altered or re-signed body): %w", err)
	}
	return BodySelfSigned, nil
}

// OIDAttestationDigest marks issued certificates with a SHA-256 of the
// attestation evidence that authorized issuance — an audit-trail extension
// shared between the CDS HTTP signer and the in-process issuer.
var OIDAttestationDigest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66378, 1, 2}

// GenerateSerial returns a cryptographically random 128-bit serial number
// suitable for X.509 certificates.
func GenerateSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, serialNumberLimit)
}

// CertFingerprint returns the lowercase hex SHA-256 fingerprint of raw
// certificate bytes (DER or x509.Certificate.Raw).
func CertFingerprint(raw []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

// EncodeCertPEM encodes DER certificate bytes as a PEM block.
func EncodeCertPEM(certDER []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

// MarshalECKeyPEM marshals an EC private key to PKCS#8 PEM format.
// PKCS#8 ("PRIVATE KEY" header) is what CDS and the rest of the stack
// expect; SEC 1 ("EC PRIVATE KEY") fails to parse with x509.ParsePKCS8PrivateKey.
func MarshalECKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// ParseECPrivateKey parses a PEM-encoded EC private key, trying PKCS8 first
// then SEC 1 (EC) format.
func ParseECPrivateKey(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	// Try PKCS8 first (openssl genpkey), then EC (openssl ecparam).
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		if ec, ok := key.(*ecdsa.PrivateKey); ok {
			return ec, nil
		}
		return nil, fmt.Errorf("pkcs8 key is not ECDSA")
	}
	ec, err2 := x509.ParseECPrivateKey(block.Bytes)
	if err2 != nil {
		return nil, fmt.Errorf("parse key: PKCS8: %w; EC: %w", err, err2)
	}
	return ec, nil
}

// LoadECPrivateKeyFile reads a PEM file and parses the EC private key.
func LoadECPrivateKeyFile(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseECPrivateKey(data)
}

// ParseCertificatePEM parses a PEM-encoded certificate, returning the first
// CERTIFICATE block found. Use [LoadCertificateFile] for file-based loading.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}

// LoadCertificateFile reads a PEM file and parses the first certificate.
func LoadCertificateFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseCertificatePEM(data)
}

// NewJSONLogger creates a JSON [slog.Logger] writing to stdout at the given
// level string. An empty string selects info; any other value must be one of
// debug, info, warn, error (case-insensitive) or an error is returned, so a
// typo fails at startup rather than silently logging at info.
func NewJSONLogger(levelStr string) (*slog.Logger, error) {
	return NewJSONLoggerTo(os.Stdout, levelStr)
}

// NewJSONLoggerTo is NewJSONLogger with an explicit writer, for commands that
// must keep stdout reserved for machine-readable output and send diagnostics
// to stderr.
func NewJSONLoggerTo(w io.Writer, levelStr string) (*slog.Logger, error) {
	level := slog.LevelInfo
	if levelStr != "" {
		// Delegate parsing/validation to the stdlib instead of maintaining a
		// level table here.
		if err := level.UnmarshalText([]byte(levelStr)); err != nil {
			return nil, err
		}
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})), nil
}

// ParsePEMCertificates parses all CERTIFICATE PEM blocks from data and returns
// the parsed certificates. It returns an error if no certificate blocks are found.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found")
	}
	return certs, nil
}

// TrimExpiredCABundle returns the subset of certs whose NotAfter is after
// cutoff. The dropped certs are returned in dropped — callers typically log
// their fingerprints. Order is preserved relative to the input.
func TrimExpiredCABundle(certs []*x509.Certificate, cutoff time.Time) (kept, dropped []*x509.Certificate) {
	for _, cert := range certs {
		if cert.NotAfter.Before(cutoff) {
			dropped = append(dropped, cert)
			continue
		}
		kept = append(kept, cert)
	}
	return kept, dropped
}

// LoadPEMCertificatesFile reads a PEM file and parses all CERTIFICATE blocks.
func LoadPEMCertificatesFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParsePEMCertificates(data)
}

// NewCATemplate returns an x509.Certificate template for a self-signed CA
// with the given serial number, subject common name, and expiry time.
func NewCATemplate(serial *big.Int, commonName string, notAfter time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// NewLeafTemplate returns the canonical x509 leaf-certificate template used
// by the C8s issuers: digital-signature key usage and Server+Client
// extended key usage, anchored at time.Now() with the given TTL. Callers
// populate DNSNames / IPAddresses on the returned template themselves so
// SAN policy stays at the call site.
func NewLeafTemplate(commonName string, ttl time.Duration) (*x509.Certificate, error) {
	serial, err := GenerateSerial()
	if err != nil {
		return nil, fmt.Errorf("generate leaf serial: %w", err)
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}, nil
}

// AppendAttestationDigest stamps an OIDAttestationDigest extension carrying
// the given digest onto tmpl. No-op when digest is empty.
func AppendAttestationDigest(tmpl *x509.Certificate, digest []byte) error {
	if len(digest) == 0 {
		return nil
	}
	ext, err := asn1.Marshal(digest)
	if err != nil {
		return fmt.Errorf("marshal attestation digest: %w", err)
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
		Id:    OIDAttestationDigest,
		Value: ext,
	})
	return nil
}
