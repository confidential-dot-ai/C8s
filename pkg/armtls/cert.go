package armtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// DefaultCertTTL is the default certificate lifetime used by both
// [CertOptions] and [ServerConfig] when no TTL is specified.
const DefaultCertTTL = 24 * time.Hour

// CertOptions configures armTLS certificate generation.
type CertOptions struct {
	// Subject for the certificate. If empty, a default is used.
	Subject pkix.Name
	// TTL is the certificate lifetime. Default: 24 hours.
	TTL time.Duration
	// DNSNames for the certificate's SAN extension.
	DNSNames []string
}

func (o *CertOptions) ttl() time.Duration {
	if o.TTL == 0 {
		return DefaultCertTTL
	}
	return o.TTL
}

func (o *CertOptions) subject() pkix.Name {
	if o.Subject.CommonName == "" {
		return pkix.Name{
			CommonName:   "armTLS Workload",
			Organization: []string{"Confidential"},
		}
	}
	return o.Subject
}

// GenerateKeyPair creates a new ECDSA P-256 keypair suitable for armTLS.
// Returns the private key and the REPORTDATA that must be embedded in the
// hardware attestation report to bind this key to the TEE.
func GenerateKeyPair() (*ecdsa.PrivateKey, [64]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, [64]byte{}, fmt.Errorf("armtls: generate key: %w", err)
	}

	reportData, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		return nil, [64]byte{}, err
	}

	return key, reportData, nil
}

// CreateAttestedCert generates an X.509 certificate with TEE attestation
// embedded as a custom extension. The certificate is the transport container
// for delivering attestation evidence during TLS handshakes — trust comes
// from the hardware attestation chain (AMD ARK → ASK → VCEK → report),
// not from the certificate's own signature.
//
// The attestation report's REPORTDATA must contain hash(publicKey) — this is
// NOT verified here but will be checked by [VerifyCert].
func CreateAttestedCert(key *ecdsa.PrivateKey, att *Attestation, opts *CertOptions) ([]byte, error) {
	if opts == nil {
		opts = &CertOptions{}
	}

	ext, err := MarshalExtension(att)
	if err != nil {
		return nil, err
	}
	extensions := []pkix.Extension{ext}

	serialNumber, err := certutil.GenerateSerial()
	if err != nil {
		return nil, fmt.Errorf("armtls: generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               opts.subject(),
		NotBefore:             now,
		NotAfter:              now.Add(opts.ttl()),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              opts.DNSNames,
		ExtraExtensions:       extensions,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("armtls: create certificate: %w", err)
	}

	return certDER, nil
}
