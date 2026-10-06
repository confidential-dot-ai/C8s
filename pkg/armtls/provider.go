package armtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

// CertProvider abstracts certificate provisioning. Implementations handle
// key generation, attestation, and certificate creation/signing.
//
// The returned time.Duration is the effective TTL so certState knows when to
// schedule rotation (at 50% of the TTL). Returning 0 means the caller should
// fall back to the configured default TTL.
//
// INVARIANT: implementations set tls.Certificate.Leaf on the returned
// certificate. The manager checks the leaf's validity window on every
// handshake, so an unset Leaf would mean an x509 parse per connection; the
// manager parses it once at provision time rather than trusting this, but a
// provider that already holds the parsed leaf should pass it through.
type CertProvider interface {
	Provision(ctx context.Context) (*tls.Certificate, time.Duration, error)
}

// SelfSignedProvider provisions self-signed ARmTLS certificates using local
// hardware attestation. This is the default provider — it wraps the existing
// provisionCert() logic behind the CertProvider interface.
type SelfSignedProvider struct {
	Platform   string
	AttestFunc func(ctx context.Context, customData string) (string, error)
	Opts       *CertOptions
}

var _ CertProvider = (*SelfSignedProvider)(nil)

// Provision generates a key, obtains hardware attestation, and creates a
// self-signed certificate with the attestation embedded as an X.509 extension.
func (p *SelfSignedProvider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	key, _, err := GenerateKeyPair()
	if err != nil {
		return nil, 0, err
	}

	teeType, err := teetypes.ParseFamily(p.Platform)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %v", ErrUnsupportedTEE, err)
	}

	reportData, err := ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		return nil, 0, err
	}

	customData := fmt.Sprintf("%x", reportData[:])
	evidence, err := p.AttestFunc(ctx, customData)
	if err != nil {
		return nil, 0, fmt.Errorf("armtls: get attestation: %w", err)
	}

	att := &Attestation{Family: teeType, Report: []byte(evidence)}
	certDER, err := CreateAttestedCert(key, att, p.Opts)
	if err != nil {
		return nil, 0, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, 0, fmt.Errorf("armtls: parse issued cert: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        cert,
	}, p.Opts.ttl(), nil
}
