package armtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	agarmtls "github.com/confidential-dot-ai/attestation-go/armtls"
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

// SelfSignedProvider provisions self-signed armTLS certificates using local
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

	family, err := teetypes.ParseFamily(p.Platform)
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

	att, err := attestationFromEvidence(family, []byte(evidence))
	if err != nil {
		return nil, 0, err
	}
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

// attestationFromEvidence wraps evidence fresh from the attestation-api in the
// extension's shape. The TEE type comes from the evidence, not from the
// configured platform (docs/armtls.md, "The attestation extension"): an
// envelope declares its own platform, and the only raw shape is the SEV-SNP
// report. An envelope carries its collateral inside, so certChain stays empty.
func attestationFromEvidence(family TEEType, evidence []byte) (*Attestation, error) {
	envelope, isEnvelope := evidenceEnvelope(evidence)
	switch {
	case isEnvelope && envelope.Platform.Family() != family:
		return nil, fmt.Errorf("%w: attestation-api returned %q evidence on a %s platform", ErrInvalidReport, envelope.Platform, family)
	case isEnvelope:
		return agarmtls.NewAttestation(envelope)
	case family == TEETypeSEVSNP && len(evidence) == SNPReportSize:
		return &Attestation{Family: TEETypeSEVSNP, Report: evidence}, nil
	default:
		return nil, fmt.Errorf("%w: %d bytes from the attestation-api are neither a %s evidence envelope nor a raw SEV-SNP report", ErrInvalidReport, len(evidence), family)
	}
}

// evidenceEnvelope reports whether the payload is a platform-tagged evidence
// envelope, and returns it when it is.
func evidenceEnvelope(evidence []byte) (teetypes.AttestationEvidence, bool) {
	var envelope teetypes.AttestationEvidence
	if err := json.Unmarshal(evidence, &envelope); err != nil {
		return envelope, false
	}
	return envelope, envelope.Platform != ""
}
