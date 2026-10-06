package cdsclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Logger is a type alias for [armtls.Logger] to avoid requiring callers
// to import both packages.
type Logger = armtls.Logger

// Provider implements armtls.CertProvider using CDS attestation and the
// CDS CA endpoint. Each Provision call performs:
// authenticate -> attest -> obtain cert and authenticated CA bundle -> return
// CA-signed certificate.
//
// Provision and RefreshCABundle share one client: the CA bundle Provision
// accepts is the trust the refresh continuity-checks against.
type Provider struct {
	client *Client
	logger Logger
}

// Ensure Provider implements CertProvider at compile time.
var _ armtls.CertProvider = (*Provider)(nil)

// NewProvider creates an CDS-backed CertProvider.
func NewProvider(cfg *Config, logger Logger) (*Provider, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return newProviderWithClient(NewClient(cfg), logger)
}

func newProviderWithClient(client *Client, logger Logger) (*Provider, error) {
	if client == nil || client.cfg == nil {
		return nil, fmt.Errorf("cdsclient: client is required")
	}
	if err := validateConfig(client.cfg); err != nil {
		return nil, err
	}

	return &Provider{
		client: client,
		logger: logger,
	}, nil
}

func validateConfig(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("cdsclient: Config is required")
	}
	if cfg.CDSURL == "" {
		return fmt.Errorf("cdsclient: CDSURL is required")
	}
	if cfg.AttestationApiURL == "" {
		return fmt.Errorf("cdsclient: AttestationApiURL is required")
	}
	if cfg.CDSCAURL == "" {
		return fmt.Errorf("cdsclient: CDSCAURL is required")
	}
	if cfg.NodeIP == "" {
		return fmt.Errorf("cdsclient: NodeIP is required")
	}
	if net.ParseIP(cfg.NodeIP) == nil {
		return fmt.Errorf("cdsclient: NodeIP %q is not a valid IP address", cfg.NodeIP)
	}
	if _, err := cfg.teeType(); err != nil {
		return err
	}

	return nil
}

// RefreshCABundle fetches the current CA bundle from CDS's /ca endpoint.
// Provision must have run first: the refresh only accepts candidates with
// signature continuity to the bundle provisioning already established.
func (p *Provider) RefreshCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	return p.client.refreshCABundle(ctx)
}

// Provision performs the full CDS attestation flow and returns a CA-signed
// TLS certificate along with its effective TTL.
func (p *Provider) Provision(ctx context.Context) (*tls.Certificate, time.Duration, error) {
	if p.logger != nil {
		p.logger.Info("cdsclient: requesting CDS-issued certificate")
	}

	key, certPEM, caCertPEM, err := p.client.RequestCert(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("cdsclient: request cert: %w", err)
	}

	cert, err := certutil.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("cdsclient: parse issued cert: %w", err)
	}
	if !certificateMatchesPrivateKey(cert, key) {
		return nil, 0, fmt.Errorf("cdsclient: issued cert public key does not match generated private key")
	}

	// Parse CA bundle from CDS's signed certificate response. This is the
	// authenticated trust seed; unauthenticated /ca polling only runs after
	// this bundle is established.
	caCerts, err := certutil.ParsePEMCertificates(caCertPEM)
	if err != nil {
		return nil, 0, fmt.Errorf("cdsclient: parse CA cert: %w", err)
	}

	// The issued leaf must be usable now: NotBefore within the shared
	// clock-skew allowance, NotAfter in the future. A leaf outside the window
	// would be cached and served to peers that reject it, so fail issuance
	// instead.
	now := time.Now()
	if err := certutil.CheckValidity(cert, now); err != nil {
		return nil, 0, fmt.Errorf("cdsclient: issued certificate: %w", err)
	}

	// Verify the issued certificate against the first CA in CDS's ordered
	// response before using it as a trust seed. Retained parents are accepted
	// only when they directly sign an accepted CA without reusing that child
	// CA's public key.
	trustSeed, err := verifiedInitialCABundle(cert, caCerts, now)
	if err != nil {
		return nil, 0, fmt.Errorf("cdsclient: issued cert does not chain to CA: %w", err)
	}

	trustedCAs := p.client.rememberVerifiedCABundle(trustSeed, caCerts, now)
	if len(trustedCAs) == 0 {
		return nil, 0, fmt.Errorf("cdsclient: issued cert verification produced no trusted CA")
	}

	chain := [][]byte{cert.Raw}
	for _, ca := range trustedCAs {
		chain = append(chain, ca.Raw)
	}

	tlsCert := &tls.Certificate{
		Certificate: chain,
		PrivateKey:  key,
		Leaf:        cert,
	}

	ttl := time.Until(cert.NotAfter)
	if ttl <= 0 {
		return nil, 0, fmt.Errorf("cdsclient: issued certificate already expired")
	}

	if p.logger != nil {
		p.logger.Info("cdsclient: certificate provisioned",
			"subject", cert.Subject.CommonName,
			"ttl", ttl.Round(time.Second),
			"notAfter", cert.NotAfter,
		)
	}

	return tlsCert, ttl, nil
}

func verifiedInitialCABundle(cert *x509.Certificate, caCerts []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	if len(caCerts) == 0 {
		return nil, fmt.Errorf("CA bundle is empty")
	}

	signer := caCerts[0]
	if !isUsableCA(signer, now) {
		return nil, fmt.Errorf("first CA in bundle is not usable")
	}
	if err := cert.CheckSignatureFrom(signer); err != nil {
		return nil, err
	}

	return growAcceptedByLink([]*x509.Certificate{signer}, caCerts[1:], nil, now, certSignsOther), nil
}

func certificateMatchesPrivateKey(cert *x509.Certificate, key *ecdsa.PrivateKey) bool {
	if cert == nil || key == nil {
		return false
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && key.PublicKey.Equal(pub)
}
