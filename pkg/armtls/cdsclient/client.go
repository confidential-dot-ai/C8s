// Package cdsclient implements certificate provisioning via the CDS
// attestation-api. It performs the attestation flow:
// authenticate -> attest -> obtain certificate and authenticated CA bundle.
// Later CA refreshes fetch /ca from CDS and require trust
// continuity.
package cdsclient

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Config for the CDS attestation client.
type Config struct {
	// CDSURL is the base URL of the CDS service
	// (e.g., "https://cds.c8s-system.svc:8443").
	CDSURL string

	// AttestationApiURL is the URL of the local attestation-api
	// used by CDS to generate TEE evidence
	// (e.g., "http://localhost:8400").
	AttestationApiURL string

	// CDSCAURL is the base URL of the CDS CA endpoint for CA
	// bundle refreshes after authenticated provisioning
	// (e.g., "https://cds.c8s-system.svc:8443").
	CDSCAURL string

	// CACertURL, when set, is the exact URL used for CA bundle refreshes.
	// Empty defaults to CDSCAURL + "/ca".
	CACertURL string

	// NodeIP is this node's IP, used only in the certificate CommonName.
	NodeIP string

	// NodeName is this node's hostname for the certificate subject.
	NodeName string

	// DNSSAN, when set, is the sole DNS SAN placed on the CSR. The mesh
	// authenticates peers by attestation, not by SAN, so this carries no
	// security meaning for the mesh; it exists to satisfy the CDS CSR policy
	// (CDS with --san-validation=false rejects IP SANs, so the leaf must
	// present a DNS SAN matching --dns-san-pattern). Empty omits all SANs.
	DNSSAN string

	// TEEType is the TEE platform to stamp into the armTLS attestation
	// extension. It must be specified explicitly. Only SEV-SNP is currently
	// supported by the CDS client evidence extraction path.
	TEEType armtls.TEEType

	// CDSMeasurements, when non-empty, restricts the CDS server's
	// accepted launch digests during the armTLS handshake to this set.
	// Each entry is a 48-byte SEV-SNP measurement. Empty means "any
	// measurement" — UNSAFE outside development; the chart should always
	// populate this from `cds.measurements` in values.yaml.
	CDSMeasurements [][]byte

	// CDSRTMRs, when non-empty, additionally pins CDS's TDX runtime
	// measurement registers by index during the armTLS handshake. On TDX the
	// launch digest covers TDVF firmware alone, so without these the
	// handshake trusts a CDS whose kernel and rootfs the host chose. Ignored
	// when CDS presents SNP evidence. Populate from `cds.rtmrs`.
	CDSRTMRs map[int][]byte

	// CDSImages additionally binds the CDS image to its authorized server key.
	CDSImages []remote.ImagePin

	// HTTPClient is an optional HTTP client. If nil, a default armTLS
	// transport is built using the CDSMeasurements policy. Tests that
	// need to bypass armTLS (e.g. against a plain HTTP fake) can supply a
	// custom client; production code MUST leave this nil so the client is
	// constructed with attestation-bound peer verification.
	HTTPClient *http.Client
}

// Client handles certificate provisioning via CDS.
type Client struct {
	cfg             *Config
	httpClient      *http.Client
	cdsAttestClient attestclient.Client
	mu              sync.RWMutex
	trustedCABundle []*x509.Certificate
}

// NewClient creates an CDS attestation client. When cfg.HTTPClient is nil,
// the returned client dials CDS over armTLS with a peer-verification policy
// built from cfg.CDSMeasurements; this is what closes the bootstrap-channel
// MITM gap (an on-path attacker cannot present a TEE-attested cert with an
// allowed measurement, so the TLS handshake fails before any cert is issued).
func NewClient(cfg *Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		policy := &armtls.VerifyPolicy{Policy: remote.Policy{Images: cfg.CDSImages, Measurements: cfg.CDSMeasurements, Registers: cfg.CDSRTMRs}, AttestationApiURL: cfg.AttestationApiURL}
		tlsCfg, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{Policy: policy})
		if err != nil {
			// NewClientTLSConfig only errors on misconfigured Platform/AttestFunc
			// pairs, which we never set; treat unexpected failure as a programmer
			// bug by falling back to a transport that will always fail closed.
			tlsCfg = nil
		}
		httpClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
				ResponseHeaderTimeout: 10 * time.Second,
				IdleConnTimeout:       30 * time.Second,
				MaxIdleConns:          10,
				MaxConnsPerHost:       5,
				TLSClientConfig:       tlsCfg,
			},
		}
	}
	return &Client{
		cfg:             cfg,
		httpClient:      httpClient,
		cdsAttestClient: attestclient.NewClientWithHTTP(cfg.CDSURL, httpClient),
	}
}

// RequestCert performs the full CDS attestation + certificate issuance flow:
//  1. Generate ECDSA keypair + CSR
//  2. Call CDS (authenticate -> attest) over armTLS to get a signed certificate
//     chain. Authenticity of the response is provided by the armTLS handshake
//     (the underlying http.Client's TLSClientConfig verifies CDS's peer cert
//     against the configured reference values).
//  3. Return key + leaf cert + authenticated CA bundle from the signed response
func (c *Client) RequestCert(ctx context.Context) (*ecdsa.PrivateKey, []byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	csrPEM, err := c.createCSR(ctx, key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	certPEM, err := c.cdsAttestClient.ObtainCertificateWithContext(ctx, c.cfg.AttestationApiURL, csrPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("CDS attestation: %w", err)
	}

	certs, err := certutil.ParsePEMCertificates([]byte(certPEM))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CDS certificate response: %w", err)
	}
	if len(certs) < 2 {
		return nil, nil, nil, fmt.Errorf("CDS certificate response missing CA bundle")
	}

	return key, certutil.EncodeCertPEM(certs[0].Raw), encodeCABundlePEM(certs[1:]), nil
}

// refreshCABundle fetches the CA certificate bundle from CDS's
// /ca endpoint. A candidate is accepted only when it is already trusted or
// when it is a CA certificate signed by an already trusted CA. This keeps
// unauthenticated CA bundle refreshes from expanding trust without signature
// continuity. Reached only through [Provider.RefreshCABundle], over the client
// [Provider.Provision] seeds that trust on.
func (c *Client) refreshCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	certs, err := c.fetchAndParseCABundle(ctx)
	if err != nil {
		return nil, err
	}
	return c.acceptCABundle(certs)
}

func (c *Client) fetchAndParseCABundle(ctx context.Context) ([]*x509.Certificate, error) {
	pemData, err := c.fetchCACertPEM(ctx)
	if err != nil {
		return nil, err
	}
	certs, err := certutil.ParsePEMCertificates(pemData)
	if err != nil {
		return nil, fmt.Errorf("CA bundle: %w", err)
	}
	return certs, nil
}

// TrustedCABundle returns the currently accepted CA bundle. The returned slice
// can be passed to armtls.CertManager.UpdateCACerts.
func (c *Client) TrustedCABundle() []*x509.Certificate {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return cloneCertSlice(c.trustedCABundle)
}

func (c *Client) rememberVerifiedCABundle(verified, published []*x509.Certificate, now time.Time) []*x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()

	accepted := dedupeCerts(verified)
	for _, cert := range published {
		if containsCert(accepted, cert) {
			continue
		}
		// Preserve overlap across in-memory CDS restarts without
		// expanding trust to CAs this client has never accepted before.
		if containsCert(c.trustedCABundle, cert) && isUsableCA(cert, now) {
			accepted = append(accepted, cert)
		}
	}

	ordered := orderLikePublished(accepted, published)
	c.trustedCABundle = cloneCertSlice(ordered)
	return cloneCertSlice(ordered)
}

func (c *Client) acceptCABundle(candidates []*x509.Certificate) ([]*x509.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.trustedCABundle) == 0 {
		return nil, fmt.Errorf("CA bundle refresh requires a trusted CA from CDS certificate provisioning")
	}

	accepted := continuityCABundle(dedupeCerts(candidates), c.trustedCABundle, time.Now())
	if len(accepted) == 0 {
		return nil, fmt.Errorf("CA bundle refresh rejected: no trusted CA continuity")
	}
	c.trustedCABundle = cloneCertSlice(accepted)
	return cloneCertSlice(accepted), nil
}

func (c *Client) createCSR(ctx context.Context, key *ecdsa.PrivateKey) (string, error) {
	cn := fmt.Sprintf("armtls-mesh-%s", c.cfg.NodeIP)
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Confidential"},
		},
	}
	// DNS SAN only — no IP SAN. CDS with --san-validation=false rejects IP
	// SANs, and the mesh verifies peers by attestation, not SAN, so the node
	// IP belongs in the CN, not a SAN.
	if c.cfg.DNSSAN != "" {
		tmpl.DNSNames = []string{c.cfg.DNSSAN}
	}

	ext, err := c.attestationExtension(ctx, key)
	if err != nil {
		return "", err
	}
	tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

func (c *Client) attestationExtension(ctx context.Context, key *ecdsa.PrivateKey) (pkix.Extension, error) {
	teeType, err := c.cfg.teeType()
	if err != nil {
		return pkix.Extension{}, err
	}

	// This no-nonce report is embedded for peer armTLS fallback. CDS still
	// performs a separate challenge-bound attestation before issuing the cert.
	reportData, err := armtls.ReportDataForKey(&key.PublicKey, nil)
	if err != nil {
		return pkix.Extension{}, err
	}
	resp, err := c.cdsAttestClient.GenerateEvidenceContext(ctx, c.cfg.AttestationApiURL, reportData[:sha512.Size384])
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("attestation-api: %w", err)
	}
	report, err := attestclient.ARMTLSEvidence(resp)
	if err != nil {
		return pkix.Extension{}, err
	}
	att := &armtls.Attestation{
		Family: teeType,
		Report: []byte(report),
	}
	return armtls.MarshalExtension(att)
}

func (cfg *Config) teeType() (armtls.TEEType, error) {
	if cfg == nil || cfg.TEEType == "" {
		return "", fmt.Errorf("cdsclient: TEEType is required")
	}
	// Both SEV-SNP and TDX are supported. attestclient.ARMTLSEvidence
	// dispatches per-TEE (SNP → raw report bytes; TDX → envelope minus
	// cc_eventlog to fit the TLS 1.3 16 KB record cap), and CDS's
	// challenge-bound verify path handles both.
	switch cfg.TEEType {
	case armtls.TEETypeSEVSNP, armtls.TEETypeTDX:
		return cfg.TEEType, nil
	default:
		return "", fmt.Errorf("cdsclient: TEEType %s is not supported", cfg.TEEType)
	}
}

func (c *Client) fetchCACertPEM(ctx context.Context) ([]byte, error) {
	url := c.caCertURL()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET CA bundle %q returned %d: %s", url, resp.StatusCode, body)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
}

func (c *Client) caCertURL() string {
	if c.cfg.CACertURL != "" {
		return c.cfg.CACertURL
	}
	return strings.TrimRight(c.cfg.CDSCAURL, "/") + "/ca"
}

func encodeCABundlePEM(certs []*x509.Certificate) []byte {
	var out []byte
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		out = append(out, certutil.EncodeCertPEM(cert.Raw)...)
	}
	return out
}

func containsCert(certs []*x509.Certificate, cert *x509.Certificate) bool {
	for _, candidate := range certs {
		if sameCertificate(candidate, cert) {
			return true
		}
	}
	return false
}

func continuityCABundle(published, trusted []*x509.Certificate, now time.Time) []*x509.Certificate {
	seed := make([]*x509.Certificate, 0, len(published))
	for _, cert := range published {
		if !isUsableCA(cert, now) {
			continue
		}
		if containsCert(trusted, cert) || renewalOfTrustedCA(cert, trusted) {
			seed = append(seed, cert)
		}
	}
	accepted := growAcceptedByLink(seed, published, trusted, now, certSignedByOther)
	return orderLikePublished(accepted, published)
}

// renewalOfTrustedCA reports whether cert is a renewed certificate for a
// trusted CA: the same subject and public key, self-signed under that key so
// only its holder could have published it, and outliving the certificate it
// replaces so a replay cannot shorten the anchor.
func renewalOfTrustedCA(cert *x509.Certificate, trusted []*x509.Certificate) bool {
	if cert.CheckSignatureFrom(cert) != nil {
		return false
	}
	for _, anchor := range trusted {
		if anchor == nil {
			continue
		}
		if bytes.Equal(anchor.RawSubjectPublicKeyInfo, cert.RawSubjectPublicKeyInfo) &&
			bytes.Equal(anchor.RawSubject, cert.RawSubject) &&
			cert.NotAfter.After(anchor.NotAfter) {
			return true
		}
	}
	return false
}

// growAcceptedByLink iteratively extends accepted with candidates that share
// a signature link (in the caller-supplied direction) with the current
// accepted set, plus any extraAnchors. Loops until no candidate is added.
func growAcceptedByLink(accepted, candidates, extraAnchors []*x509.Certificate, now time.Time, link func(cert, other *x509.Certificate) error) []*x509.Certificate {
	for {
		changed := false
		anchors := append(cloneCertSlice(extraAnchors), accepted...)
		for _, cand := range candidates {
			if containsCert(accepted, cand) {
				continue
			}
			if hasUsableCASignatureLink(cand, anchors, now, link) {
				accepted = append(accepted, cand)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return accepted
}

// hasUsableCASignatureLink reports whether cert (a usable CA) is linked by
// signature to any usable CA in others, after filtering out same-cert and
// same-pubkey matches. link is called with (cert, other) and must return nil
// for a valid signature relation in the caller's chosen direction.
func hasUsableCASignatureLink(cert *x509.Certificate, others []*x509.Certificate, now time.Time, link func(cert, other *x509.Certificate) error) bool {
	if !isUsableCA(cert, now) {
		return false
	}
	for _, other := range others {
		if other == nil || sameCertificate(other, cert) {
			continue
		}
		if !isUsableCA(other, now) {
			continue
		}
		if samePublicKey(other, cert) {
			continue
		}
		if link(cert, other) == nil {
			return true
		}
	}
	return false
}

func certSignsOther(cert, other *x509.Certificate) error { return other.CheckSignatureFrom(cert) }

func certSignedByOther(cert, other *x509.Certificate) error { return cert.CheckSignatureFrom(other) }

func isUsableCA(cert *x509.Certificate, now time.Time) bool {
	return cert != nil &&
		cert.IsCA &&
		!cert.NotBefore.After(now) &&
		cert.NotAfter.After(now) &&
		(cert.KeyUsage == 0 || cert.KeyUsage&x509.KeyUsageCertSign != 0)
}

func samePublicKey(a, b *x509.Certificate) bool {
	if a == nil || b == nil {
		return false
	}
	aDER, err := x509.MarshalPKIXPublicKey(a.PublicKey)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b.PublicKey)
	if err != nil {
		return false
	}
	return bytes.Equal(aDER, bDER)
}

func dedupeCerts(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, len(certs))
	for _, cert := range certs {
		if cert == nil || containsCert(out, cert) {
			continue
		}
		out = append(out, cert)
	}
	return out
}

func sameCertificate(a, b *x509.Certificate) bool {
	return a != nil && b != nil && bytes.Equal(a.Raw, b.Raw)
}

func cloneCertSlice(certs []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, len(certs))
	copy(out, certs)
	return out
}

func orderLikePublished(accepted, published []*x509.Certificate) []*x509.Certificate {
	ordered := make([]*x509.Certificate, 0, len(accepted))
	for _, cert := range published {
		if containsCert(accepted, cert) && !containsCert(ordered, cert) {
			ordered = append(ordered, cert)
		}
	}
	for _, cert := range accepted {
		if !containsCert(ordered, cert) {
			ordered = append(ordered, cert)
		}
	}
	return ordered
}
