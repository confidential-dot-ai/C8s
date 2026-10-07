// Package routerdiscovery consumes the router front-door discovery contract
// (types.DiscoveryDocument, served at /v1/discovery, written by get-cert).
// The front door's serving cert carries no armTLS extension; its trust path is
// the discovery document instead: attestation evidence captured at issuance,
// with REPORTDATA binding the serving-cert key + issuance challenge
// (armtls.ReportDataForKey).
//
// Serving certs are per replica (each router pod provisions its own leaf into
// a pod-local emptyDir), so evidence fetched on one connection says nothing
// about the leaf a *different* connection would be served — a scaled-out or
// rolling Service can answer alternating handshakes with alternating certs.
// This package therefore dials the front door exactly once, fetches and
// verifies the document over that connection, requires the attested cert to
// be the leaf that same handshake presented, and returns an HTTP client bound
// to that one verified connection. The client never redials: a lost
// connection fails closed with a re-run hint. Per-connection re-verification
// is the eventual replacement for this single-connection model.
//
// Evidence verification runs in-process (internal/localverify).
package routerdiscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// DefaultPath is the path the router serves its discovery document on.
const DefaultPath = "/v1/discovery"

// maxDocumentBytes caps the discovery document read.
const maxDocumentBytes = 1 << 20

// ErrNoDiscovery reports that the target serves no discovery document
// (unreachable, or a non-200 on the discovery path). Callers use it to fall
// back to direct armTLS serving-cert verification
// (localverify.NewARMTLSHTTPClient). A document that is present but malformed
// or failing verification is NOT this error — those fail closed.
var ErrNoDiscovery = errors.New("routerdiscovery: target serves no discovery document")

// NewVerifiedHTTPClient returns an http.Client for a router front door: it
// dials base once, fetches the discovery document over that connection,
// verifies the embedded attestation evidence (launch measurement checked
// against measurements — empty accepts any, UNSAFE), and requires the
// attested serving certificate to be the leaf the connection's handshake
// presented. The returned client is bound to that single verified connection
// (requests are serialized over it) and only for base's host; it never
// redials, so a lost connection fails closed — see the package comment for
// why (per-replica serving certs).
//
// verify is localverify.Verify in production, a stub in tests.
//
// Returns [ErrNoDiscovery] when base serves no discovery document, so callers
// can fall back to direct armTLS verification for a non-fronted endpoint.
//
// The issuance challenge is fixed, not a per-request nonce, so freshness is
// not proven — the same trade-off as `c8s verify` discovery mode.
func NewVerifiedHTTPClient(ctx context.Context, base string, measurements [][]byte, verify localverify.VerifyFunc) (*http.Client, error) {
	if verify == nil {
		return nil, fmt.Errorf("routerdiscovery: evidence verifier is required")
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", base, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("routerdiscovery: URL scheme must be https, got %q", u.Scheme)
	}

	conn, err := dialFrontDoor(ctx, u.Host)
	if err != nil {
		return nil, fmt.Errorf("%w: dial %s: %v", ErrNoDiscovery, u.Host, err)
	}
	client := newSingleConnClient(conn)
	verified := false
	defer func() {
		if !verified {
			conn.Close()
		}
	}()

	data, err := fetchDocument(ctx, client, u)
	if err != nil {
		return nil, err
	}
	cert, err := verifyDocument(ctx, data, verify, measurements)
	if err != nil {
		return nil, fmt.Errorf("routerdiscovery: discovery document verification failed: %w", err)
	}

	// The evidence binds cert's key; require cert to be the leaf THIS
	// connection presented, or the attestation says nothing about the peer we
	// are talking to (a different replica may have answered the handshake).
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, fmt.Errorf("routerdiscovery: connection presented no peer certificate")
	}
	if !bytes.Equal(peers[0].Raw, cert.Raw) {
		docSum := sha256.Sum256(cert.Raw)
		connSum := sha256.Sum256(peers[0].Raw)
		return nil, fmt.Errorf("routerdiscovery: discovery document attests serving cert sha256 %s but the connection presented %s — a different router replica may have answered; re-run the command",
			hex.EncodeToString(docSum[:]), hex.EncodeToString(connSum[:]))
	}

	verified = true
	return client, nil
}

// dialFrontDoor opens the one TLS connection the returned client will use.
// PKI is intentionally not verified — the trust anchor is the attestation in
// the discovery document, which NewVerifiedHTTPClient binds to this
// connection's leaf after the fetch.
func dialFrontDoor(ctx context.Context, host string) (*tls.Conn, error) {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true, //nolint:gosec // attestation, not PKI, authenticates the peer; see dialFrontDoor doc
		},
	}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	return conn.(*tls.Conn), nil
}

// fetchDocument GETs the discovery document through the connection-bound
// client. Fetch failures wrap [ErrNoDiscovery].
func fetchDocument(ctx context.Context, client *http.Client, base *url.URL) ([]byte, error) {
	u := *base
	u.Path = DefaultPath
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: GET %s: %v", ErrNoDiscovery, u.String(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: GET %s returned %d", ErrNoDiscovery, u.String(), resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes))
	if err != nil {
		return nil, fmt.Errorf("read discovery document: %w", err)
	}
	return data, nil
}

// verifyDocument parses a discovery document, verifies its attestation
// evidence, and returns the attested serving certificate. REPORTDATA =
// SHA-384(cert pubkey ‖ challenge), matching get-cert's issuance binding
// (reportDataForCSR → armtls.ReportDataForKey), passed as the unpadded 48-byte
// anchor.
func verifyDocument(ctx context.Context, data []byte, verify localverify.VerifyFunc, measurements [][]byte) (*x509.Certificate, error) {
	var d types.DiscoveryDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}

	// Only a cds-mode front door serves the CDS-issued leaf the evidence
	// binds; empty means a pre-mode-field document (cds in practice). Anything
	// else fails closed here rather than returning a client whose handshakes
	// can never match the attested cert.
	switch d.PublicTLS.Mode {
	case "", "cds":
	case "webpki":
		return nil, fmt.Errorf("front door public_tls.mode=webpki is not supported: it serves an operator WebPKI certificate this client cannot yet bind to the attestation evidence; use a cds-mode front door or port-forward CDS directly")
	case "acme":
		return nil, fmt.Errorf("front door public_tls.mode=acme is not supported: it serves an in-guest ACME certificate the issuance evidence does not bind; use a cds-mode front door or port-forward CDS directly")
	default:
		return nil, fmt.Errorf("unknown public_tls.mode %q in discovery document", d.PublicTLS.Mode)
	}

	cert, erd, err := armtls.AttestedCertFromDiscovery(&d)
	if err != nil {
		return nil, err
	}
	// Enforce the shared validity window before the evidence round-trip, so an
	// honestly-stale document is refused without costing a verification.
	//
	// The classification is deliberately not asserted here, and the window is
	// ADVISORY on this path: cds_tls.certificate_pem is the router's
	// CDS-issued leaf, so RawIssuer != RawSubject and the result is
	// BodyCAVouched — nothing checked that issuer's signature. This package
	// cannot fix that: it is bootstrapping trust, the only CA it could reach
	// is one this same unauthenticated document advertises, and the challenge
	// it binds is read out of the document too, so there is no freshness
	// anywhere on this path. A forger re-minting this body around the attested
	// key picks its own NotAfter. The bound that actually holds is applied by
	// the caller, NewVerifiedHTTPClient: the attested leaf must be
	// byte-identical to the one this connection's handshake presented, which
	// only the holder of the attested key can produce.
	if _, err := certutil.AuthenticateLeafBody(cert, time.Now()); err != nil {
		return nil, fmt.Errorf("discovery serving cert: %w", err)
	}

	// Empty platform defaults to bare-metal snp (pre-platform-field carriers);
	// a genuinely unknown platform fails closed in the verifier.
	platform := d.Attestation.Platform
	if platform == "" {
		platform = string(teetypes.PlatformSNP)
	}
	if _, err := verify(ctx, platform, d.Attestation.Evidence, localverify.Params{
		Measurements:       measurements,
		ExpectedReportData: erd[:sha512.Size384],
	}); err != nil {
		return nil, err
	}
	return cert, nil
}

// newSingleConnClient returns an http.Client whose transport hands out exactly
// conn (MaxConnsPerHost=1 serializes requests over it) and never dials again:
// the attestation verified one handshake, and a new handshake could reach a
// different router replica whose leaf that evidence does not cover. A lost
// connection — server keepalive close, idle eviction, cert rotation — fails
// closed with a re-run hint. Timeout knobs mirror armtls.NewVerifyingHTTPClient.
// dialFrontDoor + this guard are a sibling of the verify CLI's dialFrontDoor +
// singleConnClient (internal/cmds/verify/discovery.go) — port fixes both ways.
func newSingleConnClient(conn *tls.Conn) *http.Client {
	var used atomic.Bool
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				if used.Swap(true) {
					return nil, errors.New("routerdiscovery: the attested connection was lost and redialing could reach a different router replica; re-run the command to attest a fresh connection")
				}
				return conn, nil
			},
			ResponseHeaderTimeout: 10 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          1,
			MaxConnsPerHost:       1,
		},
	}
}
