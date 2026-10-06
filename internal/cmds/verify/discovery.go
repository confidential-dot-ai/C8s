package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"strings"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// defaultDiscoveryPath is the path the router serves its discovery document on.
const defaultDiscoveryPath = "/v1/discovery"

// frontDoorObservation is what a discovery gather's live TLS handshake showed
// about the serving key the front door actually speaks.
type frontDoorObservation int

const (
	// frontDoorNone: the evidence is not discovery-sourced; no front-door
	// property is presented.
	frontDoorNone frontDoorObservation = iota
	// frontDoorUnobserved: discovery-sourced, but the target connection was
	// not TLS, so no handshake showed the serving key.
	frontDoorUnobserved
	// frontDoorAttested: the handshake presented byte-identically the
	// certificate the evidence attests — the peer holds the attestation-bound
	// key.
	frontDoorAttested
	// frontDoorOther: the handshake presented a certificate the evidence does
	// not attest.
	frontDoorOther
)

// gatherFromDiscovery fetches the router discovery document and builds evidence
// from the embedded attestation, bound to the CDS cert key + the issuance
// challenge. The challenge is fixed at issuance time, so this is NOT a freshness
// proof (fresh=false) — but it ships the VCEK, so it verifies offline.
//
// An https target is dialed once and the document fetched over that one
// connection: the handshake leaf is the front door's serving key made
// observable, and serving certs are per replica, so the observation and the
// document must ride the same connection. The document stays unauthenticated
// public bytes (anyone who once fetched a genuine one can replay it with the
// certificate re-minted — see authorizeLeafBody); what the handshake adds is
// which key the door THIS connection reached actually speaks.
func gatherFromDiscovery(ctx context.Context, base, path, serverName string, timeout time.Duration, trust leafTrust) (*evidence, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse url %q: %w", base, err)
	}
	client := insecureClient(serverName, timeout)
	var conn *tls.Conn
	if u.Scheme == "https" {
		conn, err = dialFrontDoor(ctx, u.Host, serverName, timeout)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		client = singleConnClient(conn, timeout)
	}
	data, src, err := fetchDiscoveryDoc(ctx, client, u, path)
	if err != nil {
		return nil, err
	}
	var observed *x509.Certificate
	if conn != nil {
		if peers := conn.ConnectionState().PeerCertificates; len(peers) > 0 {
			observed = peers[0]
		}
	}
	return evidenceFromDiscovery(data, src, trust, observed)
}

// dialFrontDoor opens the TLS connection the discovery document is fetched
// over. PKI is intentionally not verified — the trust anchor is the
// attestation in the document, checked downstream, and the handshake leaf is
// compared against the document's attested certificate after the fetch.
func dialFrontDoor(ctx context.Context, addr, serverName string, timeout time.Duration) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: serverName}, //nolint:gosec
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &connectError{err: fmt.Errorf("dial %s: %w", addr, err)}
	}
	// tls.Dialer.DialContext always returns a *tls.Conn.
	return conn.(*tls.Conn), nil
}

// singleConnClient serves requests over the one dialed connection and never
// redials: the handshake leaf the gather compares is this connection's, so a
// second dial could reach a different router replica serving a different cert.
// Redirects are not followed for the same reason — a non-200, including a
// redirect, is a fetch failure (connectError).
// dialFrontDoor + this guard are a sibling of internal/routerdiscovery's
// dialFrontDoor + newSingleConnClient — port fixes both ways.
func singleConnClient(conn *tls.Conn, timeout time.Duration) *http.Client {
	var dialed atomic.Bool
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				if dialed.Swap(true) {
					return nil, errors.New("the attested connection was lost and redialing could reach a different router replica; re-run the command")
				}
				return conn, nil
			},
		},
	}
}

// fetchDiscoveryDoc GETs the discovery document over client and returns the
// raw bytes plus a human-readable source string.
func fetchDiscoveryDoc(ctx context.Context, client *http.Client, base *url.URL, path string) ([]byte, string, error) {
	if path == "" {
		path = defaultDiscoveryPath
	}
	u := *base
	u.Path = path
	u.RawQuery = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", &connectError{err: fmt.Errorf("GET %s: %w", u.String(), err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, "", &connectError{err: fmt.Errorf("GET %s returned %d: %s", u.String(), resp.StatusCode, strings.TrimSpace(string(body)))}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", &connectError{err: fmt.Errorf("read discovery: %w", err)}
	}
	return data, fmt.Sprintf("discovery document %s", u.String()), nil
}

// evidenceFromDiscovery parses a discovery document into verifiable evidence.
// REPORTDATA = SHA-384(cert pubkey ‖ challenge), matching get-cert's issuance
// binding (reportDataForCSR → armtls.ReportDataForKey). The parsed certificate
// gets the same body authentication as every other cert-sourced path, and is
// retained as the evidence leaf so the --mesh-ca / --sandbox-id / --workload
// pins work against discovery targets too. A CDS-issued (CA-vouched) cert in
// the document is authenticated by a --mesh-ca chain check, or by the live
// handshake below; with neither the document is rejected rather than verified
// against a body nothing signed for (authorizeLeafBody).
//
// observed is the leaf the target connection's TLS handshake presented (nil
// when no handshake was made). Byte-identical to the attested cert, the
// completed handshake proves the peer holds the attestation-bound key — the
// same possession backstop as the ARmTLS path — and the verdict may stand on
// the front door speaking the attested key (applyFrontDoorPolicy).
//
// An unknown public_tls.mode fails closed here — a securityError, so auto
// mode cannot fall through to the serving cert past a document it cannot
// classify. A known mode is classification only: the verdict keys on the
// live handshake observation (applyFrontDoorPolicy).
func evidenceFromDiscovery(data []byte, source string, trust leafTrust, observed *x509.Certificate) (*evidence, error) {
	var d types.DiscoveryDocument
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}
	switch d.PublicTLS.Mode {
	case "", "cds", "webpki", "acme":
	default:
		return nil, &securityError{err: fmt.Errorf(
			"unknown public_tls.mode %q in discovery document (this build knows cds, webpki, and acme) — failing closed on a document it cannot classify", d.PublicTLS.Mode)}
	}
	cert, rd, err := armtls.AttestedCertFromDiscovery(&d)
	if err != nil {
		return nil, err
	}
	frontDoor := frontDoorUnobserved
	var observedSHA256 string
	if observed != nil {
		sum := sha256.Sum256(observed.Raw)
		observedSHA256 = hex.EncodeToString(sum[:])
		if bytes.Equal(observed.Raw, cert.Raw) {
			frontDoor = frontDoorAttested
			// The possession backstop admits the body only where no pinned CA
			// authenticates it instead: with --mesh-ca the chain check is the
			// stronger authentication, and authorizeLeafBody reports it.
			trust.keyProven = trust.meshCA == nil
		} else {
			frontDoor = frontDoorOther
		}
	}
	body, err := authenticateLeafBody(cert)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(cert.Raw)
	chainVerified, err := authorizeLeafBody(cert, body, trust)
	if err != nil {
		// A mismatching door is the actionable signal: lead the failure
		// with the observed-vs-attested digests, then the body check.
		if frontDoor == frontDoorOther {
			err = fmt.Errorf("the front door's live TLS handshake presented serving certificate sha256 %s, not the sha256 %s this evidence attests: %w",
				observedSHA256, hex.EncodeToString(sum[:]), err)
		}
		return nil, err
	}
	sandboxID, sandboxErr := armtls.SandboxIDFromCert(cert)
	workload, workloadErr := armtls.MatchedWorkloadFromCert(cert)
	return &evidence{
		platform:            platformOrDefault(d.Attestation.Platform),
		rawEvidence:         d.Attestation.Evidence,
		erd:                 keyAnchor(rd),
		fresh:               false,
		source:              source,
		certSHA256:          hex.EncodeToString(sum[:]),
		bindingNote:         "REPORTDATA binds the CDS cert key + issuance challenge from the discovery doc (ships the VCEK; no per-request nonce — replayable within the authenticated certificate validity window)",
		leaf:                cert,
		leafBody:            body,
		leafChainVerified:   chainVerified,
		leafKeyProven:       trust.keyProven,
		frontDoor:           frontDoor,
		frontDoorCertSHA256: observedSHA256,
		sandboxID:           sandboxID,
		sandboxErr:          sandboxErr,
		workload:            workload,
		workloadErr:         workloadErr,
	}, nil
}
