// Package routerdiscovery consumes the router front-door discovery contract
// (types.DiscoveryDocument, served at /v1/discovery, written by get-cert).
// The front door's serving cert carries no armTLS extension; its trust path is
// the discovery document instead: attestation evidence captured at issuance,
// with REPORTDATA binding the serving-cert key + issuance challenge
// (armtls.ReportDataForKey).
//
// Serving certs are per replica (each router pod provisions its own leaf into
// a pod-local emptyDir) and each renewal is a new key, so evidence fetched on
// one connection says nothing about the leaf a *different* connection would be
// served — a scaled-out or rolling Service can answer alternating handshakes
// with alternating certs, and a renewal changes the cert the next handshake
// presents. This package therefore attests a connection: it fetches and
// verifies the document over that connection and requires the attested cert
// to be the leaf that same handshake presented. When the connection is lost
// (the router's keepalive limits, idle eviction) the client redials the same
// host and uses the new connection if its handshake presents the attested
// leaf again — a full TLS 1.3 handshake proves possession of the leaf's key,
// so the evidence covers the new connection exactly as it covered the first.
// A redial that presents another leaf is refused, and the client attests a new
// connection the same way, sending the request there only if its leaf is
// issued by the same CDS (mesh CA key) as the first one attested.
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
	"sync"
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

// NewVerifiedHTTPClient returns an http.Client for a router front door. It
// attests the front door (see frontDoor.attest) and sends every request over
// a connection whose handshake presents an attested serving certificate; when
// the router presents another one, it attests the front door again (see
// reattestingTransport).
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

	door := &frontDoor{url: u, measurements: measurements, verify: verify}
	session, leaf, err := door.attest(ctx)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &reattestingTransport{door: door, firstIssuerKeyID: leaf.AuthorityKeyId, session: session},
	}, nil
}

// frontDoor is a router front door and the operator's pins for its evidence.
type frontDoor struct {
	url          *url.URL
	measurements [][]byte
	verify       localverify.VerifyFunc
}

// attest dials the front door once, attests that connection (see
// verifyConnection), and returns a transport whose connections all present
// the attested leaf, and the leaf.
func (f *frontDoor) attest(ctx context.Context) (*http.Transport, *x509.Certificate, error) {
	conn, err := dialFrontDoor(ctx, f.url.Host)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: dial %s: %v", ErrNoDiscovery, f.url.Host, err)
	}
	dialer := &attestedDialer{host: f.url.Host, conn: conn}
	transport := newAttestedTransport(dialer)
	cert, err := f.verifyConnection(ctx, conn, transport)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	dialer.attest(cert.Raw)
	return transport, cert, nil
}

// verifyConnection fetches the discovery document over conn (the first
// connection transport hands out), verifies the embedded attestation evidence
// (launch measurement checked against the pins — empty accepts any, UNSAFE),
// and returns the attested serving certificate if it is the leaf conn's
// handshake presented.
func (f *frontDoor) verifyConnection(ctx context.Context, conn *tls.Conn, transport *http.Transport) (*x509.Certificate, error) {
	data, err := fetchDocument(ctx, &http.Client{Transport: transport}, f.url)
	if err != nil {
		return nil, err
	}
	cert, err := verifyDocument(ctx, data, f.verify, f.measurements)
	if err != nil {
		return nil, fmt.Errorf("routerdiscovery: discovery document verification failed: %w", err)
	}

	// The evidence binds cert's key; require cert to be the leaf THIS
	// connection presented, or the attestation says nothing about the peer we
	// are talking to.
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		return nil, fmt.Errorf("routerdiscovery: connection presented no peer certificate")
	}
	if !bytes.Equal(peers[0].Raw, cert.Raw) {
		docSum := sha256.Sum256(cert.Raw)
		connSum := sha256.Sum256(peers[0].Raw)
		return nil, fmt.Errorf("routerdiscovery: discovery document attests serving cert sha256 %s but the connection presented %s — the router may be renewing its certificate, or a different router replica answered; re-run the command",
			hex.EncodeToString(docSum[:]), hex.EncodeToString(connSum[:]))
	}
	return cert, nil
}

// dialFrontDoor opens a TLS connection to the front door. PKI is
// intentionally not verified — the trust anchor is the attestation in the
// discovery document, which frontDoor.attest binds to the connection's leaf
// after the fetch.
func dialFrontDoor(ctx context.Context, host string) (*tls.Conn, error) {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, "443")
	}
	d := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{
			// No ClientSessionCache: a resumed TLS 1.3 handshake carries no
			// CertificateVerify, so every redial must be a full handshake.
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
	// the caller, frontDoor.verifyConnection: the attested leaf must be
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
		RuntimeExtensions:  d.Attestation.RuntimeExtensions,
	}); err != nil {
		return nil, err
	}
	return cert, nil
}

// attestedDialer is the transport's dialer: it hands out the connection the
// discovery document was fetched over, then redials host on demand and admits
// a new connection only when its handshake presents the attested leaf. Until
// frontDoor.attest has attested a leaf, a lost connection fails closed.
type attestedDialer struct {
	host string

	mu   sync.Mutex
	conn *tls.Conn // the connection to hand out next; nil once handed out
	leaf []byte    // DER of the attested serving cert; nil until attested
}

// attest records the leaf every later connection must present.
func (d *attestedDialer) attest(leaf []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.leaf = leaf
}

func (d *attestedDialer) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.conn != nil {
		conn := d.conn
		d.conn = nil
		return conn, nil
	}
	if d.leaf == nil {
		return nil, errors.New("routerdiscovery: the connection was lost before the discovery document was verified; re-run the command")
	}
	conn, err := dialFrontDoor(ctx, d.host)
	if err != nil {
		return nil, fmt.Errorf("routerdiscovery: redial %s: %w", d.host, err)
	}
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 || !bytes.Equal(peers[0].Raw, d.leaf) {
		conn.Close()
		presented := "no certificate"
		if len(peers) > 0 {
			sum := sha256.Sum256(peers[0].Raw)
			presented = "serving cert sha256 " + hex.EncodeToString(sum[:])
		}
		attested := sha256.Sum256(d.leaf)
		return nil, &unattestedLeafError{presented: presented, attested: hex.EncodeToString(attested[:])}
	}
	return conn, nil
}

// unattestedLeafError is a redial the dialer refused because its handshake
// presented a leaf other than the attested one. Nothing was sent over it.
type unattestedLeafError struct {
	presented string // "serving cert sha256 <hex>", or "no certificate"
	attested  string // sha256 hex of the attested serving cert
}

func (e *unattestedLeafError) Error() string {
	return fmt.Sprintf("routerdiscovery: the attested connection was lost and the redial presented %s, not the attested %s", e.presented, e.attested)
}

// newAttestedTransport returns a transport that dials through d
// (MaxConnsPerHost=1 serializes requests over one connection). Timeout knobs
// mirror armtls.NewVerifyingHTTPClient. dialFrontDoor + attestedDialer are a
// sibling of the verify CLI's dialFrontDoor + singleConnClient
// (internal/cmds/verify/discovery.go) — port fixes both ways.
func newAttestedTransport(d *attestedDialer) *http.Transport {
	return &http.Transport{
		DialTLSContext:        d.dial,
		ResponseHeaderTimeout: 10 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          1,
		MaxConnsPerHost:       1,
	}
}

// requestTimeout bounds one request, including any re-attestation it needs.
const requestTimeout = 30 * time.Second

// reattestingTransport sends each request over the current session: a
// transport whose connections all present one attested leaf. When the session
// refuses a redial because the router presented another leaf — it renewed its
// certificate, or a different replica answered — it attests the front door
// again and resends the request over the new session.
type reattestingTransport struct {
	door             *frontDoor
	firstIssuerKeyID []byte // AuthorityKeyId the first attested leaf names

	mu      sync.Mutex
	session *http.Transport
}

func (t *reattestingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.currentSession().RoundTrip(req)
	var refused *unattestedLeafError
	if !errors.As(err, &refused) {
		return resp, err
	}
	return t.resendOnceOnNewSession(req, refused)
}

// CloseIdleConnections is what http.Client.CloseIdleConnections calls.
func (t *reattestingTransport) CloseIdleConnections() {
	t.currentSession().CloseIdleConnections()
}

func (t *reattestingTransport) currentSession() *http.Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.session
}

// resendOnceOnNewSession attests the front door again and sends req over the
// new session. net/http dials for a request it has not written yet, or to
// retry a replayable one (GET, HEAD), so the resend never writes a PUT or
// DELETE twice.
func (t *reattestingTransport) resendOnceOnNewSession(req *http.Request, refused *unattestedLeafError) (*http.Response, error) {
	resend, err := rewound(req)
	if err != nil {
		return nil, fmt.Errorf("%w; %w", refused, err)
	}
	// req's context carries the client's Timeout, so it bounds the
	// re-attestation and the resend together.
	session, err := t.replaceSession(req.Context())
	if err != nil {
		return nil, fmt.Errorf("%w; attesting it failed: %w", refused, err)
	}
	return session.RoundTrip(resend)
}

// replaceSession attests the front door again and makes the result the
// current session if its leaf names the first attested leaf's issuer key.
func (t *reattestingTransport) replaceSession(ctx context.Context) (*http.Transport, error) {
	session, leaf, err := t.door.attest(ctx)
	if errors.Is(err, ErrNoDiscovery) {
		return nil, fmt.Errorf("routerdiscovery: the front door stopped serving its discovery document mid-session: %v", err)
	}
	if err != nil {
		return nil, err
	}
	if !t.namesFirstIssuerKey(leaf) {
		session.CloseIdleConnections()
		sum := sha256.Sum256(leaf.Raw)
		return nil, fmt.Errorf("routerdiscovery: serving cert sha256 %s names another mesh CA key than the first one this command attested — another c8s deployment answered, or its CDS changed CA key; re-run the command",
			hex.EncodeToString(sum[:]))
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.session = session
	return session, nil
}

// namesFirstIssuerKey reports whether leaf names the same issuer key as the
// first attested leaf. Pins name a build, not a deployment; an attested
// router presents the leaf its own CDS issued, so this keeps one command on
// one CDS. A first leaf naming no issuer key matches nothing.
func (t *reattestingTransport) namesFirstIssuerKey(leaf *x509.Certificate) bool {
	if len(t.firstIssuerKeyID) == 0 {
		return false
	}
	return bytes.Equal(leaf.AuthorityKeyId, t.firstIssuerKeyID)
}

// rewound returns a copy of req ready to send again: the transport closed
// req's body when the dial failed, so a body is recreated from GetBody.
func rewound(req *http.Request) (*http.Request, error) {
	resend := req.Clone(req.Context())
	if req.Body == nil {
		return resend, nil
	}
	if req.GetBody == nil {
		return nil, errors.New("the request body cannot be sent again; re-run the command")
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	resend.Body = body
	return resend, nil
}
