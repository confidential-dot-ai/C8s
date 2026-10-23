package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
)

const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 10 * time.Second
	idleConnTimeout  = 90 * time.Second
)

// TransportConfig configures Transports.
type TransportConfig struct {
	// MeshIdentity is the router's mesh leaf, presented to every backend, and
	// the CAs anchoring workload backends. A mesh dial takes both from one
	// resolution; an address backend resolves them separately.
	MeshIdentity CredentialSource
	// Logger reports a router leaf whose stamp does not parse, once per leaf.
	// nil uses slog.Default.
	Logger *slog.Logger
}

// routerLeaf hands one generation's leaf to a mesh handshake. Renewal is
// get-cert's: a configuration built from this carries one connection.
type routerLeaf struct {
	cert *tls.Certificate
}

func (l routerLeaf) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	return l.cert, 0, nil
}

// Transports caches one HTTP transport per backend, so connections are pooled
// per backend and never shared between backends with different identities.
// It is safe for concurrent use.
type Transports struct {
	cfg TransportConfig

	mu    sync.Mutex
	cache map[string]pooled
	// caDigest identifies the mesh CA bundle last seen by dropMeshPools.
	caDigest [sha256.Size]byte
	// routerDigest is the router stamp's allowlist digest last seen by
	// dropMeshPools, empty for none (B10). tracked reports a first call.
	routerDigest string
	tracked      bool

	stamp stampCache
}

// pooled is a cached transport, whether it reaches a workload backend, and
// the router digest tracked when it was built.
type pooled struct {
	*http.Transport
	workload     bool
	routerDigest string
}

// errBackendDigestMismatch fails a workload handshake whose leaf was stamped
// under another allowlist than the router's (B8).
var errBackendDigestMismatch = errors.New("routing: backend allowlist digest differs from the router's")

// damagedRouterStamp is the tracked digest of a leaf whose stamp fails to
// parse: shorter than any real digest and never empty.
const damagedRouterStamp = "damaged"

// errRouterStampDamaged fails every workload dial while the router's own leaf
// carries a stamp that does not parse. The fault is the router's, not the
// backend's.
var errRouterStampDamaged = errors.New("routing: router stamp damaged")

// errRouterRenewed refuses a workload dial whose router leaf is stamped under
// another digest than the one its transport was built under, so a pool never
// mixes digests (B10).
var errRouterRenewed = errors.New("routing: router leaf renewed under another allowlist digest")

// stampCache holds the router stamp of the last leaf it parsed, so an
// unchanged leaf is parsed once.
type stampCache struct {
	log   *slog.Logger
	mu    sync.Mutex
	raw   []byte
	stamp *armtls.MatchedWorkload
	err   error
}

// of returns the matched-workload stamp on cert's leaf, nil when it carries
// none.
func (c *stampCache) of(cert *tls.Certificate) (*armtls.MatchedWorkload, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return nil, errors.New("routing: no router leaf")
	}
	raw := cert.Certificate[0]
	c.mu.Lock()
	if c.raw != nil && bytes.Equal(c.raw, raw) {
		stamp, err := c.stamp, c.err
		c.mu.Unlock()
		return stamp, err
	}
	leaf := cert.Leaf
	if leaf == nil {
		var err error
		if leaf, err = x509.ParseCertificate(raw); err != nil {
			c.mu.Unlock()
			return nil, fmt.Errorf("routing: parse router leaf: %w", err)
		}
	}
	c.raw = raw
	c.stamp, c.err = armtls.MatchedWorkloadFromCert(leaf)
	stamp, err := c.stamp, c.err
	c.mu.Unlock()
	if err != nil {
		// Once per leaf, outside the lock so a slow handler never stalls
		// dials: the per-request refusals log at Debug.
		c.log.Error("router stamp damaged", "error", err)
	}
	return stamp, err
}

// routerDigestOf is the allowlist digest of the router stamp on cred's leaf,
// nil for an unstamped leaf: that router has no policy digest to bind and
// checks backends by name alone (B9). A damaged stamp is an error, never
// absence.
func (t *Transports) routerDigestOf(cred MeshCredential) ([]byte, error) {
	stamp, err := t.stamp.of(cred.Certificate)
	if err != nil {
		return nil, fmt.Errorf("routing: router stamp: %w", err)
	}
	if stamp == nil {
		return nil, nil
	}
	return stamp.AllowlistDigest, nil
}

// NewTransports returns an empty cache.
func NewTransports(cfg TransportConfig) *Transports {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	t := &Transports{cfg: cfg, cache: map[string]pooled{}}
	t.stamp.log = cfg.Logger
	return t
}

// For returns the transport for b, building it on first use, and the router
// digest every workload connection it pools was accepted under.
func (t *Transports) For(b routes.Backend) (*http.Transport, string) {
	key := backendKey(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.cache[key]; ok {
		return p.Transport, p.routerDigest
	}
	tr := t.build(b)
	t.cache[key] = pooled{Transport: tr, workload: b.Workload != "", routerDigest: t.routerDigest}
	return tr, t.routerDigest
}

// Retain drops the transports of backends m does not name and closes their
// idle connections. A request still routed by the previous manifest rebuilds
// its transport on demand; the next successful poll drops it again.
func (t *Transports) Retain(m *routes.Manifest) {
	keep := map[string]bool{}
	for _, h := range m.Hosts {
		for _, r := range h.Routes {
			keep[backendKey(r.Backend)] = true
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, tr := range t.cache {
		if !keep[key] {
			tr.CloseIdleConnections()
			delete(t.cache, key)
		}
	}
}

func backendKey(b routes.Backend) string {
	return strings.Join([]string{b.Address, b.Workload, b.ServerName, b.CA}, "\x00")
}

func (t *Transports) build(b routes.Backend) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		DialContext:         dialer.DialContext,
		TLSHandshakeTimeout: handshakeTimeout,
		IdleConnTimeout:     idleConnTimeout,
		MaxIdleConnsPerHost: 32,
		// No ResponseHeaderTimeout: a non-streaming LLM response sends its
		// headers only when generation ends. The proxy bounds the request.
	}
	if b.Workload != "" {
		transport.DialTLSContext = t.dialWorkload(b.Workload, t.routerDigest, t.tracked, dialer)
		return transport
	}
	// A fresh pool, never nil: a nil RootCAs means the system roots.
	pool := x509.NewCertPool()
	for _, c := range b.Anchors() {
		pool.AddCert(c)
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion:           tls.VersionTLS12,
		NextProtos:           []string{"http/1.1"},
		GetClientCertificate: t.clientCertificate,
		RootCAs:              pool,
		ServerName:           b.ServerName,
		VerifyConnection:     t.refuseMeshAnchor,
		// No ClientSessionCache: a resumed session skips verification.
	}
	return transport
}

// dialWorkload reaches a workload backend as a mesh client of the member
// behind it: the mesh profile's chain path authenticates the peer against the
// published mesh CA, and the route's workload name is required of it before
// any request is written. The pod's ruleset leaves this identity's
// connections into the cluster uncaptured, so this handshake is the one that
// crosses the pod boundary. Once a digest is tracked, a leaf renewed under
// another one retires the pools instead of dialling.
func (t *Transports) dialWorkload(workload, routerDigest string, tracked bool, dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Per connection: one resolution of what get-cert publishes, and a
		// backend is dialled far less often than it is used.
		cfg, digest, err := t.meshClientConfig(workload)
		if err != nil {
			return nil, err
		}
		if tracked && string(digest) != routerDigest {
			if err := t.syncRouterDigest(); err != nil {
				return nil, err
			}
			return nil, errRouterRenewed
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		handshake, cancel := context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()
		mesh := tls.Client(conn, cfg)
		if err := mesh.HandshakeContext(handshake); err != nil {
			conn.Close()
			return nil, err
		}
		return mesh, nil
	}
}

// meshClientConfig is the armTLS mesh client configuration for one workload
// backend, built on one published generation: the leaf it presents, the CA it
// trusts and the allowlist digest it requires are the ones published together.
func (t *Transports) meshClientConfig(workload string) (*tls.Config, []byte, error) {
	cred, err := t.cfg.MeshIdentity()
	if err != nil {
		return nil, nil, fmt.Errorf("routing: mesh credential: %w", err)
	}
	// CDS publishes the one mesh CA its members are verified against.
	if len(cred.MeshCAs) != 1 {
		return nil, nil, fmt.Errorf("routing: mesh CA bundle holds %d certificates, want one", len(cred.MeshCAs))
	}
	digest, err := t.routerDigestOf(cred)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errRouterStampDamaged, err)
	}
	cfg, _, err := armtls.NewMeshClientTLSConfig(&armtls.MeshConfig{
		CertProvider: routerLeaf{cert: cred.Certificate},
		MeshCA:       cred.MeshCAs[0],
		AcceptPeer:   acceptWorkload(workload, digest),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("routing: mesh client for workload %q: %w", workload, err)
	}
	return cfg, digest, nil
}

// clientCertificate implements tls.Config.GetClientCertificate from the
// published generation.
func (t *Transports) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cred, err := t.cfg.MeshIdentity()
	if err != nil {
		return nil, err
	}
	return cred.Certificate, nil
}

// meshCAs are the CAs of the published generation.
func (t *Transports) meshCAs() ([]*x509.Certificate, error) {
	cred, err := t.cfg.MeshIdentity()
	if err != nil {
		return nil, err
	}
	return cred.MeshCAs, nil
}

// acceptWorkload fails the handshake unless the peer the chain path
// authenticated is the workload the signed route names (B1), stamped under
// the router's own allowlist digest (B8). A leaf CDS stamped no workload on
// names none, and is refused with the rest.
func acceptWorkload(workload string, routerDigest []byte) func(armtls.Peer) error {
	router := "with no router allowlist digest"
	if routerDigest != nil {
		router = fmt.Sprintf("under router allowlist digest %x", routerDigest)
	}
	return func(peer armtls.Peer) error {
		if peer.WorkloadName == "" {
			return fmt.Errorf("routing: backend leaf carries no matched-workload stamp and no allowlist digest, and this route names %q %s", workload, router)
		}
		if peer.WorkloadName != workload {
			return fmt.Errorf("routing: backend leaf names workload %q under allowlist digest %x, and this route names %q %s", peer.WorkloadName, peer.AllowlistDigest, workload, router)
		}
		if routerDigest == nil {
			return nil // B9: an unstamped router binds no policy digest
		}
		if !bytes.Equal(peer.AllowlistDigest, routerDigest) {
			return fmt.Errorf("%w: workload %q is stamped under %x, and the router's is %x", errBackendDigestMismatch, workload, peer.AllowlistDigest, routerDigest)
		}
		return nil
	}
}

// refuseMeshAnchor fails an address backend whose verified chain holds a
// current mesh CA or a certificate one signed. Accept rejects such a ca at
// apply time; this covers a mesh CA rotated in after the manifest was applied
// (B3).
func (t *Transports) refuseMeshAnchor(cs tls.ConnectionState) error {
	cas, err := t.meshCAs()
	if err != nil {
		return fmt.Errorf("routing: mesh CA bundle: %w", err)
	}
	for _, chain := range cs.VerifiedChains {
		for _, c := range chain {
			for _, ca := range cas {
				if c.Equal(ca) || bytes.Equal(c.RawSubjectPublicKeyInfo, ca.RawSubjectPublicKeyInfo) || c.CheckSignatureFrom(ca) == nil {
					return errors.New("routing: address backend chains to a mesh CA")
				}
			}
		}
	}
	return nil
}

// RouterDigest is the router stamp's allowlist digest as of the last poll,
// empty for none (B10). A bound session is checked against it (E6). A nil
// Transports, which dials no workload, has none.
func (t *Transports) RouterDigest() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.routerDigest
}

// dropMeshPools retires every transport when the mesh CA bundle changed since
// the last call or cannot be read, and every workload transport when the
// router stamp's allowlist digest changed (B10). Pooled connections skip the
// handshake, and a connection in flight returns to its pool after
// CloseIdleConnections, so new requests get fresh transports while the old
// ones drain.
func (t *Transports) dropMeshPools() error {
	cred, err := t.cfg.MeshIdentity()
	return t.retire(cred, err)
}

// syncRouterDigest is dropMeshPools for paths a client can drive, handshakes
// and dials: an unreadable credential retires nothing, so clients cannot
// churn the pools while the read fails.
func (t *Transports) syncRouterDigest() error {
	cred, err := t.cfg.MeshIdentity()
	if err != nil {
		return fmt.Errorf("routing: mesh credential: %w", err)
	}
	return t.retire(cred, nil)
}

// retire is dropMeshPools on cred, read with err. A failed read tracks no
// router digest and keeps the one already tracked: the credential did not
// change, so bound sessions must not be refused for it, and dials fail on the
// read anyway.
func (t *Transports) retire(cred MeshCredential, err error) error {
	if err != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.caDigest = [sha256.Size]byte{} // the next good read differs
		t.retireLocked(false)
		return err
	}
	var caDigest [sha256.Size]byte
	h := sha256.New()
	for _, ca := range cred.MeshCAs {
		h.Write(ca.Raw)
	}
	h.Sum(caDigest[:0])
	// An unstamped router tracks the empty digest (B9).
	routerDigest, _ := t.routerDigestOf(cred)
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked = true
	if caDigest != t.caDigest {
		t.caDigest = caDigest
		t.routerDigest = string(routerDigest)
		t.retireLocked(false)
		return nil
	}
	if string(routerDigest) != t.routerDigest {
		t.routerDigest = string(routerDigest)
		t.retireLocked(true)
	}
	return nil
}

// retireLocked drops the transports, only the workload ones if workloadOnly,
// and closes their idle connections. The caller holds t.mu.
func (t *Transports) retireLocked(workloadOnly bool) {
	for key, p := range t.cache {
		if workloadOnly && !p.workload {
			continue
		}
		p.CloseIdleConnections()
		delete(t.cache, key)
	}
}
