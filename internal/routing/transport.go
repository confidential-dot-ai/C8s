package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
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
	// Entries is the allowlist a workload backend's entry is checked against
	// (B8). Without it every workload dial fails.
	Entries *Entries
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
}

// pooled is a cached transport and the workload it reaches, empty for an
// address backend.
type pooled struct {
	*http.Transport
	workload string
}

// errBackendEntryChanged fails a workload handshake whose leaf was stamped
// under an allowlist entry the current allowlist removed or redefined (B8).
var errBackendEntryChanged = errors.New("routing: backend allowlist entry changed")

// NewTransports returns an empty cache.
func NewTransports(cfg TransportConfig) *Transports {
	return &Transports{cfg: cfg, cache: map[string]pooled{}}
}

// For returns the transport for b, building it on first use.
func (t *Transports) For(b routes.Backend) *http.Transport {
	key := backendKey(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	if p, ok := t.cache[key]; ok {
		return p.Transport
	}
	tr := t.build(b)
	t.cache[key] = pooled{Transport: tr, workload: b.Workload}
	return tr
}

// RetireWorkloads drops the transports of the workloads named and closes
// their idle connections, so the next request dials and checks the backend's
// entry again (B10). A request in flight completes on its connection.
func (t *Transports) RetireWorkloads(names []string) {
	if len(names) == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for key, p := range t.cache {
		if p.workload != "" && slices.Contains(names, p.workload) {
			p.CloseIdleConnections()
			delete(t.cache, key)
		}
	}
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
	for key, p := range t.cache {
		if !keep[key] {
			p.CloseIdleConnections()
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
		transport.DialTLSContext = t.dialWorkload(b.Workload, dialer)
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
// published mesh CA, the route's workload name is required of it (B1), and
// its stamped entry must be unchanged in the current allowlist (B8), all
// before any request is written. The pod's ruleset leaves this identity's
// connections into the cluster uncaptured, so this handshake is the one that
// crosses the pod boundary.
func (t *Transports) dialWorkload(workload string, dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Per connection: one resolution of what get-cert publishes, and a
		// backend is dialled far less often than it is used.
		var stamped string
		cfg, err := t.meshClientConfig(workload, func(peer armtls.Peer) { stamped = string(peer.AllowlistDigest) })
		if err != nil {
			return nil, err
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
		if err := t.cfg.Entries.Check(handshake, stamped, workload); err != nil {
			mesh.Close()
			return nil, fmt.Errorf("%w: %w", errBackendEntryChanged, err)
		}
		return mesh, nil
	}
}

// meshClientConfig is the armTLS mesh client configuration for one workload
// backend, built on one published generation: the leaf it presents and the CA
// it trusts are the ones published together. accepted sees the peer B1
// accepted.
func (t *Transports) meshClientConfig(workload string, accepted func(armtls.Peer)) (*tls.Config, error) {
	cred, err := t.cfg.MeshIdentity()
	if err != nil {
		return nil, fmt.Errorf("routing: mesh credential: %w", err)
	}
	// CDS publishes the one mesh CA its members are verified against.
	if len(cred.MeshCAs) != 1 {
		return nil, fmt.Errorf("routing: mesh CA bundle holds %d certificates, want one", len(cred.MeshCAs))
	}
	cfg, _, err := armtls.NewMeshClientTLSConfig(&armtls.MeshConfig{
		CertProvider: routerLeaf{cert: cred.Certificate},
		MeshCA:       cred.MeshCAs[0],
		AcceptPeer:   acceptWorkload(workload, accepted),
	})
	if err != nil {
		return nil, fmt.Errorf("routing: mesh client for workload %q: %w", workload, err)
	}
	return cfg, nil
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
// authenticated is the workload the signed route names, and hands an accepted
// peer to accepted. A leaf CDS stamped no workload on names none, and is
// refused with the rest.
func acceptWorkload(workload string, accepted func(armtls.Peer)) func(armtls.Peer) error {
	return func(peer armtls.Peer) error {
		if peer.WorkloadName == "" {
			return fmt.Errorf("routing: backend leaf names no workload, and this route names %q", workload)
		}
		if peer.WorkloadName != workload {
			return fmt.Errorf("routing: backend leaf names workload %q, and this route names %q", peer.WorkloadName, workload)
		}
		accepted(peer)
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

// dropMeshPools retires every transport when the mesh CA bundle changed since
// the last call or cannot be read. Pooled connections skip the handshake, and
// a connection in flight returns to its pool after CloseIdleConnections, so
// new requests get fresh transports while the old ones drain.
func (t *Transports) dropMeshPools() error {
	cas, err := t.meshCAs()
	var digest [sha256.Size]byte
	if err == nil {
		h := sha256.New()
		for _, ca := range cas {
			h.Write(ca.Raw)
		}
		h.Sum(digest[:0])
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err == nil && digest == t.caDigest {
		return nil
	}
	t.caDigest = digest // zero after a failed read: the next good read differs
	for _, p := range t.cache {
		p.CloseIdleConnections()
	}
	t.cache = map[string]pooled{}
	return err
}
