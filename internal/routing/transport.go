package routing

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
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
	// MeshCAs anchor workload backends (B1).
	MeshCAs CASource
	// ClientCertificate supplies the router's CDS-issued mesh leaf, presented
	// to every backend (B4).
	ClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

// Transports caches one HTTP transport per backend, so connections are pooled
// per backend and never shared between backends with different identities.
// It is safe for concurrent use.
type Transports struct {
	cfg TransportConfig

	mu    sync.Mutex
	cache map[string]*http.Transport
	// caDigest identifies the mesh CA bundle last seen by dropMeshPools.
	caDigest [sha256.Size]byte
}

// NewTransports returns an empty cache.
func NewTransports(cfg TransportConfig) *Transports {
	return &Transports{cfg: cfg, cache: map[string]*http.Transport{}}
}

// For returns the transport for b, building it on first use.
func (t *Transports) For(b routes.Backend) *http.Transport {
	key := backendKey(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	if tr, ok := t.cache[key]; ok {
		return tr
	}
	tr := t.build(b)
	t.cache[key] = tr
	return tr
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
	tlsCfg := &tls.Config{
		MinVersion:           tls.VersionTLS12,
		NextProtos:           []string{"http/1.1"},
		GetClientCertificate: t.cfg.ClientCertificate, // B4
		// No ClientSessionCache: a resumed session skips
		// VerifyPeerCertificate, and B1 lives there.
	}
	if b.Workload != "" {
		host, _, _ := net.SplitHostPort(b.Address)
		// SNI only. The name is never verified: address, DNS and the Service
		// behind it are not identity (B2).
		tlsCfg.ServerName = host
		tlsCfg.MinVersion = tls.VersionTLS13 // armTLS
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = t.verifyWorkload(b.Workload)
	} else {
		// B3. A fresh pool, never nil: a nil RootCAs means the system roots.
		pool := x509.NewCertPool()
		for _, c := range b.Anchors() {
			pool.AddCert(c)
		}
		tlsCfg.RootCAs = pool
		tlsCfg.ServerName = b.ServerName
		tlsCfg.VerifyConnection = t.refuseMeshAnchor
	}
	return &http.Transport{
		DialContext:         (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     tlsCfg,
		TLSHandshakeTimeout: handshakeTimeout,
		IdleConnTimeout:     idleConnTimeout,
		MaxIdleConnsPerHost: 32,
		// No ResponseHeaderTimeout: a non-streaming LLM response sends its
		// headers only when generation ends. The proxy bounds the request.
	}
}

// verifyWorkload authenticates a workload backend (B1): the chain to a
// current mesh CA with no evidence fallback (armTLS V5, V8), then the
// CA-vouched matched workload name, which must be present and equal.
func (t *Transports) verifyWorkload(workload string) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		cas, err := t.cfg.MeshCAs()
		if err != nil {
			return fmt.Errorf("routing: mesh CA bundle: %w", err)
		}
		pool := x509.NewCertPool()
		for _, c := range cas {
			pool.AddCert(c)
		}
		leaf, err := armtls.VerifyChain(rawCerts, pool, time.Now())
		if err != nil {
			return err
		}
		return armtls.CheckWorkloadPin(leaf, workload)
	}
}

// refuseMeshAnchor fails an address backend whose verified chain holds a
// current mesh CA or a certificate one signed. Accept rejects such a ca at
// apply time; this covers a mesh CA rotated in after the manifest was applied
// (B3).
func (t *Transports) refuseMeshAnchor(cs tls.ConnectionState) error {
	cas, err := t.cfg.MeshCAs()
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
	cas, err := t.cfg.MeshCAs()
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
	for _, tr := range t.cache {
		tr.CloseIdleConnections()
	}
	t.cache = map[string]*http.Transport{}
	return err
}
