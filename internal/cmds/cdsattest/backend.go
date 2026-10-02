package cdsattest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// hopByHopHeaders are not forwarded between the over-encrypted hop and the
// backend (RFC 7230 §6.1 plus the session header).
var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
	"content-length":      true,
	"x-c8s-session":       true,
}

const maxUpstreamResponseBytes = 32 << 20

// EchoBackend reflects the request — used for the demo and tests.
type EchoBackend struct{}

var (
	_ Backend = EchoBackend{}
	_ Backend = (*HTTPBackend)(nil)
)

// Forward implements Backend.
func (EchoBackend) Forward(_ context.Context, req types.TunnelRequest) (types.TunnelResponse, error) {
	msg := fmt.Sprintf("LB enclave received %d bytes over the over-encrypted channel for %s %s: %q",
		len(req.Body), req.Method, req.Path, string(req.Body))
	return types.TunnelResponse{
		Status:  http.StatusOK,
		Headers: []types.HeaderField{{Name: "Content-Type", Value: "text/plain; charset=utf-8"}},
		Body:    []byte(msg),
	}, nil
}

// HTTPBackend forwards the decrypted request to a real upstream. The connection
// is plaintext HTTP by default — the cluster's transparent raTLS mesh wraps the
// sidecar→backend hop, exactly like every other c8s workload. When the upstream
// is https it does mTLS with the LB's CDS-issued client cert and verifies the
// peer against the mesh CA (mirroring the router nginx proxy_ssl_* config).
type HTTPBackend struct {
	base   string // upstream base URL, e.g. http://vllm-router-service.vllm.svc.cluster.local
	client *http.Client
}

// defaultUpstreamTimeout bounds a single forwarded request to the upstream
// backend (connect + headers + body) when HTTPBackendOptions.Timeout is unset.
// It guards the sidecar against slow or hung upstreams holding decrypted-traffic
// connections open indefinitely.
const defaultUpstreamTimeout = 30 * time.Second

// HTTPBackendOptions configures the raTLS/mTLS material for an https upstream.
type HTTPBackendOptions struct {
	// ClientCertFile/ClientKeyFile present the CDS-issued cert to the backend.
	ClientCertFile string
	ClientKeyFile  string
	// TrustedCAFile verifies the backend (the mesh CA bundle).
	TrustedCAFile string
	// ServerName overrides SNI / verification name.
	ServerName string
	// Timeout bounds a single forwarded upstream request. Values <= 0 fall back
	// to defaultUpstreamTimeout.
	Timeout time.Duration
	// VerifyPeer, when set, runs on the chain-verified https upstream leaf of
	// every new connection and refuses the connection on error.
	VerifyPeer func(*x509.Certificate) error
}

// NewHTTPBackend builds an HTTP(S) forwarding backend for base (a full URL).
func NewHTTPBackend(base string, opts HTTPBackendOptions) (*HTTPBackend, error) {
	base = strings.TrimRight(base, "/")
	transport := &http.Transport{
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}
	if strings.HasPrefix(base, "https://") {
		tlsCfg := &tls.Config{ServerName: opts.ServerName, MinVersion: tls.VersionTLS12}
		if opts.TrustedCAFile != "" {
			caPEM, err := os.ReadFile(opts.TrustedCAFile)
			if err != nil {
				return nil, fmt.Errorf("read upstream CA: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("upstream CA file %q has no certificates", opts.TrustedCAFile)
			}
			tlsCfg.RootCAs = pool
		}
		if opts.ClientCertFile != "" && opts.ClientKeyFile != "" {
			loader, err := newUpstreamCertLoader(opts.ClientCertFile, opts.ClientKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load upstream client cert: %w", err)
			}
			tlsCfg.GetClientCertificate = loader.getClientCertificate
		}
		if opts.VerifyPeer != nil {
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return fmt.Errorf("upstream presented no certificate")
				}
				return opts.VerifyPeer(cs.PeerCertificates[0])
			}
		}
		transport.TLSClientConfig = tlsCfg
	} else if !strings.HasPrefix(base, "http://") {
		return nil, fmt.Errorf("upstream must be an http:// or https:// URL, got %q", base)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultUpstreamTimeout
	}
	return &HTTPBackend{base: base, client: &http.Client{Transport: transport, Timeout: timeout}}, nil
}

// upstreamCertRecheckInterval is how often the upstream client credential is
// re-read from disk while it is still valid. get-cert rotates at 50% of TTL,
// so this only needs to be small next to the rotation window.
const upstreamCertRecheckInterval = 30 * time.Second

// upstreamCertLoader hands the upstream handshake a currently-valid copy of
// the get-cert-managed client credential. Loading the pair once into
// tls.Config.Certificates, as this backend used to, pins one leaf for the
// lifetime of a long-lived sidecar: the upstream verifies it against its
// ClientCAs, so the first expiry breaks the backend hop and nothing short of
// a restart recovers. The mesh identity (identity.go) is already re-read per
// request; this is the same rule for the one credential that predates
// pkg/ratls' certState.
type upstreamCertLoader struct {
	certFile string
	keyFile  string

	mu        sync.Mutex
	cached    *tls.Certificate
	recheckAt time.Time
}

// newUpstreamCertLoader reads the pair once so an unreadable path or a
// mismatched key still fails at startup, as it did when the pair was loaded
// straight into tls.Config. The validity window is deliberately NOT enforced
// here: a sidecar restarting while CDS is down would otherwise crash-loop
// instead of coming up and serving whatever needs no upstream hop.
func newUpstreamCertLoader(certFile, keyFile string) (*upstreamCertLoader, error) {
	l := &upstreamCertLoader{certFile: certFile, keyFile: keyFile}
	cert, err := l.read()
	if err != nil {
		return nil, err
	}
	l.cached = cert
	l.recheckAt = time.Now().Add(upstreamCertRecheckInterval)
	return l, nil
}

func (l *upstreamCertLoader) read() (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(l.certFile, l.keyFile)
	if err != nil {
		return nil, err
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("upstream client certificate %q has no certificate", l.certFile)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse upstream client leaf: %w", err)
	}
	pair.Leaf = leaf
	return &pair, nil
}

// getClientCertificate re-reads the files when the cached credential is stale
// or outside its window, and applies the repo-wide validity check before
// handing anything to a handshake.
func (l *upstreamCertLoader) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	canReuseCachedCertificate := l.cached != nil && now.Before(l.recheckAt) && certutil.CheckValidity(l.cached.Leaf, now) == nil
	if canReuseCachedCertificate {
		return l.cached, nil
	}

	cert, err := l.read()
	if err == nil {
		err = certutil.CheckValidity(cert.Leaf, now)
	}
	if err != nil {
		// get-cert writes the certificate and the key as separate files, so a
		// rotation can leave the two momentarily out of step. Keep serving
		// the cached credential while it is still inside its own window
		// rather than failing the hop on a transient mismatch.
		if l.cached != nil && certutil.CheckValidity(l.cached.Leaf, now) == nil {
			return l.cached, nil
		}
		return nil, fmt.Errorf("upstream client certificate: %w", err)
	}

	l.cached = cert
	l.recheckAt = now.Add(upstreamCertRecheckInterval)
	return cert, nil
}

// Forward implements Backend by proxying the reconstructed request upstream.
func (b *HTTPBackend) Forward(ctx context.Context, env types.TunnelRequest) (types.TunnelResponse, error) {
	body := env.Body
	method := env.Method
	if method == "" {
		method = http.MethodGet
	}
	path := env.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	req, err := http.NewRequestWithContext(ctx, method, b.base+path, bytes.NewReader(body))
	if err != nil {
		return types.TunnelResponse{}, fmt.Errorf("build upstream request: %w", err)
	}
	for _, f := range env.Headers {
		if hopByHopHeaders[strings.ToLower(f.Name)] {
			continue
		}
		req.Header.Add(f.Name, f.Value)
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return types.TunnelResponse{}, fmt.Errorf("forward to upstream: %w", err)
	}
	defer resp.Body.Close()
	limitedBody := &io.LimitedReader{R: resp.Body, N: maxUpstreamResponseBytes + 1}
	respBody, err := io.ReadAll(limitedBody)
	if err != nil {
		return types.TunnelResponse{}, fmt.Errorf("read upstream response: %w", err)
	}
	if len(respBody) > maxUpstreamResponseBytes {
		return types.TunnelResponse{}, fmt.Errorf("upstream response exceeds %d byte limit", maxUpstreamResponseBytes)
	}

	return types.TunnelResponse{
		Status:  resp.StatusCode,
		Headers: responseHeaderFields(resp.Header),
		Body:    respBody,
	}, nil
}

// responseHeaderFields flattens the upstream header map into ordered pairs:
// names sorted (the map holds no order to preserve), values of one name in
// their upstream order, hop-by-hop fields dropped.
func responseHeaderFields(h http.Header) []types.HeaderField {
	names := make([]string, 0, len(h))
	for name := range h {
		if hopByHopHeaders[strings.ToLower(name)] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var fields []types.HeaderField
	for _, name := range names {
		for _, value := range h[name] {
			fields = append(fields, types.HeaderField{Name: name, Value: value})
		}
	}
	return fields
}
