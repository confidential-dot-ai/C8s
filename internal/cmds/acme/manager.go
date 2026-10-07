package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	challengePrefix = "/.well-known/acme-challenge/"
	issueTimeout    = 5 * time.Minute
	// recheckInterval paces the renewal loop; retryInterval is its pace while
	// the disk certificate misses a configured name, so a hostname that starts
	// reaching this router is picked up quickly.
	recheckInterval = time.Hour
	retryInterval   = time.Minute
	accountKeyFile  = "account.key"
	certFile        = "cert.pem"
	keyFile         = "key.pem"
)

// manager issues and renews one certificate for the configured domains whose
// public HTTP challenge paths reach this router. Account key and issued key/cert live under --cert-dir only.
type manager struct {
	directoryURL string
	email        string
	dir          string // --cert-dir
	domains      []string
	log          *slog.Logger
	// httpPort is nginx's :80 server on pod loopback, probed before any CA
	// contact so a validation is never sent at a listener that is still
	// starting. 0 (tests without a front door) skips the probe; the CLI
	// validates the flag into 1-65535.
	httpPort int
	// probe dials each configured domain's public challenge path, so issuance
	// covers only the domains that reach this router. nil (tests without a
	// front door) treats every domain as reachable.
	probe *http.Client

	// recheck/retry pace run; tests tighten them.
	recheck time.Duration
	retry   time.Duration

	mu     sync.Mutex
	client *acme.Client
	tokens map[string]string // challenge token -> key authorization
}

func newManager(directoryURL, email, certDir string, domains []string, log *slog.Logger) *manager {
	return &manager{
		directoryURL: directoryURL,
		email:        email,
		dir:          certDir,
		domains:      domains,
		log:          log,
		recheck:      recheckInterval,
		retry:        retryInterval,
		tokens:       make(map[string]string),
	}
}

func (m *manager) certPath() string { return filepath.Join(m.dir, certFile) }
func (m *manager) keyPath() string  { return filepath.Join(m.dir, keyFile) }

// handler answers HTTP-01 challenges (nginx's :80 server proxies the
// challenge path here).
func (m *manager) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.URL.Path, challengePrefix)
		if !ok || token == "" {
			http.NotFound(w, r)
			return
		}
		m.mu.Lock()
		keyAuth, live := m.tokens[token]
		m.mu.Unlock()
		if !live {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, keyAuth)
	})
}

// run issues eagerly, then re-checks until ctx is done. Renewal fires at 2/3
// of the certificate's lifetime; while the disk certificate does not cover
// every configured name the loop re-checks at retryInterval.
func (m *manager) run(ctx context.Context) {
	if err := m.bootstrap(); err != nil {
		m.log.Error("bootstrap certificate failed", "error", err)
	}
	for {
		m.ensure(ctx)
		wait := m.recheck
		if m.needsIssue() {
			wait = m.retry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (m *manager) diskLeaf() (*x509.Certificate, error) {
	data, err := os.ReadFile(m.certPath())
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(m.keyPath()); err != nil {
		return nil, err
	}
	return certutil.ParseCertificatePEM(data)
}

// needsIssue reports whether the disk certificate is absent, is the
// self-signed bootstrap placeholder, covers a different SAN set than the
// configured domains, or is past 2/3 of its lifetime.
func (m *manager) needsIssue() bool {
	leaf, err := m.diskLeaf()
	if err != nil {
		return true
	}
	if bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return true
	}
	if !sameDomainSet(leaf.DNSNames, m.domains) {
		return true
	}
	renewAt := leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
	return time.Now().After(renewAt)
}

// bootstrap writes a self-signed placeholder key + cert when no certificate
// parses from disk, so nginx (whose config names both files) can start and
// serve the :80 challenge proxy the first real issuance needs. The
// self-issued leaf always reads as needing issuance.
func (m *manager) bootstrap() error {
	if _, err := m.diskLeaf(); err == nil {
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: m.domains[0]},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     m.domains,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	if err := fileutil.WriteAtomic(m.keyPath(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write bootstrap key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := fileutil.WriteAtomic(m.certPath(), certPEM, 0o644); err != nil {
		return fmt.Errorf("write bootstrap certificate: %w", err)
	}
	m.log.Info("wrote self-signed bootstrap certificate", "domains", m.domains)
	return nil
}

func sameDomainSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// ensure runs one issuance if the disk certificate needs one.
func (m *manager) ensure(ctx context.Context) {
	if !m.needsIssue() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, issueTimeout)
	defer cancel()
	domains := m.reachableDomains(ctx)
	if len(domains) == 0 {
		m.log.Warn("no configured hostname reaches this router's public HTTP challenge path")
		return
	}
	if !m.needsIssueFor(domains) {
		return
	}
	if err := m.issueDomains(ctx, domains); err != nil {
		m.log.Error("certificate issuance failed", "domains", domains, "error", err)
		return
	}
	m.log.Info("certificate issued", "domains", domains)
}

// acmeClient lazily initializes the ACME account: key from disk or freshly
// generated (0600), then registered at the directory.
func (m *manager) acmeClient(ctx context.Context) (*acme.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.client != nil {
		return m.client, nil
	}
	key, err := m.accountKey()
	if err != nil {
		return nil, err
	}
	client := &acme.Client{Key: key, DirectoryURL: m.directoryURL}
	account := &acme.Account{}
	if m.email != "" {
		account.Contact = []string{"mailto:" + m.email}
	}
	if _, err := client.Register(ctx, account, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("register ACME account: %w", err)
	}
	m.client = client
	return client, nil
}

func (m *manager) accountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(m.dir, accountKeyFile)
	if data, err := os.ReadFile(path); err == nil {
		key, err := certutil.ParseECPrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("account key at %s: %w", path, err)
		}
		return key, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, err
	}
	if err := fileutil.WriteAtomic(path, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write account key: %w", err)
	}
	return key, nil
}

// frontDoorReady blocks until nginx hands back this sidecar's own key
// authorization over pod loopback, so no order is opened at the CA before the
// public HTTP-01 path is serviceable (nginx up and proxy_pass intact).
func (m *manager) frontDoorReady(ctx context.Context) error {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	keyAuth := "probe." + token
	m.mu.Lock()
	m.tokens[token] = keyAuth
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.tokens, token)
		m.mu.Unlock()
	}()

	url := fmt.Sprintf("http://127.0.0.1:%d%s%s", m.httpPort, challengePrefix, token)
	client := &http.Client{Timeout: 2 * time.Second}
	for delay := 250 * time.Millisecond; ; delay = min(delay*2, 5*time.Second) {
		resp, err := client.Get(url)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && string(body) == keyAuth {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("front door never answered %s: %w", url, ctx.Err())
		case <-time.After(delay):
		}
	}
}

// issue runs the RFC 8555 HTTP-01 flow for the configured domain set and
// installs key + full chain under --cert-dir.
func (m *manager) issue(ctx context.Context) error { return m.issueDomains(ctx, m.domains) }

func (m *manager) issueDomains(ctx context.Context, domains []string) error {
	if m.httpPort != 0 {
		if err := m.frontDoorReady(ctx); err != nil {
			return err
		}
	}
	client, err := m.acmeClient(ctx)
	if err != nil {
		return err
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return fmt.Errorf("new order: %w", err)
	}
	for _, authzURL := range order.AuthzURLs {
		if err := m.fulfillAuthorization(ctx, client, authzURL); err != nil {
			return err
		}
	}
	if order, err = client.WaitOrder(ctx, order.URI); err != nil {
		return fmt.Errorf("order: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: domains}, key)
	if err != nil {
		return fmt.Errorf("create CSR: %w", err)
	}
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	var chainPEM []byte
	for _, der := range ders {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return err
	}
	// Key before cert: nginx is reloaded on the cert file, so a visible cert
	// must always have its key beside it.
	if err := fileutil.WriteAtomic(m.keyPath(), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if err := fileutil.WriteAtomic(m.certPath(), chainPEM, 0o644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	return nil
}

// fulfillAuthorization answers one authorization's http-01 challenge.
func (m *manager) fulfillAuthorization(ctx context.Context, client *acme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("authorization: %w", err)
	}
	if authz.Status == acme.StatusValid {
		return nil
	}
	var challenge *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "http-01" {
			challenge = c
			break
		}
	}
	if challenge == nil {
		return fmt.Errorf("authorization offers no http-01 challenge")
	}
	keyAuth, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.tokens[challenge.Token] = keyAuth
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.tokens, challenge.Token)
		m.mu.Unlock()
	}()
	if _, err := client.Accept(ctx, challenge); err != nil {
		return fmt.Errorf("accept challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("authorization did not validate: %w", err)
	}
	return nil
}

// needsIssueFor keeps a valid certificate when it already covers the reachable
// names. Names outside the signed launch configuration are never retained.
// A configured name the certificate covers but the probe missed may be a
// transient failure, so it blocks issuance until 5/6 of the lifetime.
func (m *manager) needsIssueFor(domains []string) bool {
	leaf, err := m.diskLeaf()
	if err != nil || bytes.Equal(leaf.RawIssuer, leaf.RawSubject) {
		return true
	}
	for _, name := range leaf.DNSNames {
		if !slices.Contains(m.domains, name) {
			return true
		}
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if time.Now().Before(leaf.NotBefore.Add(lifetime * 5 / 6)) {
		for _, name := range leaf.DNSNames {
			if !slices.Contains(domains, name) {
				return false
			}
		}
	}
	for _, name := range domains {
		if !slices.Contains(leaf.DNSNames, name) {
			return true
		}
	}
	return time.Now().After(leaf.NotBefore.Add(lifetime * 2 / 3))
}

// reachableDomains prevents an unavailable launch hostname from blocking the
// other names. This probe is only a readiness check. The CA still performs
// normal HTTP-01 ownership validation before it issues any certificate.
func (m *manager) reachableDomains(ctx context.Context) []string {
	if m.probe == nil {
		return slices.Clone(m.domains)
	}
	var reachable []string
	for _, name := range m.domains {
		if ctx.Err() != nil {
			break
		}
		if m.probeDomain(ctx, name) {
			reachable = append(reachable, name)
		}
	}
	return reachable
}

// probeDomain reports whether a request to name's public challenge path comes
// back to this manager: it serves a one-off token and checks the answer.
func (m *manager) probeDomain(ctx context.Context, name string) bool {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return false
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])
	proof := "c8s-public-probe." + token
	m.mu.Lock()
	m.tokens[token] = proof
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.tokens, token)
		m.mu.Unlock()
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+name+challengePrefix+token, nil)
	if err != nil {
		return false
	}
	resp, err := m.probe.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	return err == nil && resp.StatusCode == http.StatusOK && string(body) == proof
}

// publicProbeClient dials public names directly, with no proxy and no
// redirects, so a probe answer proves the path reaches this router.
func publicProbeClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	return &http.Client{
		Transport:     transport,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
