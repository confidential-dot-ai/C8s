//go:build linux

// The per-pod mesh endpoint's credentials. get-cert publishes one generation at a
// time behind a pointer; the endpoint resolves that pointer and validates what it
// names, so the leaf it presents and the CA set it trusts come from one set.

package armtlsmesh

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

const (
	// generationPollInterval is how often the generation pointer is resolved.
	generationPollInterval = time.Second

	// pointerName is the pointer get-cert flips onto a published generation.
	pointerName = "current"
)

// credentialVolume is the directory get-cert publishes on: its pointer, plus
// the three file names the pod's readers use.
type credentialVolume struct {
	dir                        string
	chainName, keyName, caName string
}

// credentialVolumeFor requires the three reader paths in one directory under
// distinct names: one pointer covers a generation only if it covers all three.
func credentialVolumeFor(chainPath, keyPath, caPath string) (credentialVolume, error) {
	paths := []string{chainPath, keyPath, caPath}
	dirs := map[string]bool{}
	names := map[string]bool{}
	for _, path := range paths {
		dirs[filepath.Clean(filepath.Dir(path))] = true
		names[filepath.Base(path)] = true
	}
	if len(dirs) != 1 || len(names) != 3 {
		return credentialVolume{}, fmt.Errorf("--cert-path, --key-path and --ca-path must name three different files in one directory, not %q", paths)
	}
	return credentialVolume{
		dir:       filepath.Clean(filepath.Dir(chainPath)),
		chainName: filepath.Base(chainPath),
		keyName:   filepath.Base(keyPath),
		caName:    filepath.Base(caPath),
	}, nil
}

func (v credentialVolume) pointerPath() string { return filepath.Join(v.dir, pointerName) }

// read resolves the pointer once and reads the three files of the generation it
// names, so a publication part-way through cannot mix two generations.
func (v credentialVolume) read() (publishedSet, error) {
	target, err := os.Readlink(v.pointerPath())
	if err != nil {
		return publishedSet{}, fmt.Errorf("resolve the generation pointer: %w", err)
	}
	dir := filepath.Join(v.dir, target)
	chain, chainErr := os.ReadFile(filepath.Join(dir, v.chainName))
	key, keyErr := os.ReadFile(filepath.Join(dir, v.keyName))
	ca, caErr := os.ReadFile(filepath.Join(dir, v.caName))
	if err := errors.Join(chainErr, keyErr, caErr); err != nil {
		return publishedSet{}, fmt.Errorf("read generation %s: %w", target, err)
	}
	return publishedSet{chainPEM: chain, keyPEM: key, caPEM: ca}, nil
}

// publishedSet is the PEM of one generation, as the pointer named it.
type publishedSet struct {
	chainPEM, keyPEM, caPEM []byte
}

func (s publishedSet) sameAs(other publishedSet) bool {
	return bytes.Equal(s.chainPEM, other.chainPEM) &&
		bytes.Equal(s.keyPEM, other.keyPEM) &&
		bytes.Equal(s.caPEM, other.caPEM)
}

// generation is one adopted credential set with the two mesh configurations
// built from it. A configuration is never carried across an adoption, so an
// endpoint trusts only the CA set published with the leaf it presents.
type generation struct {
	serverTLS, clientTLS *tls.Config
	cert                 *tls.Certificate
	caSet                []*x509.Certificate
	published            publishedSet
}

// adoptPublishedSet validates a published set and builds the configurations that
// serve it: the leaf matches the published key, names a workload instance, and
// chains to the CA set published with it.
func adoptPublishedSet(published publishedSet, now time.Time, logger *slog.Logger) (*generation, error) {
	cert, err := tls.X509KeyPair(published.chainPEM, published.keyPEM)
	if err != nil {
		return nil, fmt.Errorf("published leaf and key: %w", err)
	}
	cert.Leaf, err = certutil.ParseCertificatePEM(published.chainPEM)
	if err != nil {
		return nil, fmt.Errorf("published leaf: %w", err)
	}
	caSet, err := certutil.ParsePEMCertificates(published.caPEM)
	if err != nil {
		return nil, fmt.Errorf("published CA set: %w", err)
	}
	if err := requireWorkloadInstance(cert.Leaf); err != nil {
		return nil, err
	}
	if err := requireChainToCASet(cert.Leaf, caSet, now); err != nil {
		return nil, err
	}
	provider, err := newPublishedCredentials(&cert)
	if err != nil {
		return nil, err
	}
	meshCfg := &armtls.MeshConfig{CertProvider: provider, MeshCAs: caSet, Logger: logger}
	serverTLS, _, err := armtls.NewMeshServerTLSConfig(meshCfg)
	if err != nil {
		return nil, err
	}
	clientTLS, _, err := armtls.NewMeshClientTLSConfig(meshCfg)
	if err != nil {
		return nil, err
	}
	return &generation{serverTLS: serverTLS, clientTLS: clientTLS, cert: &cert, caSet: caSet, published: published}, nil
}

// requireWorkloadInstance refuses a leaf no mesh peer would accept: the instance
// ID is what names the workload behind the key.
func requireWorkloadInstance(leaf *x509.Certificate) error {
	id, err := armtls.SandboxIDFromCert(leaf)
	if err != nil {
		return fmt.Errorf("published leaf workload instance ID: %w", err)
	}
	if id == "" {
		return errors.New("published leaf carries no workload instance ID")
	}
	return nil
}

// requireChainToCASet is the trust policy a generation carries: the leaf chains
// to the CA set its peers are verified against, in both roles it is presented in.
func requireChainToCASet(leaf *x509.Certificate, caSet []*x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	for _, ca := range caSet {
		roots.AddCert(ca)
	}
	for role, purpose := range map[string]x509.ExtKeyUsage{
		"mesh server": x509.ExtKeyUsageServerAuth,
		"mesh client": x509.ExtKeyUsageClientAuth,
	} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: now,
			KeyUsages:   []x509.ExtKeyUsage{purpose},
		}); err != nil {
			return fmt.Errorf("published leaf does not chain to the published CA set as a %s: %w", role, err)
		}
	}
	return nil
}

// expiry is when the generation stops authenticating connections: the earliest
// NotAfter of its leaf and of the CA set it trusts.
func (g *generation) expiry() time.Time {
	expiry := g.cert.Leaf.NotAfter
	for _, ca := range g.caSet {
		if ca.NotAfter.Before(expiry) {
			expiry = ca.NotAfter
		}
	}
	return expiry
}

// usableAt reports whether the generation can still authenticate a new
// connection: its leaf is inside its window and nothing it trusts has expired.
func (g *generation) usableAt(now time.Time) error {
	if err := certutil.CheckValidity(g.cert.Leaf, now); err != nil {
		return fmt.Errorf("leaf: %w", err)
	}
	for _, ca := range g.caSet {
		if err := certutil.CheckValidity(ca, now); err != nil {
			return fmt.Errorf("mesh CA %q: %w", ca.Subject.CommonName, err)
		}
	}
	return nil
}

// publishedCredentials hands one generation's credentials to a handshake.
// Renewal is get-cert's: a new generation replaces the whole configuration.
type publishedCredentials struct {
	cert *tls.Certificate
}

// newPublishedCredentials requires the parsed leaf the validity check reads.
func newPublishedCredentials(cert *tls.Certificate) (publishedCredentials, error) {
	if cert == nil || cert.Leaf == nil {
		return publishedCredentials{}, errors.New("published credentials carry no parsed leaf")
	}
	return publishedCredentials{cert: cert}, nil
}

func (p publishedCredentials) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	return p.cert, time.Until(p.cert.Leaf.NotAfter), nil
}

// credentials is the endpoint's view of the published generations: it adopts
// each one that validates and holds nothing else.
type credentials struct {
	volume  credentialVolume
	logger  *slog.Logger
	adopted atomic.Pointer[generation]
}

// usable returns the generation a new connection must use, or the reason the
// endpoint refuses the connection (R3).
func (c *credentials) usable(now time.Time) (*generation, error) {
	g := c.adopted.Load()
	if g == nil {
		return nil, errors.New("no credential generation is published")
	}
	if err := g.usableAt(now); err != nil {
		return nil, err
	}
	return g, nil
}

// watchGenerations adopts each published generation for the connections opened
// after it. It returns when ctx is cancelled.
func (c *credentials) watchGenerations(ctx context.Context) {
	ticker := time.NewTicker(generationPollInterval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		c.reload(time.Now())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *credentials) reload(now time.Time) {
	c.adoptPublication(now)
	c.withdrawUnusable(now)
}

// adoptPublication adopts the published generation when it is new and validates.
// A publication that does not validate never replaces a usable generation (R2);
// a withdrawn pointer leaves the endpoint with nothing (R3).
func (c *credentials) adoptPublication(now time.Time) {
	published, err := c.volume.read()
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.withdraw(err)
		return
	case err != nil:
		c.logger.Warn("reading the published generation failed", "error", err)
		return
	}
	if adopted := c.adopted.Load(); adopted != nil && adopted.published.sameAs(published) {
		return
	}
	g, err := adoptPublishedSet(published, now, c.logger)
	if err != nil {
		c.logger.Error("published credential generation rejected", "error", err)
		return
	}
	c.adopted.Store(g)
	c.logger.Info("credential generation adopted", "expires", g.expiry())
}

// withdrawUnusable drops the adopted generation once it stops validating.
func (c *credentials) withdrawUnusable(now time.Time) {
	adopted := c.adopted.Load()
	if adopted == nil {
		return
	}
	if err := adopted.usableAt(now); err != nil {
		c.withdraw(err)
	}
}

// withdraw drops the adopted generation: every later connection is refused (R3).
func (c *credentials) withdraw(cause error) {
	if c.adopted.Swap(nil) == nil {
		return
	}
	c.logger.Warn("credential generation withdrawn; refusing new connections", "error", cause)
}
