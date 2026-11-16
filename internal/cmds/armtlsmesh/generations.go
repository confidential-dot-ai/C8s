//go:build linux

// The per-pod mesh endpoint's credentials. get-cert publishes one generation at a
// time behind a pointer; the endpoint validates the generation credvolume
// resolves, so the leaf it presents and the CA it trusts come from one set.

package armtlsmesh

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/credvolume"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// generationPollInterval is how often the generation pointer is resolved.
const generationPollInterval = time.Second

// generation is one adopted credential set with the two mesh configurations
// built from it. A configuration is never carried across an adoption, so an
// endpoint trusts only the CA published with the leaf it presents.
type generation struct {
	serverTLS, clientTLS *tls.Config
	cert                 *tls.Certificate
	ca                   *x509.Certificate
	published            credvolume.Set
}

// adoptPublishedSet validates a published set and builds the configurations that
// serve it: the leaf matches the published key, names a workload instance, and
// chains to the CA published with it.
func adoptPublishedSet(published credvolume.Set, now time.Time, logger *slog.Logger) (*generation, error) {
	cert, err := tls.X509KeyPair(published.ChainPEM, published.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("published leaf and key: %w", err)
	}
	cert.Leaf, err = certutil.ParseCertificatePEM(published.ChainPEM)
	if err != nil {
		return nil, fmt.Errorf("published leaf: %w", err)
	}
	cas, err := certutil.ParsePEMCertificates(published.CAPEM)
	if err != nil {
		return nil, fmt.Errorf("published CA: %w", err)
	}
	// CDS holds one mesh CA, so a generation published with any other number
	// of them is not one this endpoint can serve.
	if len(cas) != 1 {
		return nil, fmt.Errorf("published CA holds %d certificates, want the one mesh CA", len(cas))
	}
	ca := cas[0]
	if err := requireWorkloadInstance(cert.Leaf); err != nil {
		return nil, err
	}
	if err := requireChainToCA(cert.Leaf, ca, now); err != nil {
		return nil, err
	}
	provider, err := newPublishedCredentials(&cert)
	if err != nil {
		return nil, err
	}
	meshCfg := &armtls.MeshConfig{
		CertProvider: provider,
		MeshCA:       ca,
		Logger:       logger,
	}
	serverTLS, _, err := armtls.NewMeshServerTLSConfig(meshCfg)
	if err != nil {
		return nil, err
	}
	clientTLS, _, err := armtls.NewMeshClientTLSConfig(meshCfg)
	if err != nil {
		return nil, err
	}
	return &generation{
		serverTLS: serverTLS,
		clientTLS: clientTLS,
		cert:      &cert,
		ca:        ca,
		published: published,
	}, nil
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

// requireChainToCA is the trust policy a generation carries: the leaf chains to
// the CA its peers are verified against, in both roles it is presented in.
func requireChainToCA(leaf *x509.Certificate, ca *x509.Certificate, now time.Time) error {
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	for role, purpose := range map[string]x509.ExtKeyUsage{
		"mesh server": x509.ExtKeyUsageServerAuth,
		"mesh client": x509.ExtKeyUsageClientAuth,
	} {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:       roots,
			CurrentTime: now,
			KeyUsages:   []x509.ExtKeyUsage{purpose},
		}); err != nil {
			return fmt.Errorf("published leaf does not chain to the published CA as a %s: %w", role, err)
		}
	}
	return nil
}

// expiry is when the generation stops authenticating connections: the earlier
// NotAfter of its leaf and of the CA it trusts.
func (g *generation) expiry() time.Time {
	if g.ca.NotAfter.Before(g.cert.Leaf.NotAfter) {
		return g.ca.NotAfter
	}
	return g.cert.Leaf.NotAfter
}

// usableAt reports whether the generation can still authenticate a new
// connection: its leaf is inside its window and nothing it trusts has expired.
func (g *generation) usableAt(now time.Time) error {
	if err := certutil.CheckValidity(g.cert.Leaf, now); err != nil {
		return fmt.Errorf("leaf: %w", err)
	}
	if err := certutil.CheckValidity(g.ca, now); err != nil {
		return fmt.Errorf("mesh CA %q: %w", g.ca.Subject.CommonName, err)
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
	volume  credvolume.Volume
	logger  *slog.Logger
	adopted atomic.Pointer[generation]
}

// usable returns the generation a new connection must use, or the reason the
// endpoint refuses the connection.
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
// A publication that does not validate never replaces a usable generation;
// a withdrawn pointer leaves the endpoint with nothing.
func (c *credentials) adoptPublication(now time.Time) {
	published, err := c.volume.Read()
	switch {
	case errors.Is(err, credvolume.ErrMissingPointer):
		c.withdraw(err)
		return
	case err != nil:
		c.logger.Warn("reading the published generation failed", "error", err)
		return
	}
	if adopted := c.adopted.Load(); adopted != nil && adopted.published.SameAs(published) {
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

// withdraw drops the adopted generation: every later connection is refused.
func (c *credentials) withdraw(cause error) {
	if c.adopted.Swap(nil) == nil {
		return
	}
	c.logger.Warn("credential generation withdrawn; refusing new connections", "error", cause)
}
