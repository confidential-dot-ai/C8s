package routing

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/routesclient"
)

// errNoManifest reports that the CDS stores no manifest (C1, 404).
var errNoManifest = errors.New("CDS stores no route manifest")

// Fetcher fetches the signed manifest the CDS stores (C1).
type Fetcher interface {
	Routes(ctx context.Context) (routes.Envelope, error)
}

// KeySource returns the operator keys a signed manifest must verify under
// (W2, W6).
type KeySource interface {
	OperatorKeys(ctx context.Context) ([]*ecdsa.PublicKey, error)
}

// KeyFile is a KeySource that reads a PEM bundle of operator public keys from
// a path on every call, such as the node's launch configuration (W6).
type KeyFile string

// OperatorKeys implements KeySource.
func (f KeyFile) OperatorKeys(context.Context) ([]*ecdsa.PublicKey, error) {
	b, err := os.ReadFile(string(f))
	if err != nil {
		return nil, err
	}
	return operatorauth.ParsePublicKeysPEM(b)
}

// CAFile returns a CASource that reads a PEM CA bundle from path on every
// call, so a bundle get-cert rewrites after a CDS restart takes effect.
func CAFile(path string) CASource {
	return func() ([]*x509.Certificate, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return certutil.ParsePEMCertificates(b)
	}
}

// CDSClient reads the route manifest and the operator keys from the CDS. It
// is a Fetcher and a KeySource. The caller supplies an HTTP client that
// verifies the CDS (A1).
type CDSClient struct {
	routes routesclient.Client
	base   string
	http   *http.Client
}

// NewCDSClient returns a client for the CDS at base, an https origin.
func NewCDSClient(base string, client *http.Client) (*CDSClient, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("CDS URL %q must use https", base)
	}
	if u.User != nil {
		return nil, fmt.Errorf("CDS URL %q must carry no credentials", base)
	}
	rc, err := routesclient.New(base, client)
	if err != nil {
		return nil, err
	}
	return &CDSClient{routes: rc, base: u.Scheme + "://" + u.Host, http: client}, nil
}

// Routes implements Fetcher.
func (c *CDSClient) Routes(ctx context.Context) (routes.Envelope, error) {
	env, err := c.routes.Get(ctx)
	if errors.Is(err, routesclient.ErrNotFound) {
		return routes.Envelope{}, errNoManifest
	}
	return env, err
}

// OperatorKeys implements KeySource from the CDS's published keys. It returns
// operatorauth.ErrNoPublishedKeys when the CDS pins none.
func (c *CDSClient) OperatorKeys(ctx context.Context) ([]*ecdsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+operatorauth.PublishedKeysPath, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", operatorauth.PublishedKeysPath, err)
	}
	defer resp.Body.Close()
	return operatorauth.ReadPublishedKeys(resp)
}
