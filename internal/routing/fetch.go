package routing

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlistclient"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/routes"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/routesclient"
)

// errNoManifest reports that the Trust Authority stores no manifest (C1, 404).
var errNoManifest = errors.New("the Trust Authority stores no route manifest")

// Fetcher fetches the signed manifest the Trust Authority stores (C1).
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

// TAClient reads the route manifest and the operator keys from the Trust Authority. It
// is a Fetcher and a KeySource. The caller supplies an HTTP client that
// verifies the Trust Authority (A1).
type TAClient struct {
	routes    routesclient.Client
	allowlist allowlistclient.Client
	base      string
	http      *http.Client
}

// NewTAClient returns a client for the Trust Authority at base, an https origin.
func NewTAClient(base string, client *http.Client) (*TAClient, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("the Trust Authority URL %q must use https", base)
	}
	if u.User != nil {
		return nil, fmt.Errorf("the Trust Authority URL %q must carry no credentials", base)
	}
	rc, err := routesclient.New(base, client)
	if err != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Host
	return &TAClient{routes: rc, allowlist: allowlistclient.NewClientWithHTTP(origin, client), base: origin, http: client}, nil
}

// Object implements AllowlistHistory.
func (c *TAClient) Object(ctx context.Context, digest [sha256.Size]byte) (*allowlist.Allowlist, error) {
	return c.allowlist.Object(ctx, digest)
}

// Routes implements Fetcher.
func (c *TAClient) Routes(ctx context.Context) (routes.Envelope, error) {
	env, err := c.routes.Get(ctx)
	if errors.Is(err, routesclient.ErrNotFound) {
		return routes.Envelope{}, errNoManifest
	}
	return env, err
}

// OperatorKeys implements KeySource from the Trust Authority's published keys. It returns
// operatorauth.ErrNoPublishedKeys when the Trust Authority pins none.
func (c *TAClient) OperatorKeys(ctx context.Context) ([]*ecdsa.PublicKey, error) {
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
