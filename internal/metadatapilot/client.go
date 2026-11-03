package metadatapilot

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

type Client struct {
	endpoint  string
	namespace string
	client    *http.Client
	token     atomic.Pointer[string]
}

func CheckEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("metadata endpoint must be an HTTPS origin without credentials, path, query or fragment")
	}
	return nil
}

func NewClient(endpoint, namespace, token string, transport http.RoundTripper) (*Client, error) {
	if err := CheckEndpoint(endpoint); err != nil {
		return nil, err
	}
	if !validNamespace(namespace) {
		return nil, errors.New("invalid metadata namespace")
	}
	c := &Client{endpoint: strings.TrimSuffix(endpoint, "/"), namespace: namespace,
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if err := c.SetToken(token); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) SetToken(token string) error {
	if !ValidToken(token) {
		return errors.New("metadata pilot requires a separate bearer token of at least 32 ASCII characters")
	}
	c.token.Store(&token)
	return nil
}

func (c *Client) Close() { c.client.CloseIdleConnections() }

func (c *Client) Get(ctx context.Context, key string) (objectwal.Object, error) {
	return c.do(ctx, http.MethodGet, key, nil, "")
}
func (c *Client) Put(ctx context.Context, key string, body []byte, expected string) (string, error) {
	if len(body) == 0 || len(body) > MaxHeadBytes {
		return "", errors.New("metadata head exceeds size bound")
	}
	obj, err := c.do(ctx, http.MethodPut, key, body, expected)
	return obj.ETag, err
}

func (c *Client) do(ctx context.Context, method, key string, body []byte, expected string) (objectwal.Object, error) {
	if key != c.namespace+"/head" {
		return objectwal.Object{}, errors.New("metadata pilot: key outside configured head")
	}
	r, err := http.NewRequestWithContext(ctx, method, c.endpoint+HeadPath, bytes.NewReader(body))
	if err != nil {
		return objectwal.Object{}, err
	}
	r.GetBody = nil // Never replay a conditional publication after a lost reply.
	r.Header.Set("Authorization", "Bearer "+*c.token.Load())
	r.Header.Set("X-CDS-Namespace", c.namespace)
	if method == http.MethodPut {
		if expected == "" {
			r.Header.Set("If-None-Match", "*")
		} else {
			r.Header.Set("If-Match", expected)
		}
	}
	response, err := c.client.Do(r)
	if err != nil {
		if ctx.Err() != nil {
			return objectwal.Object{}, ctx.Err()
		}
		return objectwal.Object{}, errors.New("metadata pilot: transport failure")
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusNotFound:
		return objectwal.Object{}, objectwal.ErrNotFound
	case http.StatusPreconditionFailed:
		return objectwal.Object{}, objectwal.ErrConflict
	case http.StatusTooManyRequests:
		return objectwal.Object{}, objectwal.ErrBackpressure
	}
	want := http.StatusOK
	if method == http.MethodPut {
		want = http.StatusNoContent
	}
	if response.StatusCode != want {
		return objectwal.Object{}, fmt.Errorf("metadata pilot: HTTP %d", response.StatusCode)
	}
	if response.Header.Get("ETag") == "" {
		return objectwal.Object{}, errors.New("metadata pilot: missing ETag")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, MaxHeadBytes+1))
	if err != nil || len(data) > MaxHeadBytes {
		return objectwal.Object{}, errors.New("metadata pilot: unreadable or oversized response")
	}
	return objectwal.Object{Data: data, ETag: response.Header.Get("ETag")}, nil
}

// SplitStore preserves the immutable-object path and routes only the encrypted
// commit head to transactional metadata. It intentionally preserves one ordered
// CDS history; it does not claim per-secret or per-token write sharding.
type SplitStore struct {
	Objects  objectwal.Store
	Metadata objectwal.Store
	HeadKey  string
}

func (s SplitStore) Get(ctx context.Context, key string) (objectwal.Object, error) {
	if key == s.HeadKey {
		return s.Metadata.Get(ctx, key)
	}
	return s.Objects.Get(ctx, key)
}
func (s SplitStore) Put(ctx context.Context, key string, value []byte, etag string) (string, error) {
	if key == s.HeadKey {
		return s.Metadata.Put(ctx, key, value, etag)
	}
	return s.Objects.Put(ctx, key, value, etag)
}
