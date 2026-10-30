// Package cdsboard is the client for a CDS cluster's decree board: the
// S3-compatible object store an operator leaves decrees in and the leader
// writes status and backups to. The store is outside the trust boundary. It
// carries signed objects only, and the reader of an object verifies it, so the
// client speaks path-style S3 REST over HTTPS with the image's system roots
// and no credentials: the store admits a replica by network scope.
package cdsboard

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

const (
	// requestTimeout bounds one board request, its body included.
	requestTimeout = 30 * time.Second
	// maxListKeys and maxListBytes bound one listing, whatever the store
	// holds or answers.
	maxListKeys  = 1000
	maxListBytes = 1 << 20
	// maxKeyBytes is the longest key an S3 store takes.
	maxKeyBytes = 1024
)

// pathSegment accepts one segment of a board key.
var pathSegment = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// ErrNotFound reports a path the store holds nothing at: a missing object, a
// missing prefix or a missing bucket.
var ErrNotFound = errors.New("the store holds nothing there")

// Client reads and writes one cluster's board. Every key is relative to the
// cluster's own path under the store's prefix.
type Client struct {
	origin *url.URL
	bucket string
	// base prefixes every key, and ends with a slash.
	base string
	http *http.Client
}

// Object is one listed board object.
type Object struct {
	Key  string
	Size int64
}

// New addresses clusterID's board in the store its configuration names.
func New(board cdsconfig.Board, clusterID string) (*Client, error) {
	return newClient(board, clusterID, http.DefaultTransport)
}

func newClient(board cdsconfig.Board, clusterID string, transport http.RoundTripper) (*Client, error) {
	origin, err := url.Parse(board.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("board endpoint %q: %w", board.Endpoint, err)
	}
	if err := checkPath("cluster id", clusterID); err != nil {
		return nil, err
	}
	return &Client{
		origin: origin,
		bucket: board.Bucket,
		base:   path.Join(board.Prefix, clusterID) + "/",
		http: &http.Client{
			Timeout:       requestTimeout,
			Transport:     transport,
			CheckRedirect: refuseRedirect,
		},
	}, nil
}

// refuseRedirect keeps every request on the endpoint the launch file names.
func refuseRedirect(*http.Request, []*http.Request) error {
	return errors.New("the board endpoint answered with a redirect")
}

// List returns the objects under dir. A directory holding more than
// maxListKeys of them is refused rather than listed in part.
func (c *Client) List(ctx context.Context, dir string) ([]Object, error) {
	prefix, err := c.key(dir)
	if err != nil {
		return nil, err
	}
	target := c.bucketURL(url.Values{
		"list-type": {"2"},
		"max-keys":  {strconv.Itoa(maxListKeys)},
		"prefix":    {prefix + "/"},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	listing, err := readutil.ReadAll(resp.Body, maxListBytes)
	if err != nil {
		return nil, fmt.Errorf("board listing: %w", err)
	}
	return c.listed(listing)
}

// Get returns one object, refusing a body over maxBytes.
func (c *Client) Get(ctx context.Context, key string, maxBytes int64) ([]byte, error) {
	target, err := c.objectURL(key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	object, err := readutil.ReadAll(resp.Body, maxBytes)
	if err != nil {
		return nil, fmt.Errorf("board object %q: %w", key, err)
	}
	return object, nil
}

// Put writes one object. Writes are unconditional: the store orders nothing.
func (c *Client) Put(ctx context.Context, key string, object []byte) error {
	target, err := c.objectURL(key)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(object))
	if err != nil {
		return err
	}
	resp, err := c.send(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// send makes one request under the client's deadline; the caller closes the
// body of the answer.
func (c *Client) send(req *http.Request) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("board: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		resp.Body.Close()
		return nil, fmt.Errorf("board %s %s: %w", req.Method, req.URL.Path, ErrNotFound)
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return nil, fmt.Errorf("board %s %s: %s", req.Method, req.URL.Path, resp.Status)
	}
	return resp, nil
}

// listed reads a listing, naming each object by its key under the cluster's
// own path and passing over every key this client cannot address.
func (c *Client) listed(listing []byte) ([]Object, error) {
	var answer struct {
		XMLName   xml.Name `xml:"ListBucketResult"`
		Truncated bool     `xml:"IsTruncated"`
		Contents  []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(listing, &answer); err != nil {
		return nil, fmt.Errorf("board listing: %w", err)
	}
	if answer.Truncated {
		return nil, fmt.Errorf("board listing holds more than %d objects", maxListKeys)
	}
	objects := make([]Object, 0, len(answer.Contents))
	for _, entry := range answer.Contents {
		key, named := c.names(entry.Key)
		if !named {
			continue
		}
		objects = append(objects, Object{
			Key:  key,
			Size: entry.Size,
		})
	}
	return objects, nil
}

// names returns the listed key under the cluster's own path, and whether this
// client can address it there.
func (c *Client) names(listed string) (string, bool) {
	key, inside := strings.CutPrefix(listed, c.base)
	if !inside {
		return "", false
	}
	return key, checkPath("board key", key) == nil
}

// key is the bucket-relative key of one of this cluster's objects.
func (c *Client) key(relative string) (string, error) {
	if err := checkPath("board key", relative); err != nil {
		return "", err
	}
	key := c.base + relative
	if len(key) > maxKeyBytes {
		return "", fmt.Errorf("board key %q is longer than %d bytes", key, maxKeyBytes)
	}
	return key, nil
}

// checkPath accepts a relative path of named segments, so no key escapes the
// cluster's own path it is joined to.
func checkPath(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s names nothing", field)
	}
	for segment := range strings.SplitSeq(value, "/") {
		if !pathSegment.MatchString(segment) {
			return fmt.Errorf("%s %q: every segment must match %s", field, value, pathSegment)
		}
	}
	return nil
}

func (c *Client) objectURL(relative string) (string, error) {
	key, err := c.key(relative)
	if err != nil {
		return "", err
	}
	target := *c.origin
	target.Path = "/" + c.bucket + "/" + key
	return target.String(), nil
}

func (c *Client) bucketURL(query url.Values) string {
	target := *c.origin
	target.Path = "/" + c.bucket
	target.RawQuery = query.Encode()
	return target.String()
}
