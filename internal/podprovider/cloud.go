package podprovider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const cloudTimeout = 20 * time.Second

var errCloudNotFound = errors.New("cloud instance not found")

// These wire types cover the instance subset of Cloud API 2026-10-15.
type createRequest struct {
	Image     string            `json:"image"`
	Size      string            `json:"size"`
	Location  string            `json:"location"`
	Tee       string            `json:"tee"`
	Name      string            `json:"name"`
	Count     int               `json:"count"`
	Labels    map[string]string `json:"labels"`
	Network   networkSpec       `json:"network"`
	Readiness readinessSpec     `json:"readiness"`
	Trust     trustSpec         `json:"trust"`
}
type networkSpec struct {
	PublicIP string    `json:"publicIp"`
	Ingress  []ingress `json:"ingress"`
}
type ingress struct {
	Name string `json:"name"`
	Port int    `json:"port"`
}
type readinessSpec struct {
	TCPPorts []int `json:"tcpPorts"`
}
type trustSpec struct {
	LaunchKey string   `json:"launchKey"`
	InitData  initData `json:"initData"`
}
type initData struct {
	Format    string `json:"format"`
	Document  []byte `json:"document"`
	Signature []byte `json:"signature"`
}
type endpoint struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}
type instance struct {
	ID        string            `json:"id"`
	Status    string            `json:"status"`
	Tee       string            `json:"tee"`
	Labels    map[string]string `json:"labels"`
	Endpoints []endpoint        `json:"endpoints"`
	Image     struct {
		Family  string `json:"family"`
		Version string `json:"version"`
	} `json:"image"`
	Compute struct {
		VCPUs     int64 `json:"vcpus"`
		MemoryGiB int64 `json:"memoryGiB"`
	} `json:"compute"`
	Boot struct {
		Count int64 `json:"count"`
	} `json:"boot"`
}

type cloudAPI interface {
	Create(context.Context, string, createRequest) (*instance, error)
	Find(context.Context, string) (*instance, error)
	Get(context.Context, string) (*instance, error)
	Delete(context.Context, string) error
	Ping(context.Context) error
}

type cloudClient struct {
	base, token string
	http        *http.Client
}

func newCloudClient(cfg *Config) *cloudClient {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.TLSHandshakeTimeout = 5 * time.Second
	tr.ResponseHeaderTimeout = 10 * time.Second
	return &cloudClient{base: cfg.CloudURL, token: cfg.token, http: &http.Client{Transport: tr, Timeout: cloudTimeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (c *cloudClient) Create(ctx context.Context, key string, req createRequest) (*instance, error) {
	var out struct {
		Items []instance `json:"items"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/instances", key, req, &out); err != nil {
		return nil, err
	}
	if len(out.Items) != 1 {
		return nil, errors.New("cloud create must return exactly one instance")
	}
	return &out.Items[0], nil
}

func (c *cloudClient) Find(ctx context.Context, key string) (*instance, error) {
	var out struct {
		Items         []instance `json:"items"`
		NextPageToken string     `json:"nextPageToken"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/instances?idempotencyKey="+url.QueryEscape(key), "", nil, &out); err != nil {
		return nil, err
	}
	if len(out.Items) > 1 || out.NextPageToken != "" {
		return nil, errors.New("cloud idempotency lookup must identify at most one instance")
	}
	if len(out.Items) == 0 {
		return nil, nil
	}
	return &out.Items[0], nil
}

func (c *cloudClient) Get(ctx context.Context, id string) (*instance, error) {
	var out instance
	if err := c.do(ctx, http.MethodGet, "/v1/instances/"+url.PathEscape(id), "", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *cloudClient) Delete(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/v1/instances/"+url.PathEscape(id), "", nil, nil)
	if errors.Is(err, errCloudNotFound) {
		return nil
	}
	return err
}

func (c *cloudClient) Ping(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/v1/instances?pageSize=1", "", nil, new(json.RawMessage))
}

func (c *cloudClient) do(ctx context.Context, method, path, key string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, cloudTimeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return errors.New("construct Cloud request")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Api-Version", "2026-10-15")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cloud request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8*maxFile+1))
	if err != nil {
		return err
	}
	if len(data) > 8*maxFile {
		return errors.New("cloud response exceeds limit")
	}
	if resp.StatusCode == http.StatusNotFound {
		return errCloudNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Error details may contain launch input. Only the bounded error code
		// reaches controller logs; retries stay with the work queue.
		var p struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data, &p)
		if len(p.Code) > 80 || strings.ContainsAny(p.Code, " \r\n\t") {
			p.Code = "unknown"
		}
		return fmt.Errorf("cloud returned HTTP %d (%s)", resp.StatusCode, p.Code)
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return errors.New("invalid Cloud response")
		}
	}
	return nil
}
