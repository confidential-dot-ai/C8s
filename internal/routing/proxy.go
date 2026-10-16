package routing

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/routes"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	// maxTunnelResponseBytes bounds a backend response the tunnel buffers to
	// seal.
	maxTunnelResponseBytes = 32 << 20
	// defaultTunnelSlots bounds tunnelled requests in flight. Each buffers up
	// to four copies of its response (body, CBOR, sealed, written) and three
	// of its 8 MiB request, about 150 MiB.
	defaultTunnelSlots = 32
	// clientSlotShare is the fraction of the tunnel slots one client may hold,
	// so a client holding slow requests cannot take every slot.
	clientSlotShare = 4
)

// ExporterHeader carries the tunnel's channel-binding exporter to backends.
// Only the tunnel may set it: the routing listener drops a client's value.
const ExporterHeader = "X-C8s-Exporter"

// ProxyConfig configures a Proxy.
type ProxyConfig struct {
	State      *State
	Transports *Transports
	// Timeout bounds a request on the routing listener while no data moves
	// either way, and a tunnelled request's whole backend exchange, which
	// Forward buffers. Zero means none.
	Timeout time.Duration
	// TunnelSlots bounds tunnelled requests in flight (Acquire). Zero means
	// 32.
	TunnelSlots int
	Logger      *slog.Logger
}

// Proxy routes application requests by the applied manifest. It serves the
// routing listener as an http.Handler and the automated ingress tunnel through
// Forward, so both resolve against the same State (A7).
type Proxy struct {
	state      *State
	transports *Transports
	timeout    time.Duration
	log        *slog.Logger

	slotsMu        sync.Mutex
	slots          int            // tunnelled requests allowed in flight
	slotsPerClient int            // of those, what one client may hold
	inFlight       int            // tunnelled requests in flight
	held           map[string]int // client -> its requests in flight
}

// NewProxy returns a Proxy.
func NewProxy(cfg ProxyConfig) *Proxy {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	slots := cfg.TunnelSlots
	if slots <= 0 {
		slots = defaultTunnelSlots
	}
	return &Proxy{
		state:          cfg.State,
		transports:     cfg.Transports,
		timeout:        cfg.Timeout,
		log:            logger,
		slots:          slots,
		slotsPerClient: max(slots/clientSlotShare, 1),
		held:           make(map[string]int),
	}
}

// State returns the state the proxy routes by.
func (p *Proxy) State() *State { return p.state }

// Acquire takes a tunnel slot for client, or reports false when every slot
// is taken or client holds its share of them. The caller holds it from
// reading the sealed request until the sealed response is written, then calls
// release once.
func (p *Proxy) Acquire(client string) (release func(), ok bool) {
	p.slotsMu.Lock()
	defer p.slotsMu.Unlock()
	if p.inFlight >= p.slots || p.held[client] >= p.slotsPerClient {
		return nil, false
	}
	p.inFlight++
	p.held[client]++
	return func() {
		p.slotsMu.Lock()
		defer p.slotsMu.Unlock()
		p.inFlight--
		if p.held[client]--; p.held[client] == 0 {
			delete(p.held, client)
		}
	}, true
}

// ServeHTTP routes r by its Host (M1) and the path bytes it arrived with
// (routes.Table.Select). It drops a client's X-C8s-Exporter: backends trust
// it as the tunnel's channel binding.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del(ExporterHeader)
	applied := p.state.Current()
	if applied == nil {
		http.Error(w, "routes not applied", http.StatusServiceUnavailable) // A2
		return
	}
	route, target, ok := applied.Table.Select(r)
	if !ok {
		http.NotFound(w, r) // M5
		return
	}
	if p.timeout > 0 {
		var stop func()
		w, r, stop = idleExchange(w, r, p.timeout)
		defer stop()
	}
	p.reverseProxy(route, target, func(err error) {
		p.log.Warn("backend request failed", "host", r.Host, "path", target.RawPath, "backend", route.Backend.Address, "error", err)
		http.Error(w, "backend unavailable", http.StatusBadGateway) // B5
	}).ServeHTTP(w, r)
}

// clientAddressHeaders name the client's network address. A tunnelled request
// takes them from the outer request nginx populated, never from the sealed
// headers the client chose (router R6). Either way they are metadata the host
// can forge, not identity.
var clientAddressHeaders = []string{"X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto"}

// sealedDropped are sealed headers never forwarded: hop-by-hop fields
// (RFC 9110 §7.6.1), whose Connection list would let a client strip headers
// the tunnel sets, and the client-address fields.
var sealedDropped = map[string]bool{
	"host": true, "content-length": true, "x-c8s-session": true,
	"connection": true, "proxy-connection": true, "keep-alive": true, "te": true,
	"trailer": true, "transfer-encoding": true, "proxy-authenticate": true, "proxy-authorization": true,
	"x-real-ip": true, "x-forwarded-for": true, "x-forwarded-proto": true, "forwarded": true,
}

// Forward routes a request reconstructed from the automated ingress tunnel
// (A7), within outer's context. Its host is the sealed Host header, never
// outer's host: a sealed request without exactly one gets 400 (M1). Routing
// outcomes the client must see (A2, M5) are responses; an error means the
// backend failed (B5). The caller holds a slot from Acquire.
func (p *Proxy) Forward(outer *http.Request, req types.TunnelRequest) (types.TunnelResponse, error) {
	ctx := outer.Context()
	var host string
	var hosts int
	for _, f := range req.Headers {
		switch {
		case strings.EqualFold(f.Name, "Host"):
			host = f.Value
			hosts++
		case strings.EqualFold(f.Name, "Upgrade"):
			// The tunnel carries one buffered response; it cannot carry an
			// upgraded connection.
			return textResponse(http.StatusBadRequest, "the tunnel does not carry protocol upgrades"), nil
		}
	}
	if hosts != 1 {
		return textResponse(http.StatusBadRequest, "the sealed request must carry exactly one Host header"), nil
	}
	applied := p.state.Current()
	if applied == nil {
		return textResponse(http.StatusServiceUnavailable, "routes not applied"), nil
	}
	if p.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	header := http.Header{}
	for _, f := range req.Headers {
		if !sealedDropped[strings.ToLower(f.Name)] {
			header.Add(f.Name, f.Value)
		}
	}
	for _, name := range clientAddressHeaders {
		if v, ok := outer.Header[http.CanonicalHeaderKey(name)]; ok {
			header[http.CanonicalHeaderKey(name)] = v
		}
	}
	in := (&http.Request{
		Method:        method,
		URL:           &url.URL{Path: "/"},
		RequestURI:    req.Path,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Host:          host,
		Body:          io.NopCloser(bytes.NewReader(req.Body)),
		ContentLength: int64(len(req.Body)),
	}).WithContext(ctx)
	// in carries the sealed Host and request target only, so the outer
	// request's host never reaches Select (M1).
	route, target, ok := applied.Table.Select(in)
	if !ok {
		return textResponse(http.StatusNotFound, "404 page not found"), nil
	}

	var backendErr error
	rp := p.reverseProxy(route, target, func(err error) { backendErr = err })
	// Buffer the body here rather than in the copy ReverseProxy does after
	// this hook: a failed read surfaces as a backend error, never as a
	// truncated 200.
	var body []byte
	rp.ModifyResponse = func(res *http.Response) error {
		defer res.Body.Close()
		if res.StatusCode == http.StatusSwitchingProtocols {
			return errors.New("backend switched protocols on a tunnelled request")
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, maxTunnelResponseBytes+1))
		if err != nil {
			return err
		}
		if len(b) > maxTunnelResponseBytes {
			return fmt.Errorf("response exceeds %d bytes", maxTunnelResponseBytes)
		}
		body = b
		res.Body = http.NoBody
		return nil
	}
	rec := &capture{header: http.Header{}}
	rp.ServeHTTP(rec, in)
	if backendErr != nil {
		return types.TunnelResponse{}, fmt.Errorf("backend %s: %w", route.Backend.Address, backendErr)
	}
	return types.TunnelResponse{Status: rec.status, Headers: headerFields(rec.header), Body: body}, nil
}

// reverseProxy forwards to route's backend at target, which Select built
// (B6). onErr runs when the backend cannot be reached or fails verification;
// nothing is retried, in plaintext or on another route (B5).
func (p *Proxy) reverseProxy(route routes.Route, target *url.URL, onErr func(error)) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: p.transports.For(route.Backend),
		Rewrite: func(pr *httputil.ProxyRequest) {
			out := *target
			out.Scheme = "https"
			out.Host = route.Backend.Address
			pr.Out.URL = &out
			pr.Out.Host = pr.In.Host
			// ReverseProxy drops these before Rewrite; nginx set them for
			// the backend (router R6).
			for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Proto"} {
				if v, ok := pr.In.Header[name]; ok {
					pr.Out.Header[name] = v
				}
			}
		},
		FlushInterval: -1,
		ErrorHandler: func(_ http.ResponseWriter, _ *http.Request, err error) {
			onErr(err)
		},
	}
}

func textResponse(status int, msg string) types.TunnelResponse {
	return types.TunnelResponse{
		Status:  status,
		Headers: []types.HeaderField{{Name: "Content-Type", Value: "text/plain; charset=utf-8"}},
		Body:    []byte(msg),
	}
}

// headerFields flattens h into ordered pairs: names sorted, values of one name
// in backend order. ReverseProxy already dropped the hop-by-hop fields.
func headerFields(h http.Header) []types.HeaderField {
	names := make([]string, 0, len(h))
	for name := range h {
		if strings.EqualFold(name, "Content-Length") {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	var fields []types.HeaderField
	for _, name := range names {
		for _, v := range h[name] {
			fields = append(fields, types.HeaderField{Name: name, Value: v})
		}
	}
	return fields
}

// capture records the status and headers of a tunnelled response; the body
// is buffered by ModifyResponse.
type capture struct {
	header http.Header
	status int
}

func (c *capture) Header() http.Header { return c.header }

func (c *capture) WriteHeader(status int) {
	if c.status == 0 && status >= 200 {
		c.status = status
	}
}

func (c *capture) Write(b []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	return len(b), nil
}
