package routing

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	// MaxTunnelRecordBytes bounds a sealed tunnel request record.
	MaxTunnelRecordBytes = 8 << 20
	// MaxTunnelResponseBytes bounds a backend response the tunnel buffers to
	// seal.
	MaxTunnelResponseBytes = 32 << 20
	// DefaultTunnelBudget is the tunnel budget when ProxyConfig sets none.
	DefaultTunnelBudget = 32 << 30
	// A tunnelled request holds up to three copies of its record (sealed,
	// opened, decoded) and four of its response (body, envelope, sealed,
	// encoded).
	recordCopies   = 3
	responseCopies = 4
	// clientShare is the fraction of the budget one client may hold, so one
	// client holding slow requests cannot take all of it.
	clientShare = 4
)

// TunnelReservation is what Acquire reserves for a tunnelled request with a
// record of recordBytes: every copy of the record and of the largest response
// it may buffer.
func TunnelReservation(recordBytes int64) int64 {
	return recordCopies*recordBytes + responseCopies*MaxTunnelResponseBytes
}

// backendEntryChanged is the body of the 502 a workload route gets when the
// backend's stamped allowlist entry is not unchanged in the current allowlist
// (B8).
const backendEntryChanged = "backend_entry_changed"

// ExporterHeader carries the tunnel's channel-binding exporter to backends.
// Only the tunnel may set it: the routing listener drops a client's value.
const ExporterHeader = "X-C8s-Exporter"

// ConnectionHeader names the public connection nginx relayed a request on,
// replacing any client value (E8). It pairs a routing-listener request with
// the attest-lb handshake that arrived on the same connection; it is not
// evidence.
const ConnectionHeader = "X-C8s-Connection"

// Binding is what a client verified on an attested handshake (E5): the digest
// of the manifest the handshake bound, and the allowlist digest of the router
// stamp on the mesh leaf it bound, empty for a leaf without one. The session
// routes while that manifest is applied and the entries its workload routes
// name are unchanged from that allowlist in the current one (E6).
type Binding struct {
	RouteDigest  [sha256.Size]byte
	RouterDigest string
}

// Bindings holds the attest-lb bindings by connection identifier. Hold
// reports the binding of connection, the code a request on it was refused
// with ("" for none), and whether it has one; a held binding does not expire
// until release, which restarts its idle lifetime (E7). Refuse records a
// refusal on the binding generation the request held, so the connection stays
// refused (E6); a binding replaced by a newer handshake since the hold is
// left alone.
type Bindings interface {
	Hold(connection string) (bound Binding, refused string, gen uint64, release func(), ok bool)
	Refuse(connection string, gen uint64, code string)
}

// BindingChangedError refuses a request whose session is bound to another
// route digest than the applied one, or to entries the current allowlist
// changed (E6). Code is the route policy's error code for it.
type BindingChangedError struct {
	Code string
}

func (e *BindingChangedError) Error() string { return "routing: session binding changed: " + e.Code }

// ProxyConfig configures a Proxy.
type ProxyConfig struct {
	State      *State
	Transports *Transports
	// Bindings, when set, refuses a routing-listener request on an attest-lb
	// bound connection whose binding no longer holds (E6).
	Bindings Bindings
	// Timeout bounds a request on the routing listener while no data moves
	// either way, and a tunnelled request's whole backend exchange, which
	// Forward buffers. Zero means none.
	Timeout time.Duration
	// TunnelBudget bounds the bytes tunnelled requests in flight may buffer
	// (Acquire); one client may hold a quarter of it, or at least one
	// full-size request. Zero means DefaultTunnelBudget.
	TunnelBudget int64
	Logger       *slog.Logger
}

// Proxy routes application requests by the applied manifest. It serves the
// routing listener as an http.Handler and the automated ingress tunnel through
// Forward, so both resolve against the same State (A7).
type Proxy struct {
	state      *State
	transports *Transports
	bindings   Bindings
	timeout    time.Duration
	log        *slog.Logger

	budgetMu  sync.Mutex
	budget    int64            // bytes tunnelled requests may reserve
	perClient int64            // of those, what one client may hold
	reserved  int64            // bytes reserved by tunnelled requests in flight
	held      map[string]int64 // client -> bytes its requests reserve
}

// NewProxy returns a Proxy.
func NewProxy(cfg ProxyConfig) *Proxy {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	budget := cfg.TunnelBudget
	if budget <= 0 {
		budget = DefaultTunnelBudget
	}
	return &Proxy{
		state:      cfg.State,
		transports: cfg.Transports,
		bindings:   cfg.Bindings,
		timeout:    cfg.Timeout,
		log:        logger,
		budget:     budget,
		perClient:  min(max(budget/clientShare, TunnelReservation(MaxTunnelRecordBytes)), budget),
		held:       make(map[string]int64),
	}
}

// Session and Current read the State the proxy routes by, so a handshake
// binds the digest of the manifest its tunnel then routes by (A5, E2).
func (p *Proxy) Session() (*Applied, error) { return p.state.Session() }

// Current returns the applied manifest, or nil before the first apply.
func (p *Proxy) Current() *Applied { return p.state.Current() }

// Acquire reserves TunnelReservation(recordBytes) for a tunnelled request
// from client. It reports false when the budget, or client's share of it,
// cannot cover that. The caller holds the reservation from reading the record
// until the sealed response is written, then calls release once.
func (p *Proxy) Acquire(client string, recordBytes int64) (release func(), ok bool) {
	n := TunnelReservation(recordBytes)
	p.budgetMu.Lock()
	defer p.budgetMu.Unlock()
	if p.reserved+n > p.budget || p.held[client]+n > p.perClient {
		return nil, false
	}
	p.reserved += n
	p.held[client] += n
	return func() {
		p.budgetMu.Lock()
		defer p.budgetMu.Unlock()
		p.reserved -= n
		if p.held[client] -= n; p.held[client] == 0 {
			delete(p.held, client)
		}
	}, true
}

// ServeHTTP routes r by its Host (M1) and the path bytes it arrived with
// (routes.Table.Select). It drops a client's X-C8s-Exporter: backends trust
// it as the tunnel's channel binding. A request on an attest-lb bound
// connection is routed only while its binding holds (E6).
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Del(ExporterHeader)
	connection := r.Header.Get(ConnectionHeader)
	r.Header.Del(ConnectionHeader)
	applied := p.state.Current()
	if applied == nil {
		http.Error(w, "routes not applied", http.StatusServiceUnavailable) // A2
		return
	}
	var held uint64
	refuse := func(code string) {
		// A digest changing back does not route the connection again (E6).
		p.bindings.Refuse(connection, held, code)
		p.log.Debug("bound request refused", "code", code, "host", r.Host)
		http.Error(w, code, http.StatusServiceUnavailable)
	}
	if p.bindings != nil && connection != "" {
		if b, refused, gen, release, ok := p.bindings.Hold(connection); ok {
			// Refused requests slide the lifetime too, so the connection stays
			// refused while nginx keeps it open (E7).
			defer release()
			held = gen
			code := refused
			if code == "" {
				code = p.changed(r.Context(), b, applied)
			}
			if code != "" {
				refuse(code)
				return
			}
		}
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
		status, body := p.refusal(err, r.Host, target.RawPath, route.Backend.Address)
		http.Error(w, body, status)
	}).ServeHTTP(w, r)
}

// changed returns the code refusing a request bound to b, or "" while applied
// is the manifest b holds and every entry its workload routes name is
// unchanged from b's router digest in the current allowlist (E6). A binding
// with no router digest holds the manifest alone.
func (p *Proxy) changed(ctx context.Context, b Binding, applied *Applied) string {
	if applied.Signed.Digest() != b.RouteDigest {
		return types.ErrorCodeRouteDigestChanged
	}
	if b.RouterDigest == "" {
		return ""
	}
	if err := p.transports.cfg.Entries.Check(ctx, b.RouterDigest, applied.workloadNames()...); err != nil {
		p.log.Info("bound session refused", "error", err)
		return types.ErrorCodeRouteEntryChanged
	}
	return ""
}

// refusal logs a failed backend exchange and returns the response it gets:
// 502 backend_entry_changed (B8) or the plain 502 of B5. A changed entry is
// expected for a backend not yet renewed after an allowlist write, so it logs
// at Info.
func (p *Proxy) refusal(err error, host, path, backend string) (int, string) {
	if errors.Is(err, errBackendEntryChanged) {
		p.log.Info("backend request refused", "host", host, "path", path, "backend", backend, "error", err)
		return http.StatusBadGateway, backendEntryChanged
	}
	p.log.Warn("backend request failed", "host", host, "path", path, "backend", backend, "error", err)
	return http.StatusBadGateway, "backend unavailable"
}

// clientAddressHeaders name the client's network address. A tunnelled request
// takes them from the outer request nginx populated, never from the sealed
// headers the client chose (router R2). Either way they are metadata the host
// can forge, not identity.
var clientAddressHeaders = []string{"X-Real-IP", "X-Forwarded-For", "X-Forwarded-Proto"}

// sealedDropped are sealed headers never forwarded: hop-by-hop fields
// (RFC 9110 §7.6.1), whose Connection list would let a client strip headers
// the tunnel sets, and the client-address fields.
var sealedDropped = map[string]bool{
	"host": true, "content-length": true, "x-c8s-session": true, "x-c8s-connection": true,
	"connection": true, "proxy-connection": true, "keep-alive": true, "te": true,
	"trailer": true, "transfer-encoding": true, "proxy-authenticate": true, "proxy-authorization": true,
	"x-real-ip": true, "x-forwarded-for": true, "x-forwarded-proto": true, "forwarded": true,
}

// Forward routes a request reconstructed from the automated ingress tunnel
// (A7), within outer's context, for a session bound to bound. Its host is the
// sealed Host header, never outer's host: a sealed request without exactly
// one gets 400 (M1). Routing outcomes the client must see (A2, M5) are
// responses. A *BindingChangedError means bound no longer holds and nothing
// was forwarded (E6); any other error means the backend failed (B5). The
// caller holds a reservation from Acquire.
func (p *Proxy) Forward(outer *http.Request, req types.TunnelRequest, bound Binding) (types.TunnelResponse, error) {
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
	// Against the manifest this request is then routed by, so a manifest
	// applied after the check cannot route it.
	if code := p.changed(ctx, bound, applied); code != "" {
		return types.TunnelResponse{}, &BindingChangedError{Code: code}
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
		b, err := io.ReadAll(io.LimitReader(res.Body, MaxTunnelResponseBytes+1))
		if err != nil {
			return err
		}
		if len(b) > MaxTunnelResponseBytes {
			return fmt.Errorf("response exceeds %d bytes", MaxTunnelResponseBytes)
		}
		body = b
		res.Body = http.NoBody
		return nil
	}
	rec := &capture{header: http.Header{}}
	rp.ServeHTTP(rec, in)
	if errors.Is(backendErr, errBackendEntryChanged) {
		status, msg := p.refusal(backendErr, in.Host, target.RawPath, route.Backend.Address)
		return textResponse(status, msg), nil
	}
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
			// the backend (router R2).
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
