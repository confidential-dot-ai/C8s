package cdsattest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"
)

// connectionTimeHeader carries nginx's $connection_time: how long the client's
// front-door connection has been open when the request arrived. On a
// keepalive connection that is the connection's age, not the request's.
const connectionTimeHeader = "X-C8s-Connection-Time"

// maxConnectionAge bounds the header so it converts to a Duration without
// overflowing into a future connection start.
const maxConnectionAge = 365 * 24 * time.Hour

// verifiedStateHeader carries the journal head (the rollout state's "head")
// the client verified. When a request carries it, the request is forwarded
// only while it equals the router's current head, so that client never
// reaches the upstream under a state it has not checked. Requests without it
// are served as before.
const verifiedStateHeader = "X-C8s-Verified-State"

// reconnectStatus refuses a request whose client must open a new connection
// and attest again. It is private to the loopback hop: nginx cannot close the
// client's keepalive connection on an upstream 503 or Connection: close, so
// location / maps this status to a 503 from a location with keepalive off
// (router-configmap.yaml, @c8s_reconnect). Connection: close is also set for
// a client that talks to the forwarder directly.
const reconnectStatus = 590

const reconnectMessage = "the allowlist bound changed: open a new connection and attest again"

func refuseReconnect(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	http.Error(w, reconnectMessage, reconnectStatus)
}

// newLBForwarder streams front-door requests nginx hands over in pinned mode
// to the upstream, through the backend's stamp-checking transport. A request
// is refused when the client's connection predates the router's last view of
// a widened bound, since its attest-lb check may have seen the older bound.
// A request in flight when the bound changes is cancelled: a streamed
// response (SSE, token streams) is cut off, and the client must reconnect
// and attest again.
func newLBForwarder(fence *rollout, backend *HTTPBackend, log *slog.Logger) (http.Handler, error) {
	target, err := url.Parse(backend.base)
	if err != nil {
		return nil, err
	}
	proxy := &httputil.ReverseProxy{
		Transport:     backend.client.Transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.Out.Header["X-Forwarded-Proto"] = pr.In.Header["X-Forwarded-Proto"]
			pr.Out.Header.Del(connectionTimeHeader)
			pr.Out.Header.Del(verifiedStateHeader)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(context.Cause(r.Context()), errBoundChanged) {
				log.Info("front-door forward cancelled: the allowlist bound changed", "path", r.URL.Path)
				refuseReconnect(w)
				return
			}
			log.Warn("front-door forward failed", "path", r.URL.Path, "error", err)
			http.Error(w, "backend error", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		age, err := strconv.ParseFloat(r.Header.Get(connectionTimeHeader), 64)
		// Written as a positive range so NaN, which fails every comparison, is refused.
		if err != nil || !(age >= 0 && age <= maxConnectionAge.Seconds()) {
			http.Error(w, "missing connection time", http.StatusForbidden)
			return
		}
		// Taken before the fence check, so a bound change after it still
		// cancels the forward.
		ctx, cancel := fence.requestContext(r.Context())
		defer cancel()
		now := time.Now()
		if !fence.admitsConnection(now.Add(-time.Duration(age*float64(time.Second))), now) {
			refuseReconnect(w)
			return
		}
		// Opt-in: a client that sends no header is served as before; one that
		// sends a state other than the current head must re-verify.
		if got := r.Header.Get(verifiedStateHeader); got != "" && got != fence.currentHead() {
			http.Error(w, "state changed: re-verify", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}
