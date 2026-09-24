package cdsattest

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"
)

// connectionTimeHeader carries nginx's $connection_time: how long the client's
// front-door connection has been open when the request arrived.
const connectionTimeHeader = "X-C8s-Connection-Time"

// newLBForwarder streams front-door requests nginx hands over in pinned mode
// to the upstream, through the backend's stamp-checking transport. A request
// is refused when the client's connection predates the router's last view of
// a widened bound, since its attest-lb check may have seen the older bound.
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
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Warn("front-door forward failed", "path", r.URL.Path, "error", err)
			http.Error(w, "backend error", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		age, err := strconv.ParseFloat(r.Header.Get(connectionTimeHeader), 64)
		if err != nil || age < 0 {
			http.Error(w, "missing connection time", http.StatusForbidden)
			return
		}
		now := time.Now()
		if !fence.admitsConnection(now.Add(-time.Duration(age*float64(time.Second))), now) {
			http.Error(w, "the allowlist bound changed: open a new connection and attest again", http.StatusServiceUnavailable)
			return
		}
		proxy.ServeHTTP(w, r)
	}), nil
}
