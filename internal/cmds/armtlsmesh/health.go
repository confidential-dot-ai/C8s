//go:build linux

package armtlsmesh

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// healthServer exposes /live, /ready, and /metrics on a dedicated admin port.
// certGate is the readiness slice of [armtls.CertManager]. It is an interface
// so /ready can be exercised without minting short-lived certificates and
// sleeping past their expiry.
type certGate interface {
	// CertReady reports that a certificate was provisioned at least once.
	CertReady() bool
	// CertUsable reports that the cached certificate is still inside its
	// validity window, i.e. that a handshake would actually succeed.
	CertUsable() bool
}

type healthServer struct {
	ready                atomic.Bool
	metrics              *metrics
	mux                  *http.ServeMux
	serverCertMgr        certGate
	clientCertMgr        certGate // nil if no mTLS
	acceptErrorThreshold int64
	readTimeout          time.Duration
	writeTimeout         time.Duration
}

func newHealthServer(m *metrics, serverCertMgr, clientCertMgr *armtls.CertManager, acceptErrorThreshold int64, readTimeout, writeTimeout time.Duration) *healthServer {
	h := &healthServer{
		metrics:              m,
		acceptErrorThreshold: acceptErrorThreshold,
		readTimeout:          readTimeout,
		writeTimeout:         writeTimeout,
	}
	// Assign through the concrete type so a nil manager stays a nil interface
	// rather than a non-nil interface holding a nil pointer.
	if serverCertMgr != nil {
		h.serverCertMgr = serverCertMgr
	}
	if clientCertMgr != nil {
		h.clientCertMgr = clientCertMgr
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /live", h.handleLive)
	mux.HandleFunc("GET /ready", h.handleReady)
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	h.mux = mux
	return h
}

func (h *healthServer) handleLive(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok\n"))
}

func (h *healthServer) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !h.ready.Load() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	// Gate on cert provisioning: don't accept traffic until we can serve TLS.
	// CertReady is sticky, so it only covers startup; CertUsable covers the
	// terminal state where rotation has failed past NotAfter and the manager
	// refuses to hand the expired cert to a handshake. Without the second
	// gate such a pod stays in the endpoint list and blackholes every
	// connection routed to it.
	if h.serverCertMgr != nil {
		if !h.serverCertMgr.CertReady() {
			http.Error(w, "server cert not provisioned", http.StatusServiceUnavailable)
			return
		}
		if !h.serverCertMgr.CertUsable() {
			http.Error(w, "server cert outside its validity window", http.StatusServiceUnavailable)
			return
		}
	}
	if h.clientCertMgr != nil {
		if !h.clientCertMgr.CertReady() {
			http.Error(w, "client cert not provisioned", http.StatusServiceUnavailable)
			return
		}
		if !h.clientCertMgr.CertUsable() {
			http.Error(w, "client cert outside its validity window", http.StatusServiceUnavailable)
			return
		}
	}
	// Degrade readiness if either accept loop is in sustained failure.
	if h.metrics.acceptConsecutiveInbound.Load() >= h.acceptErrorThreshold ||
		h.metrics.acceptConsecutiveOutbound.Load() >= h.acceptErrorThreshold {
		http.Error(w, "accept loop degraded", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ready\n"))
}

// serve binds addr, or adopts the pre-bound ln when non-nil, and serves
// until ctx is cancelled.
func (h *healthServer) serve(ctx context.Context, addr string, ln net.Listener) error {
	srv := &http.Server{
		Handler:      h.mux,
		ReadTimeout:  durOrDefault(h.readTimeout, 5*time.Second),
		WriteTimeout: durOrDefault(h.writeTimeout, 10*time.Second),
		IdleTimeout:  60 * time.Second,
	}
	if ln == nil {
		var err error
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
	}
	return serveHTTP(ctx, srv, ln)
}

// serveHTTP serves srv on ln until ctx is cancelled.
func serveHTTP(ctx context.Context, srv *http.Server, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}
