package armtls

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

// serveWarmUpTimeout bounds provisioning the first serving certificate.
const serveWarmUpTimeout = 30 * time.Second

// ServeAttestBudget is how long a handler under Serve may spend attesting
// within one response; WriteTimeout leaves room for it.
const ServeAttestBudget = 30 * time.Second

// maxServeConns caps accepted sockets. Serve's callers bind every interface,
// and each connection costs an armTLS handshake before any request is read.
const maxServeConns = 64

// newServer states the resource bounds once so they can be asserted: none
// changes a legitimate answer, so a regression is otherwise silent.
func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Allow the bounded body read, attestation, and response write.
		WriteTimeout: ServeAttestBudget + 20*time.Second,
		IdleTimeout:  30 * time.Second,
		// Go's 1MiB default lets one unauthenticated request buy far more
		// memory than any real request needs.
		MaxHeaderBytes: 16 << 10,
	}
}

type servingKeyCtx struct{}

// ServingKey returns the public key of the armTLS certificate that served
// the request's connection, or nil outside Serve.
func ServingKey(ctx context.Context) crypto.PublicKey {
	if f, ok := ctx.Value(servingKeyCtx{}).(func() crypto.PublicKey); ok {
		return f()
	}
	return nil
}

// WithServingKey is for tests of handlers that call ServingKey.
func WithServingKey(ctx context.Context, pub crypto.PublicKey) context.Context {
	return context.WithValue(ctx, servingKeyCtx{}, func() crypto.PublicKey { return pub })
}

// Serve serves handler over armTLS on addr until ctx is done, then shuts it
// down. It provisions the serving certificate from cfg before binding, so the
// first request doesn't race a cold cert manager, and records each
// connection's certificate for ServingKey.
func Serve(ctx context.Context, addr string, handler http.Handler, cfg *ServerConfig) error {
	return ServeListener(ctx, nil, addr, handler, cfg)
}

// ServeListener is Serve over ln, which the caller bound; a test binds
// 127.0.0.1:0 so it knows the port before the server accepts. A nil ln binds
// addr after the certificate warm-up, as Serve does.
func ServeListener(ctx context.Context, ln net.Listener, addr string, handler http.Handler, cfg *ServerConfig) error {
	tlsCfg, certMgr, err := NewServerTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("build armTLS config: %w", err)
	}
	warmCtx, cancelWarm := context.WithTimeout(ctx, serveWarmUpTimeout)
	err = certMgr.WarmUp(warmCtx)
	cancelWarm()
	if err != nil {
		return fmt.Errorf("warm up armTLS serving cert: %w", err)
	}
	go certMgr.RunRotation(ctx)

	var served sync.Map // underlying net.Conn -> crypto.PublicKey
	getCert := tlsCfg.GetCertificate
	tlsCfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := getCert(hello)
		if err == nil {
			// ensureLeaf sets Leaf on every certificate the manager serves.
			served.Store(hello.Conn, cert.Leaf.PublicKey)
		}
		return cert, err
	}
	srv := newServer(addr, handler)
	srv.TLSConfig = tlsCfg
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if tc, ok := c.(*tls.Conn); ok {
			return context.WithValue(ctx, servingKeyCtx{}, func() crypto.PublicKey {
				key, _ := served.Load(tc.NetConn())
				pub, _ := key.(crypto.PublicKey)
				return pub
			})
		}
		return ctx
	}
	srv.ConnState = func(c net.Conn, state http.ConnState) {
		if tc, ok := c.(*tls.Conn); ok && (state == http.StateClosed || state == http.StateHijacked) {
			served.Delete(tc.NetConn())
		}
	}

	if ln == nil {
		ln, err = net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
	}
	ln = netutil.LimitListener(ln, maxServeConns)

	errCh := make(chan error, 1)
	go func() {
		// certs come from tlsCfg (armTLS), so no cert/key files.
		errCh <- srv.ServeTLS(ln, "", "")
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutCtx)
	case err := <-errCh:
		return err
	}
}
