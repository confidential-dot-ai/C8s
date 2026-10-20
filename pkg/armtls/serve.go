package armtls

import (
	"context"
	"crypto"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/netutil"
)

// serveWarmUpTimeout bounds provisioning the first serving certificate.
const serveWarmUpTimeout = 30 * time.Second

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

// Serve serves srv over armTLS on srv.Addr until ctx is done, then shuts it
// down. It provisions the serving certificate from cfg before binding, so the
// first request doesn't race a cold cert manager, and records each
// connection's certificate for ServingKey. maxConns > 0 caps accepted
// sockets; every connection costs a handshake before any request is read.
//
// Serve owns srv.TLSConfig, srv.ConnContext and srv.ConnState; they must be
// unset.
func Serve(ctx context.Context, srv *http.Server, cfg *ServerConfig, maxConns int) error {
	return ServeListener(ctx, nil, srv, cfg, maxConns)
}

// ServeListener is Serve over ln, which the caller bound; a test binds
// 127.0.0.1:0 so it knows the port before the server accepts. A nil ln binds
// srv.Addr after the certificate warm-up, as Serve does.
func ServeListener(ctx context.Context, ln net.Listener, srv *http.Server, cfg *ServerConfig, maxConns int) error {
	if srv.TLSConfig != nil || srv.ConnContext != nil || srv.ConnState != nil {
		return errors.New("armtls.Serve: srv.TLSConfig, ConnContext and ConnState must be unset")
	}
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
		ln, err = net.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", srv.Addr, err)
		}
	}
	if maxConns > 0 {
		ln = netutil.LimitListener(ln, maxConns)
	}

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
