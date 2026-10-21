package testutil

// A member backend as a test reaches it: its own mesh endpoint answers the
// mesh protocol and carries plain HTTP inside the connection. net/http serves
// nothing over a *tls.Conn whose negotiated protocol it does not know, so the
// connection is handed to a server of its own as a plain one.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// ServeMeshBackend turns an unstarted test server into a member backend: it
// presents leaf on the mesh profile and serves its handler inside the mesh
// protocol. The caller starts it with StartTLS.
func ServeMeshBackend(srv *httptest.Server, leaf tls.Certificate) {
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{leaf},
		ClientAuth:   tls.RequireAnyClientCert,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{armtls.MeshALPN},
	}
	srv.Config.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){
		armtls.MeshALPN: serveInsideMeshALPN,
	}
}

// MeshPeer is the leaf the client presented on the mesh connection carrying
// r, which the plain request inside it does not carry. It is nil on any other
// connection.
func MeshPeer(r *http.Request) *x509.Certificate {
	peer, _ := r.Context().Value(meshPeerKey{}).(*x509.Certificate)
	return peer
}

type meshPeerKey struct{}

// serveInsideMeshALPN returns when the connection closes: the server above
// closes one its protocol handler has returned from.
func serveInsideMeshALPN(srv *http.Server, conn *tls.Conn, handler http.Handler) {
	var peer *x509.Certificate
	if presented := conn.ConnectionState().PeerCertificates; len(presented) > 0 {
		peer = presented[0]
	}
	inside := &http.Server{
		Handler:  handler,
		ErrorLog: srv.ErrorLog,
		ConnContext: func(ctx context.Context, _ net.Conn) context.Context {
			return context.WithValue(ctx, meshPeerKey{}, peer)
		},
	}
	carried := &meshConn{Conn: conn, closed: make(chan struct{})}
	_ = inside.Serve(&singleConn{conn: carried})
}

// meshConn is the connection as the server inside the mesh protocol sees it:
// a plain one, which reports its own close to the listener below.
type meshConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *meshConn) Close() error {
	c.once.Do(func() {
		close(c.closed)
	})
	return c.Conn.Close()
}

// singleConn hands a server the one connection it was built around, and holds
// it there until that connection closes.
type singleConn struct {
	conn   *meshConn
	served bool
}

func (l *singleConn) Accept() (net.Conn, error) {
	if l.served {
		<-l.conn.closed
		return nil, net.ErrClosed
	}
	l.served = true
	return l.conn, nil
}

func (l *singleConn) Close() error {
	return nil
}

func (l *singleConn) Addr() net.Addr {
	return l.conn.LocalAddr()
}
