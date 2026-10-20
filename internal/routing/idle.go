package routing

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

var errIdle = errors.New("no data moved within the backend timeout")

// idleExchange wraps a routing listener request so it fails only once no
// data has moved either way for timeout: reading the client's body, or
// writing to the client, restarts the clock, as does either direction of an
// upgraded connection. A client that keeps sending or reading is never cut
// off, however slow. stop releases the timer and clears
// the write deadline, which would otherwise outlive the request on a
// kept-alive connection.
func idleExchange(w http.ResponseWriter, r *http.Request, timeout time.Duration) (_ http.ResponseWriter, _ *http.Request, stop func()) {
	ctx, cancel := context.WithCancelCause(r.Context())
	timer := time.AfterFunc(timeout, func() { cancel(errIdle) })
	touch := func() { timer.Reset(timeout) }
	r = r.WithContext(ctx)
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = idleBody{ReadCloser: r.Body, touch: touch}
	}
	iw := &idleWriter{ResponseWriter: w, rc: http.NewResponseController(w), timeout: timeout, touch: touch}
	return iw, r, func() {
		timer.Stop()
		cancel(nil)
		_ = iw.rc.SetWriteDeadline(time.Time{})
	}
}

type idleBody struct {
	io.ReadCloser
	touch func()
}

func (b idleBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.touch()
	}
	return n, err
}

// idleWriter pushes the connection's write deadline forward before each
// write, so a client that stops reading fails the write instead of holding
// the handler.
type idleWriter struct {
	http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
	touch   func()
}

func (w *idleWriter) Write(p []byte) (int, error) {
	// A writer without deadlines (a test recorder) still gets the idle
	// context.
	_ = w.rc.SetWriteDeadline(time.Now().Add(w.timeout))
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.touch()
	}
	return n, err
}

// Hijack hands ReverseProxy the client connection for a protocol upgrade.
// Its traffic either way restarts the clock; once it stops, the idle context
// makes ReverseProxy close both ends.
func (w *idleWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := w.rc.Hijack()
	if err != nil {
		return nil, nil, err
	}
	// Clear the deadline the last Write left behind.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, nil, err
	}
	return &idleConn{Conn: conn, timeout: w.timeout, touch: w.touch}, brw, nil
}

// idleConn is an upgraded connection that restarts the idle clock on traffic
// and fails a write the client does not drain within timeout.
type idleConn struct {
	net.Conn
	timeout time.Duration
	touch   func()
}

func (c *idleConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleConn) Write(p []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return 0, err
	}
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.touch()
	}
	return n, err
}

// Unwrap lets ReverseProxy flush through the wrapper.
func (w *idleWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
