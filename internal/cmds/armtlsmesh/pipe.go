//go:build linux

package armtlsmesh

// Carrying one connection's bytes: the endpoint copies in both directions
// until one side ends, and a copy that failed resets its peer rather than
// closing it cleanly — a FIN after a failed copy would let the peer read a
// cut-short stream as complete.
//
// Every connection carried here is captured TCP, either as a *net.TCPConn or
// as a *tls.Conn over one.

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
)

// pipeConns copies between a and b until both directions end.
func pipeConns(pool *bufPool, a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		copyDir(pool, b, a)
	}()
	go func() {
		defer wg.Done()
		copyDir(pool, a, b)
	}()
	wg.Wait()
}

// copyDir carries one direction to its end: a failed copy resets dst, and a
// complete one half-closes it so the peer reads the end of the stream.
func copyDir(pool *bufPool, dst, src net.Conn) {
	buf := pool.get()
	defer pool.put(buf)
	if _, err := io.CopyBuffer(dst, src, *buf); err != nil {
		abort(dst)
		return
	}
	if err := closeWrite(dst); err != nil {
		abort(dst)
	}
}

// copyBufferSize is what one direction of a connection copies through.
const copyBufferSize = 32 * 1024

// bufPool hands out those buffers, so a connection's copy never allocates one
// of its own.
type bufPool struct {
	pool sync.Pool
}

func newBufPool() *bufPool {
	return &bufPool{pool: sync.Pool{New: func() any {
		buf := make([]byte, copyBufferSize)
		return &buf
	}}}
}

func (p *bufPool) get() *[]byte {
	return p.pool.Get().(*[]byte)
}

func (p *bufPool) put(buf *[]byte) {
	p.pool.Put(buf)
}

// closeWrite half-closes the connections this endpoint carries: a TLS
// connection sends close_notify, a TCP one a FIN.
func closeWrite(c net.Conn) error {
	if wrapped, isTLS := c.(*tls.Conn); isTLS {
		return wrapped.CloseWrite()
	}
	return c.(*net.TCPConn).CloseWrite()
}

// abort ends a connection without a graceful close: tls.Conn.Close sends
// close_notify, so the transport is closed under it, and SO_LINGER 0 makes the
// peer see an RST rather than a FIN.
func abort(c net.Conn) {
	if wrapped, isTLS := c.(*tls.Conn); isTLS {
		c = wrapped.NetConn()
	}
	reset(c.(*net.TCPConn))
}

// reset discards the send buffer and closes, so the peer reads an RST.
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}
