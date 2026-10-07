//go:build linux

package armtlsmesh

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Resolver maps pod IPs to node IPs for routing armTLS connections.
type Resolver interface {
	Resolve(podIP string) (nodeIP string, local bool)
	// ValidateOutboundDest reports whether ip is a known pod destination
	// allowed to enter the outbound proxy through iptables REDIRECT. When
	// false, reason is a short label suitable for the outbound-reject
	// metric (host_addr / unknown_pod).
	ValidateOutboundDest(ip string) (ok bool, reason string)
	// ValidateLocalDest returns true if ip is a valid destination for
	// inbound traffic on this node (i.e. a pod running here).
	ValidateLocalDest(ip string) bool
}

// Proxy is a transparent L4 TCP proxy that wraps pod traffic in armTLS
// mTLS. Outbound (:15001) intercepts app traffic and initiates armTLS to the
// destination node. Inbound (:15006) accepts armTLS from peer nodes and delivers
// to the local pod.
type Proxy struct {
	outboundAddr string
	inboundAddr  string
	// outboundLn/inboundLn, when non-nil, are served instead of binding the
	// Addr strings; tests hand over pre-bound listeners.
	outboundLn  net.Listener
	inboundLn   net.Listener
	serverTLS   *tls.Config
	clientTLS   *tls.Config
	nodeIP      string
	inboundPort int
	resolver    Resolver
	origDstFunc func(net.Conn) (string, error)
	logger      *slog.Logger
	metrics     *metrics
	accessLog   bool

	dialTimeout       time.Duration
	tlsDialTimeout    time.Duration
	destHeaderTimeout time.Duration
	drainTimeout      time.Duration
	keepAlive         time.Duration
	idleTimeout       time.Duration

	maxDestHeaderSize int
	pipeBufferSize    int
	bufPool           *sync.Pool

	connSem        chan struct{} // nil = unlimited
	maxConnsPerSrc int           // 0 = unlimited
	srcConnsMu     sync.Mutex
	srcConns       map[string]*atomic.Int64
	onReady        func()
	onShutdown     func()
	activeConns    sync.WaitGroup
	nextConnID     atomic.Uint64
}

func durOrDefault(d, fallback time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return fallback
}

func intOrDefault(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// accessLogEntry holds flat fields for a structured per-connection access log.
type accessLogEntry struct {
	connID       uint64
	dir          string // "inbound", "outbound", "outbound_same_node"
	src          string
	dst          string
	node         string // destination node address (outbound-armtls only)
	local        string // local listener address
	bytesFwd     int64
	bytesRev     int64
	dur          time.Duration
	tlsHandshake time.Duration
	ttfb         time.Duration // time to first byte (accept → pipe start)
	certMode     string        // "self-signed" or "cds"
	result       string        // success, route_error, dial_error, tls_error, header_error, dest_rejected
	err          string
}

// logTo emits the access log entry via slog.Info if access logging is enabled.
func (e *accessLogEntry) logTo(log *slog.Logger, enabled bool) {
	if !enabled {
		return
	}
	attrs := []any{
		"conn_id", e.connID,
		"dir", e.dir,
		"src", e.src,
		"dst", e.dst,
		"bytes_fwd", e.bytesFwd,
		"bytes_rev", e.bytesRev,
		"dur", e.dur.Round(time.Microsecond),
		"cert_mode", e.certMode,
		"result", e.result,
	}
	if e.node != "" {
		attrs = append(attrs, "node", e.node)
	}
	if e.local != "" {
		attrs = append(attrs, "local", e.local)
	}
	if e.tlsHandshake > 0 {
		attrs = append(attrs, "tls_handshake", e.tlsHandshake.Round(time.Microsecond))
	}
	if e.ttfb > 0 {
		attrs = append(attrs, "ttfb", e.ttfb.Round(time.Microsecond))
	}
	if e.err != "" {
		attrs = append(attrs, "error", e.err)
	}
	log.Info("access", attrs...)
}

// certModeStr returns the current certificate mode as a string.
func (p *Proxy) certModeStr() string {
	if p.metrics.certMode.Load() == 1 {
		return "cds"
	}
	return "self-signed"
}

// Run starts both listeners and blocks until ctx is cancelled. On shutdown it
// waits for in-flight connections to drain (up to drainTimeout).
func (p *Proxy) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 2)
	outReady := make(chan struct{})
	inReady := make(chan struct{})

	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := p.serve(ctx, p.outboundAddr, p.outboundLn, nil, p.handleOutbound, outReady, &p.metrics.acceptConsecutiveOutbound); err != nil {
			errCh <- fmt.Errorf("outbound: %w", err)
		}
	}()
	go func() {
		defer wg.Done()
		if err := p.serve(ctx, p.inboundAddr, p.inboundLn, p.serverTLS, p.handleInbound, inReady, &p.metrics.acceptConsecutiveInbound); err != nil {
			errCh <- fmt.Errorf("inbound: %w", err)
		}
	}()

	// Signal readiness after both listeners are bound.
	go func() {
		<-outReady
		<-inReady
		if p.onReady != nil {
			p.onReady()
		}
	}()

	<-ctx.Done()

	// Signal not-ready immediately so K8s stops routing traffic.
	if p.onShutdown != nil {
		p.onShutdown()
	}

	// Wait for listeners to close.
	wg.Wait()

	// Drain active connections with timeout.
	done := make(chan struct{})
	go func() { p.activeConns.Wait(); close(done) }()

	select {
	case <-done:
		p.logger.Info("all connections drained")
	case <-time.After(durOrDefault(p.drainTimeout, 30*time.Second)):
		p.logger.Warn("drain timeout exceeded, forcing shutdown")
	}

	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

// serve is the generic listen/accept loop. ln, when non-nil, is served
// instead of binding addr. If tlsCfg is non-nil the listener is wrapped with
// TLS. The ready channel is closed once the listener is acquired.
// consecutiveErrors is an atomic counter exposed as a metric for readiness gating.
func (p *Proxy) serve(ctx context.Context, addr string, ln net.Listener, tlsCfg *tls.Config, handler func(context.Context, net.Conn), ready chan<- struct{}, consecutiveErrors *atomic.Int64) error {
	if ln == nil {
		var err error
		ln, err = (&net.ListenConfig{
			KeepAlive: durOrDefault(p.keepAlive, 30*time.Second),
		}).Listen(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}

	p.logger.Info("listener ready", "addr", ln.Addr(), "tls", tlsCfg != nil)
	close(ready)

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			n := consecutiveErrors.Add(1)
			p.metrics.acceptErrors.Inc()
			p.logger.Warn("accept error", "addr", ln.Addr(), "error", err, "consecutive", n)

			// Exponential backoff: 5ms, 10ms, 20ms, … capped at 640ms.
			backoff := 5 * time.Millisecond
			for i := int64(1); i < n && i < 8; i++ {
				backoff *= 2
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		consecutiveErrors.Store(0)

		// Global connection limit: reject if at capacity.
		if p.connSem != nil {
			select {
			case p.connSem <- struct{}{}:
			default:
				p.metrics.connLimitRejected.Inc()
				p.logger.Warn("connection limit reached", "addr", addr)
				conn.Close()
				continue
			}
		}

		// Per-source connection limit: reject if a single source exceeds its budget.
		var (
			srcKey string
			srcCnt *atomic.Int64
		)
		if p.maxConnsPerSrc > 0 {
			srcKey, _, _ = net.SplitHostPort(conn.RemoteAddr().String())
			if srcKey == "" {
				srcKey = conn.RemoteAddr().String()
			}
			cnt, ok := p.tryAcquireSrc(srcKey)
			if !ok {
				p.metrics.connLimitPerSourceRejected.Inc()
				p.logger.Warn("per-source connection limit reached", "src", srcKey, "addr", addr)
				if p.connSem != nil {
					<-p.connSem
				}
				conn.Close()
				continue
			}
			srcCnt = cnt
		}

		p.activeConns.Add(1)
		go func() {
			defer func() {
				if srcCnt != nil {
					p.releaseSrc(srcKey, srcCnt)
				}
				if p.connSem != nil {
					<-p.connSem
				}
				p.activeConns.Done()
			}()
			handler(ctx, conn)
		}()
	}
}

func (p *Proxy) handleOutbound(ctx context.Context, downstream net.Conn) {
	defer downstream.Close()
	p.metrics.activeConnections.WithLabelValues("outbound").Inc()
	defer p.metrics.activeConnections.WithLabelValues("outbound").Dec()
	connID := p.nextConnID.Add(1)
	log := p.logger.With("conn", connID)
	start := time.Now()
	cm := p.certModeStr()

	entry := &accessLogEntry{
		connID:   connID,
		src:      downstream.RemoteAddr().String(),
		local:    downstream.LocalAddr().String(),
		certMode: cm,
		result:   "success",
	}
	defer func() {
		entry.dur = time.Since(start)
		p.metrics.connectionDuration.WithLabelValues(entry.dir, cm).Observe(entry.dur.Seconds())
		entry.logTo(log, p.accessLog)
	}()

	origDst, err := p.origDstFunc(downstream)
	if err != nil {
		p.metrics.routeErrors.Inc()
		entry.dir = "outbound"
		entry.result = "route_error"
		entry.err = err.Error()
		log.Warn("failed to get original destination", "error", err)
		return
	}
	entry.dst = origDst

	host, _, err := net.SplitHostPort(origDst)
	if err != nil {
		p.metrics.routeErrors.Inc()
		entry.dir = "outbound"
		entry.result = "route_error"
		entry.err = err.Error()
		log.Warn("invalid original destination", "dst", origDst, "error", err)
		return
	}
	if ok, reason := p.resolver.ValidateOutboundDest(host); !ok {
		p.metrics.recordOutboundDestRejected(reason)
		entry.dir = "outbound"
		entry.result = "dest_rejected"
		entry.err = "destination is not a known pod IP"
		log.Warn("outbound destination rejected: not a known pod IP", "dst", origDst, "reason", reason)
		return
	}

	nodeIP, local := p.resolver.Resolve(host)

	entry.dir = "outbound"
	if local {
		entry.dir = "outbound_same_node"
	}
	// Even on the same-node path we dial nodeIP (not 127.0.0.1): the inbound
	// listener binds the host netns under hostNetwork: true, the dial reaches
	// it via the kernel's local-routing path, and the armTLS handshake stays
	// uniform across local/remote so attestation is the only thing that gates
	// byte relay. The old plaintext same-node shortcut is gone — see
	// DESIGN.md "Local vs remote path".
	remoteAddr := net.JoinHostPort(nodeIP, strconv.Itoa(p.inboundPort))
	entry.node = remoteAddr
	pipeStart := time.Now()
	fwd, rev, tlsDur := p.dialAndPipeARMTLS(ctx, downstream, remoteAddr, origDst, log)
	entry.ttfb = pipeStart.Sub(start)
	entry.tlsHandshake = tlsDur
	entry.bytesFwd = fwd.N
	entry.bytesRev = rev.N
	if fwd.Err != nil || rev.Err != nil {
		if tlsDur == 0 {
			entry.result = "tls_error"
		} else {
			entry.result = "dial_error"
		}
		if fwd.Err != nil {
			entry.err = fwd.Err.Error()
		} else {
			entry.err = rev.Err.Error()
		}
	}
	if tlsDur > 0 {
		p.metrics.tlsHandshakeDuration.WithLabelValues(entry.dir, cm).Observe(tlsDur.Seconds())
	}
	p.metrics.timeToFirstByte.WithLabelValues(entry.dir, cm).Observe(entry.ttfb.Seconds())
	p.recordOutbound(fwd, rev, local)
}

// dialAndPipeARMTLS dials via armTLS, sends the destination header, then pipes.
// Returns the TLS handshake duration as the third value (zero if handshake failed).
func (p *Proxy) dialAndPipeARMTLS(ctx context.Context, downstream net.Conn, remoteAddr, destHeader string, log *slog.Logger) (fwd, rev pipeResult, tlsHandshakeDur time.Duration) {
	tlsStart := time.Now()
	upstream, err := (&tls.Dialer{
		Config: p.clientTLS,
		NetDialer: &net.Dialer{
			Timeout:   durOrDefault(p.tlsDialTimeout, 10*time.Second),
			KeepAlive: durOrDefault(p.keepAlive, 30*time.Second),
		},
	}).DialContext(ctx, "tcp", remoteAddr)
	if err != nil {
		p.metrics.tlsDialFailures.Inc()
		log.Warn("armTLS dial failed", "node", remoteAddr, "error", err)
		fwd.Err = err
		rev.Err = err
		return
	}
	tlsHandshakeDur = time.Since(tlsStart)
	defer upstream.Close()

	if tlsConn, ok := upstream.(*tls.Conn); ok && tlsConn.ConnectionState().DidResume {
		p.metrics.tlsSessionResumptions.Inc()
	}

	if _, err := fmt.Fprintf(upstream, "%s\n", destHeader); err != nil {
		p.metrics.destHeaderErrors.WithLabelValues("write").Inc()
		log.Warn("destination header write failed", "error", err)
		fwd.Err = err
		rev.Err = err
		return
	}

	fwd, rev = p.pipe(p.wrapIdle(downstream), p.wrapIdle(upstream))
	return
}

func (p *Proxy) handleInbound(ctx context.Context, downstream net.Conn) {
	defer downstream.Close()
	p.metrics.activeConnections.WithLabelValues("inbound").Inc()
	defer p.metrics.activeConnections.WithLabelValues("inbound").Dec()
	connID := p.nextConnID.Add(1)
	log := p.logger.With("conn", connID)
	start := time.Now()
	cm := p.certModeStr()

	entry := &accessLogEntry{
		connID:   connID,
		dir:      "inbound",
		src:      downstream.RemoteAddr().String(),
		local:    downstream.LocalAddr().String(),
		certMode: cm,
		result:   "success",
	}
	defer func() {
		entry.dur = time.Since(start)
		p.metrics.connectionDuration.WithLabelValues("inbound", cm).Observe(entry.dur.Seconds())
		entry.logTo(log, p.accessLog)
	}()

	// Bounded read with deadline to prevent slow-loris and OOM.
	if err := downstream.SetReadDeadline(time.Now().Add(durOrDefault(p.destHeaderTimeout, 5*time.Second))); err != nil {
		log.Warn("failed to set read deadline", "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	// Bound the header read so ReadString cannot allocate beyond the limit,
	// even if a malicious peer sends infinite bytes without '\n'.
	maxHeader := intOrDefault(p.maxDestHeaderSize, 256)
	lr := &io.LimitedReader{R: downstream, N: int64(maxHeader + 1)}
	reader := bufio.NewReader(lr)
	dstLine, err := reader.ReadString('\n')
	if err != nil {
		p.metrics.destHeaderErrors.WithLabelValues("read").Inc()
		log.Warn("failed to read destination header", "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	if len(dstLine) > maxHeader {
		p.metrics.destHeaderErrors.WithLabelValues("read").Inc()
		log.Warn("destination header too large", "size", len(dstLine))
		entry.result = "header_error"
		entry.err = "header too large"
		return
	}

	// Lift the read limit for the relay phase. Any bytes already buffered
	// by reader are preserved; subsequent reads go to downstream via lr.
	lr.N = math.MaxInt64

	// Clear deadline for the data relay phase.
	if err := downstream.SetReadDeadline(time.Time{}); err != nil {
		log.Warn("failed to clear read deadline", "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	dst := strings.TrimSpace(dstLine)
	entry.dst = dst
	host, _, err := net.SplitHostPort(dst)
	if err != nil {
		p.metrics.destHeaderErrors.WithLabelValues("read").Inc()
		log.Warn("invalid destination header", "dst", dst, "error", err)
		entry.result = "header_error"
		entry.err = err.Error()
		return
	}

	if !p.resolver.ValidateLocalDest(host) {
		p.metrics.inboundDestRejected.Inc()
		log.Warn("inbound destination rejected: not a local pod", "dst", dst)
		entry.result = "dest_rejected"
		return
	}

	pipeStart := time.Now()
	upstream, err := (&net.Dialer{
		Timeout:   durOrDefault(p.dialTimeout, 5*time.Second),
		KeepAlive: durOrDefault(p.keepAlive, 30*time.Second),
	}).DialContext(ctx, "tcp", dst)
	if err != nil {
		p.metrics.dialFailures.Inc()
		log.Warn("local pod dial failed", "dst", dst, "error", err)
		entry.result = "dial_error"
		entry.err = err.Error()
		return
	}
	defer upstream.Close()

	entry.ttfb = pipeStart.Sub(start)
	p.metrics.timeToFirstByte.WithLabelValues("inbound", cm).Observe(entry.ttfb.Seconds())

	fwd, rev := p.pipe(p.wrapIdle(&bufferedConn{downstream, reader}), p.wrapIdle(upstream))
	entry.bytesFwd = fwd.N
	entry.bytesRev = rev.N
	if fwd.Err != nil || rev.Err != nil {
		entry.result = "dial_error"
		if fwd.Err != nil {
			entry.err = fwd.Err.Error()
		} else {
			entry.err = rev.Err.Error()
		}
	}
	p.recordInbound(fwd, rev)
}

func (p *Proxy) recordOutbound(fwd, rev pipeResult, local bool) {
	p.metrics.bytesTotal.WithLabelValues("outbound", "forward").Add(float64(fwd.N))
	p.metrics.bytesTotal.WithLabelValues("outbound", "reverse").Add(float64(rev.N))
	if local {
		if fwd.Err != nil || rev.Err != nil {
			p.metrics.connectionsTotal.WithLabelValues("outbound_same_node", "error").Inc()
		} else {
			p.metrics.connectionsTotal.WithLabelValues("outbound_same_node", "success").Inc()
		}
		return
	}
	if fwd.Err != nil || rev.Err != nil {
		p.metrics.connectionsTotal.WithLabelValues("outbound", "error").Inc()
	} else {
		p.metrics.connectionsTotal.WithLabelValues("outbound", "success").Inc()
	}
}

func (p *Proxy) recordInbound(fwd, rev pipeResult) {
	p.metrics.bytesTotal.WithLabelValues("inbound", "forward").Add(float64(fwd.N))
	p.metrics.bytesTotal.WithLabelValues("inbound", "reverse").Add(float64(rev.N))
	if fwd.Err != nil || rev.Err != nil {
		p.metrics.connectionsTotal.WithLabelValues("inbound", "error").Inc()
	} else {
		p.metrics.connectionsTotal.WithLabelValues("inbound", "success").Inc()
	}
}

// wrapIdle wraps a connection with idle timeout if configured.
func (p *Proxy) wrapIdle(c net.Conn) net.Conn {
	if p.idleTimeout > 0 {
		return &idleConn{Conn: c, idle: p.idleTimeout}
	}
	return c
}

// idleConn resets read/write deadlines on every I/O operation. If no data
// flows for the configured duration, the OS closes the connection.
type idleConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleConn) Read(b []byte) (int, error) {
	if err := c.SetReadDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *idleConn) Write(b []byte) (int, error) {
	if err := c.SetWriteDeadline(time.Now().Add(c.idle)); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// bufferedConn wraps a net.Conn with a bufio.Reader so bytes consumed while
// reading the destination header are not lost.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

var _ net.Conn = (*bufferedConn)(nil)

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

// CloseWrite forwards the half-close to the wrapped connection. Without it
// the CloseWrite type assertion in pipe fails on the wrapper and an upstream
// FIN is never propagated to the peer.
func (c *bufferedConn) CloseWrite() error { return closeWrite(c.Conn) }

// CloseWrite forwards the half-close to the wrapped connection (see
// bufferedConn.CloseWrite).
func (c *idleConn) CloseWrite() error { return closeWrite(c.Conn) }

// closeWrite half-closes c if it supports it (*net.TCPConn, *tls.Conn, or one
// of our wrappers). Other connections are left untouched; the caller closes
// them once both pipe directions are done.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// abort resets c without a graceful close. It unwraps our wrappers and
// *tls.Conn to the transport, because tls.Conn.Close sends close_notify, and
// sets SO_LINGER 0 on TCP so the peer sees an RST rather than a FIN.
func abort(c net.Conn) {
	for {
		switch w := c.(type) {
		case *idleConn:
			c = w.Conn
		case *bufferedConn:
			c = w.Conn
		case *tls.Conn:
			c = w.NetConn()
		default:
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetLinger(0)
			}
			_ = c.Close()
			return
		}
	}
}

// pipeResult holds the byte count and error for one direction of a pipe.
type pipeResult struct {
	N   int64
	Err error
}

func newBufPool(size int) *sync.Pool {
	if size <= 0 {
		size = 32 * 1024
	}
	return &sync.Pool{
		New: func() any {
			b := make([]byte, size)
			return &b
		},
	}
}

// tryAcquireSrc reserves a slot for srcIP under the maxConnsPerSrc budget.
// On success returns the counter that the caller must hand to releaseSrc;
// on failure (limit hit) returns nil, false.
//
// The mutex serialises increment-and-create with releaseSrc's
// decrement-and-delete so no goroutine ever holds a counter that has been
// removed from the map (which would otherwise race connection limits).
func (p *Proxy) tryAcquireSrc(srcIP string) (*atomic.Int64, bool) {
	p.srcConnsMu.Lock()
	defer p.srcConnsMu.Unlock()
	if p.srcConns == nil {
		p.srcConns = make(map[string]*atomic.Int64)
	}
	cnt, ok := p.srcConns[srcIP]
	if !ok {
		cnt = &atomic.Int64{}
		p.srcConns[srcIP] = cnt
	}
	if int(cnt.Add(1)) > p.maxConnsPerSrc {
		cnt.Add(-1)
		return nil, false
	}
	return cnt, true
}

// releaseSrc returns a slot to the budget and removes the map entry when
// the source has no in-flight connections, keeping srcConns bounded.
func (p *Proxy) releaseSrc(srcIP string, cnt *atomic.Int64) {
	p.srcConnsMu.Lock()
	defer p.srcConnsMu.Unlock()
	if cnt.Add(-1) > 0 {
		return
	}
	if existing, ok := p.srcConns[srcIP]; ok && existing == cnt {
		delete(p.srcConns, srcIP)
	}
}

// pipe copies bytes bidirectionally until both directions are done.
func (p *Proxy) pipe(a, b net.Conn) (fwd, rev pipeResult) {
	pool := p.bufPool
	if pool == nil {
		pool = newBufPool(0)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn, r *pipeResult) {
		defer wg.Done()
		bufp := pool.Get().(*[]byte)
		r.N, r.Err = io.CopyBuffer(dst, src, *bufp)
		pool.Put(bufp)
		// INVARIANT: a clean EOF from src is the only thing forwarded as a
		// clean close. A FIN or close_notify after a failed copy would let
		// the peer read a cut-short stream as complete, so reset dst instead.
		if r.Err != nil {
			abort(dst)
			return
		}
		if err := closeWrite(dst); err != nil {
			abort(dst)
		}
	}
	go cp(a, b, &fwd)
	go cp(b, a, &rev)
	wg.Wait()
	return
}
