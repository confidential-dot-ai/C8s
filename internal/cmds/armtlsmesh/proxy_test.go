//go:build linux

package armtlsmesh

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"

	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/attestclient"
)

// histogramSampleCount returns h's observation count via the dto protocol;
// testutil.ToFloat64 doesn't work on Histograms.
func histogramSampleCount(h prometheus.Observer) uint64 {
	hist, ok := h.(prometheus.Histogram)
	if !ok {
		return 0
	}
	pb := &dto.Metric{}
	if err := hist.Write(pb); err != nil {
		return 0
	}
	return pb.Histogram.GetSampleCount()
}

// staticResolver treats loopback and the node's own IP as local;
// everything else is remote (using the pod IP as the node address).
// Used only in tests — production requires the k8s resolver.
type staticResolver struct {
	nodeIP string
}

func (r *staticResolver) Resolve(podIP string) (string, bool) {
	if podIP == r.nodeIP || podIP == "127.0.0.1" || podIP == "::1" {
		return r.nodeIP, true
	}
	return podIP, false
}

func (r *staticResolver) ValidateOutboundDest(ip string) (bool, string) { return true, "" }
func (r *staticResolver) ValidateLocalDest(ip string) bool              { return true }

type fixedRemoteResolver struct {
	nodeIP string
}

func (r *fixedRemoteResolver) Resolve(string) (string, bool)              { return r.nodeIP, false }
func (r *fixedRemoteResolver) ValidateOutboundDest(string) (bool, string) { return true, "" }
func (r *fixedRemoteResolver) ValidateLocalDest(string) bool              { return true }

// testTLSConfigs creates mutually-attested server+client TLS configs: both
// sides mint armTLS certs from mockapi evidence and verify the peer
// through the production VerifyPeerCertificate. These tests exercise L4 proxy
// plumbing, not attestation policy, so the policy pins no measurements;
// pinning is covered by the mesh handshake tests.
func testTLSConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()

	stub := mockapi.New(t)
	attestFunc := makeAttestFunc(attestclient.NewClient(""), stub.URL())
	policy := &armtls.VerifyPolicy{AttestationApiURL: stub.URL()}

	serverCfg, _, err := armtls.NewServerTLSConfig(&armtls.ServerConfig{
		Platform:     "sev-snp",
		AttestFunc:   attestFunc,
		DNSNames:     []string{"localhost"},
		CertTTL:      1 * time.Hour,
		ClientPolicy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}

	clientCfg, _, err := armtls.NewClientTLSConfig(&armtls.ClientConfig{
		Policy:     policy,
		Platform:   "sev-snp",
		AttestFunc: attestFunc,
		CertTTL:    1 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	return serverCfg, clientCfg
}

// staticCertProvider serves one fixed certificate through the
// armtls.CertProvider interface, for tests that need the handshake to present
// a specific leaf.
type staticCertProvider struct {
	cert tls.Certificate
}

func (p staticCertProvider) Provision(context.Context) (*tls.Certificate, time.Duration, error) {
	return &p.cert, 0, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testMetrics() *metrics {
	return newMetrics()
}

func assertEventually(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cond() {
		return
	}
	t.Fatal(msg)
}

// startBackend creates a TCP server that echoes "hello from <name>".
func startBackend(t *testing.T, name string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 1024)
				n, _ := conn.Read(buf)
				fmt.Fprintf(conn, "hello from %s (got %q)", name, buf[:n])
			}()
		}
	}()
	return ln.Addr().String()
}

func TestPipe(t *testing.T) {
	// Echo server as the "upstream" end.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	// Proxy that pipes a frontend connection to the echo server.
	frontLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer frontLn.Close()
	go func() {
		front, err := frontLn.Accept()
		if err != nil {
			return
		}
		defer front.Close()
		back, err := net.Dial("tcp", echoLn.Addr().String())
		if err != nil {
			return
		}
		defer back.Close()
		(&Proxy{}).pipe(front, back)
	}()

	// Client sends a message through the pipe and reads it back.
	conn, err := net.Dial("tcp", frontLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := "test message"
	fmt.Fprint(conn, msg)
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestInboundHandler(t *testing.T) {
	backend := startBackend(t, "backend")
	serverTLS, clientTLS := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr: "127.0.0.1:0",
		serverTLS:   serverTLS,
		resolver:    &staticResolver{nodeIP: "127.0.0.1"},
		logger:      testLogger(),
		metrics:     testMetrics(),
	}

	ctx := t.Context()

	// Start inbound listener manually to get the actual port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	defer ln.Close()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Connect as armTLS client, send destination header, then data.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprintf(conn, "%s\n", backend)
	fmt.Fprint(conn, "ping")
	conn.CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from backend (got "ping")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestOutboundLocal(t *testing.T) {
	backend := startBackend(t, "local-pod")
	serverTLS, clientTLS := testTLSConfigs(t)

	host, _, _ := net.SplitHostPort(backend)

	inboundLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inboundLn.Close()
	inboundTLSLn := tls.NewListener(inboundLn, serverTLS)
	_, inboundPortStr, _ := net.SplitHostPort(inboundLn.Addr().String())
	var inboundPort int
	fmt.Sscanf(inboundPortStr, "%d", &inboundPort)

	p := &Proxy{
		nodeIP:      host,
		inboundPort: inboundPort,
		serverTLS:   serverTLS,
		clientTLS:   clientTLS,
		resolver:    &staticResolver{nodeIP: host},
		origDstFunc: func(_ net.Conn) (string, error) { return backend, nil },
		logger:      testLogger(),
		metrics:     testMetrics(),
	}

	ctx := t.Context()

	go func() {
		for {
			conn, err := inboundTLSLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Start outbound listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "ping")
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from local-pod (got "ping")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
	assertEventually(t, time.Second, func() bool {
		return histogramSampleCount(p.metrics.tlsHandshakeDuration.WithLabelValues("outbound_same_node", "self-signed")) > 0
	}, "expected same-node outbound path to perform an armTLS handshake")
}

func TestEndToEnd(t *testing.T) {
	// Simulates: app → node1 outbound → armTLS → node2 inbound → backend.
	backend := startBackend(t, "remote-pod")
	serverTLS, clientTLS := testTLSConfigs(t)

	// Node 2: inbound listener.
	node2Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer node2Ln.Close()
	node2TLSLn := tls.NewListener(node2Ln, serverTLS)
	_, node2PortStr, _ := net.SplitHostPort(node2Ln.Addr().String())

	node2 := &Proxy{logger: testLogger(), metrics: testMetrics(), resolver: &staticResolver{nodeIP: "127.0.0.1"}}
	ctx := t.Context()

	go func() {
		for {
			conn, err := node2TLSLn.Accept()
			if err != nil {
				return
			}
			go node2.handleInbound(ctx, conn)
		}
	}()

	// Node 1: outbound proxy.
	var node2Port int
	fmt.Sscanf(node2PortStr, "%d", &node2Port)

	node1 := &Proxy{
		nodeIP:      "1.1.1.1", // Different from backend host → treated as remote.
		inboundPort: node2Port,
		clientTLS:   clientTLS,
		resolver:    &fixedRemoteResolver{nodeIP: "127.0.0.1"},
		origDstFunc: func(_ net.Conn) (string, error) { return backend, nil },
		logger:      testLogger(),
		metrics:     testMetrics(),
	}

	// The resolver returns node2's listener host for the remote pod. The
	// outbound handler will dial 127.0.0.1:node2Port via armTLS.

	node1Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer node1Ln.Close()

	go func() {
		for {
			conn, err := node1Ln.Accept()
			if err != nil {
				return
			}
			go node1.handleOutbound(ctx, conn)
		}
	}()

	// App connects to node1 outbound.
	conn, err := net.Dial("tcp", node1Ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "e2e-ping")
	conn.(*net.TCPConn).CloseWrite()

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from remote-pod (got "e2e-ping")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestConcurrentConnections(t *testing.T) {
	backend := startBackend(t, "concurrent")
	serverTLS, clientTLS := testTLSConfigs(t)

	inboundLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inboundLn.Close()
	tlsLn := tls.NewListener(inboundLn, serverTLS)

	p := &Proxy{logger: testLogger(), metrics: testMetrics(), resolver: &staticResolver{nodeIP: "127.0.0.1"}}
	ctx := t.Context()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	const n = 10
	var wg sync.WaitGroup
	errs := make([]error, n)

	for i := range n {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			conn, err := tls.Dial("tcp", inboundLn.Addr().String(), clientTLS)
			if err != nil {
				errs[idx] = err
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("msg-%d", idx)
			fmt.Fprintf(conn, "%s\n%s", backend, msg)
			conn.CloseWrite()

			got, err := io.ReadAll(conn)
			if err != nil {
				errs[idx] = err
				return
			}
			want := fmt.Sprintf("hello from concurrent (got %q)", msg)
			if string(got) != want {
				errs[idx] = fmt.Errorf("got %q, want %q", got, want)
			}
		}(i)
	}

	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}

func TestDestHeaderTimeout(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr:       "127.0.0.1:0",
		serverTLS:         serverTLS,
		destHeaderTimeout: 200 * time.Millisecond,
		resolver:          &staticResolver{nodeIP: "127.0.0.1"},
		logger:            testLogger(),
		metrics:           testMetrics(),
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	defer ln.Close()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Connect but never send the destination header.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The server should close the connection after destHeaderTimeout.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed by server, got data")
	}
}

func TestInvalidDestination(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr:       "127.0.0.1:0",
		serverTLS:         serverTLS,
		destHeaderTimeout: 5 * time.Second,
		resolver:          &staticResolver{nodeIP: "127.0.0.1"},
		logger:            testLogger(),
		metrics:           testMetrics(),
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)
	defer ln.Close()

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send an invalid destination header (no port).
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	fmt.Fprint(conn, "no-port\n")
	conn.CloseWrite()

	// Server should reject and close without sending data.
	got, _ := io.ReadAll(conn)
	if len(got) != 0 {
		t.Errorf("expected empty response for invalid dest, got %q", got)
	}
}

func TestGracefulDrain(t *testing.T) {
	backend := startBackend(t, "drain")
	serverTLS, clientTLS := testTLSConfigs(t)

	p := &Proxy{
		inboundAddr:  "127.0.0.1:0",
		serverTLS:    serverTLS,
		drainTimeout: 5 * time.Second,
		resolver:     &staticResolver{nodeIP: "127.0.0.1"},
		logger:       testLogger(),
		metrics:      testMetrics(),
	}

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(ln, serverTLS)

	// Track active connections through the proxy.
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			p.activeConns.Go(func() {
				p.handleInbound(ctx, conn)
			})
		}
	}()

	// Establish a connection that will be in-flight during shutdown.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}

	// Send destination header + data.
	fmt.Fprintf(conn, "%s\n", backend)
	fmt.Fprint(conn, "drain-test")

	// Sleep covers the window between accept and DialContext so cancel()
	// doesn't race the dial; no mid-handler metric advances early enough
	// to gate on.
	time.Sleep(100 * time.Millisecond)

	// Cancel context (simulate shutdown) while connection is active.
	cancel()
	ln.Close()

	// The in-flight connection should still complete.
	conn.CloseWrite()
	got, err := io.ReadAll(conn)
	conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	want := `hello from drain (got "drain-test")`
	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// activeConns should drain within timeout.
	done := make(chan struct{})
	go func() { p.activeConns.Wait(); close(done) }()
	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("active connections did not drain")
	}
}

func TestStaticResolver(t *testing.T) {
	r := &staticResolver{nodeIP: "10.0.0.1"}

	tests := []struct {
		podIP     string
		wantNode  string
		wantLocal bool
	}{
		{"10.0.0.1", "10.0.0.1", true},      // node IP = local
		{"127.0.0.1", "10.0.0.1", true},     // loopback = local
		{"::1", "10.0.0.1", true},           // IPv6 loopback = local
		{"10.244.1.5", "10.244.1.5", false}, // unknown = remote
	}

	for _, tt := range tests {
		nodeIP, local := r.Resolve(tt.podIP)
		if nodeIP != tt.wantNode || local != tt.wantLocal {
			t.Errorf("Resolve(%q) = (%q, %v), want (%q, %v)",
				tt.podIP, nodeIP, local, tt.wantNode, tt.wantLocal)
		}
	}
}

func TestIPv6RemoteAddr(t *testing.T) {
	// Verify that IPv6 node IPs produce valid host:port addresses.
	p := &Proxy{
		inboundPort: 15006,
		nodeIP:      "2001:db8::1",
		resolver:    &staticResolver{nodeIP: "1.1.1.1"}, // force remote path
		origDstFunc: func(_ net.Conn) (string, error) {
			return "[2001:db8::2]:8080", nil
		},
		logger:  testLogger(),
		metrics: testMetrics(),
	}

	// The staticResolver returns podIP as nodeIP for remote. With an IPv6
	// pod IP, net.JoinHostPort must produce a bracketed address.
	nodeIP, local := p.resolver.Resolve("2001:db8::2")
	if local {
		t.Fatal("expected remote")
	}
	addr := net.JoinHostPort(nodeIP, "15006")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q) failed: %v", addr, err)
	}
	if host != "2001:db8::2" || port != "15006" {
		t.Errorf("got host=%q port=%q, want 2001:db8::2 / 15006", host, port)
	}
}

func TestConnectionLimit(t *testing.T) {
	backend := startBackend(t, "limited")
	serverTLS, clientTLS := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS:  serverTLS,
		resolver:   &staticResolver{nodeIP: "127.0.0.1"},
		logger:     testLogger(),
		metrics:    m,
		inboundSem: make(chan struct{}, 1), // limit to 1 concurrent
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}

			// Simulate the connection limit check from serve().
			select {
			case p.inboundSem <- struct{}{}:
			default:
				p.metrics.connLimitRejected.Add(1)
				conn.Close()
				continue
			}

			p.activeConns.Add(1)
			go func() {
				defer func() {
					<-p.inboundSem
					p.activeConns.Done()
				}()
				p.handleInbound(ctx, conn)
			}()
		}
	}()

	// First connection: should succeed.
	conn1, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn1, "%s\n", backend)

	// Wait for the accept goroutine to claim the semaphore slot so the
	// second connection actually races against an in-flight handler.
	assertEventually(t, time.Second, func() bool {
		return len(p.inboundSem) == cap(p.inboundSem)
	}, "first connection did not consume the limit-1 semaphore slot")

	// Second connection: should be rejected (limit=1, one in-flight).
	// Server closes the raw TCP connection before TLS handshake, so
	// tls.Dial itself may fail — that's the expected rejection.
	conn2, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err == nil {
		// If TLS handshake somehow completed, the read should still fail.
		conn2.SetReadDeadline(time.Now().Add(1 * time.Second))
		_, err = conn2.Read(make([]byte, 1))
		if err == nil {
			t.Error("expected rejected connection to be closed")
		}
		conn2.Close()
	}

	// Finish first connection.
	fmt.Fprint(conn1, "done")
	conn1.CloseWrite()
	io.ReadAll(conn1)
	conn1.Close()

	if rejected := testutil.ToFloat64(m.connLimitRejected); rejected == 0 {
		t.Error("expected connLimitRejected > 0")
	}
}

func TestIdleTimeout(t *testing.T) {
	// Create two connected pipes and wrap one end with idleConn.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	idle := &idleConn{Conn: server, idle: 100 * time.Millisecond}

	// Write should succeed immediately.
	go func() {
		idle.Write([]byte("hello"))
	}()
	buf := make([]byte, 10)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q, want %q", buf[:n], "hello")
	}

	// After idle period, read on the idle-wrapped conn should timeout.
	time.Sleep(150 * time.Millisecond)
	_, err = idle.Read(make([]byte, 1))
	if err == nil {
		t.Error("expected timeout error after idle period")
	}
}

func TestRouteErrorMetrics(t *testing.T) {
	m := testMetrics()
	p := &Proxy{
		nodeIP:      "10.0.0.1",
		inboundPort: 15006,
		resolver:    &staticResolver{nodeIP: "10.0.0.1"},
		origDstFunc: func(_ net.Conn) (string, error) {
			return "", fmt.Errorf("simulated SO_ORIGINAL_DST failure")
		},
		logger:  testLogger(),
		metrics: m,
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	assertEventually(t, time.Second, func() bool {
		return testutil.ToFloat64(m.routeErrors) > 0
	}, "routeErrors did not advance after origDst failure")
}

func TestOutboundRejectsNonPodOriginalDestination(t *testing.T) {
	m := testMetrics()
	p := &Proxy{
		nodeIP:      "10.0.0.1",
		inboundPort: 15006,
		resolver:    &rejectResolver{},
		origDstFunc: func(_ net.Conn) (string, error) {
			return "10.0.0.1:15001", nil
		},
		logger:  testLogger(),
		metrics: m,
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(conn)
	conn.Close()

	// rejectResolver returns reason=host_addr; the direct-dial counter must
	// move, and the unknown-pod baseline counter must stay at 0 so the two
	// reasons cannot be confused in alert rules downstream.
	if testutil.ToFloat64(m.outboundDestRejected.WithLabelValues(outboundRejectHostAddr)) == 0 {
		t.Error("expected outboundDestRejectedHostAddr > 0 after host-address rejection")
	}
	if testutil.ToFloat64(m.outboundDestRejected.WithLabelValues(outboundRejectUnknownPod)) != 0 {
		t.Error("expected outboundDestRejectedUnknownPod == 0 for host-address rejection (label confusion would defeat the split)")
	}
	if testutil.ToFloat64(m.routeErrors) != 0 {
		t.Error("non-pod destination rejection must not increment routeErrors (reserved for origDst/parse failures)")
	}
}

func TestDestHeaderReadErrorMetrics(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS:         serverTLS,
		destHeaderTimeout: 5 * time.Second,
		resolver:          &staticResolver{nodeIP: "127.0.0.1"},
		logger:            testLogger(),
		metrics:           m,
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send an invalid destination header (no port).
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "no-port\n")
	conn.CloseWrite()
	io.ReadAll(conn)
	conn.Close()

	assertEventually(t, time.Second, func() bool {
		return testutil.ToFloat64(m.destHeaderErrors.WithLabelValues("read")) > 0
	}, "destHeaderReadErrors did not advance after invalid header")
}

func TestReadinessOnShutdown(t *testing.T) {
	m := testMetrics()
	health := newHealthServer(m, nil, nil, 10, 5*time.Second, 10*time.Second)

	p := &Proxy{
		outboundAddr: "127.0.0.1:0",
		inboundAddr:  "127.0.0.1:0",
		logger:       testLogger(),
		metrics:      m,
		onReady:      func() { health.ready.Store(true) },
		onShutdown:   func() { health.ready.Store(false) },
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	assertEventually(t, 2*time.Second, func() bool {
		return health.ready.Load()
	}, "health.ready never became true")

	// Shutdown.
	cancel()
	<-done

	if health.ready.Load() {
		t.Fatal("health.ready should be false after shutdown")
	}
}

// A held port makes the outbound bind fail; Run must return the listen
// error instead of dropping it.
func TestRunReturnsListenError(t *testing.T) {
	held := bindLoopback(t)
	p := &Proxy{
		outboundAddr: held.Addr().String(),
		inboundAddr:  "127.0.0.1:0",
		logger:       testLogger(),
		metrics:      testMetrics(),
		drainTimeout: time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()
	cancel()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "outbound: listen") {
			t.Fatalf("Run() = %v, want the outbound listen error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestMetricsAccounting(t *testing.T) {
	backend := startBackend(t, "metrics")
	serverTLS, clientTLS := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS: serverTLS,
		resolver:  &staticResolver{nodeIP: "127.0.0.1"},
		logger:    testLogger(),
		metrics:   m,
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send a request through the inbound handler.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Fprintf(conn, "%s\n", backend)
	fmt.Fprint(conn, "metrics-test")
	conn.CloseWrite()
	io.ReadAll(conn)
	conn.Close()

	assertEventually(t, time.Second, func() bool {
		return testutil.ToFloat64(m.connectionsTotal.WithLabelValues("inbound", "success")) > 0 &&
			testutil.ToFloat64(m.bytesTotal.WithLabelValues("inbound", "forward")) > 0 &&
			testutil.ToFloat64(m.bytesTotal.WithLabelValues("inbound", "reverse")) > 0
	}, "inbound success/bytes metrics did not advance")
}

func TestInboundDialFailureMetrics(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS:   serverTLS,
		resolver:    &staticResolver{nodeIP: "127.0.0.1"},
		dialTimeout: 100 * time.Millisecond,
		logger:      testLogger(),
		metrics:     m,
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Trigger an inbound connection whose destination pod dial fails.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "127.0.0.1:1\n")
	conn.Close()

	assertEventually(t, 2*time.Second, func() bool {
		return testutil.ToFloat64(m.dialFailures) > 0
	}, "dialFailures did not advance after failed inbound dial")
}

func TestARMTLSDialFailureMetrics(t *testing.T) {
	_, clientTLS := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		nodeIP:      "1.1.1.1",
		inboundPort: 15006,
		clientTLS:   clientTLS,
		resolver: &staticResolver{
			nodeIP: "1.1.1.1",
		},
		origDstFunc: func(_ net.Conn) (string, error) {
			// Remote pod IP resolves to itself (not local).
			return "10.244.1.5:8080", nil
		},
		tlsDialTimeout: 100 * time.Millisecond,
		logger:         testLogger(),
		metrics:        m,
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleOutbound(ctx, conn)
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()

	assertEventually(t, 2*time.Second, func() bool {
		return testutil.ToFloat64(m.tlsDialFailures) > 0 && testutil.ToFloat64(m.connectionsTotal.WithLabelValues("outbound", "error")) > 0
	}, "tlsDialFailures/connErrorOutbound did not advance after armTLS dial failure")

	if testutil.ToFloat64(m.connectionsTotal.WithLabelValues("outbound", "success")) != 0 {
		t.Error("expected connSuccessOutbound == 0 after armTLS dial failure")
	}
}

func TestAcceptLoopBackoff(t *testing.T) {
	m := testMetrics()
	ready := make(chan struct{})
	p := &Proxy{
		outboundAddr: "127.0.0.1:0",
		inboundAddr:  "127.0.0.1:0",
		logger:       testLogger(),
		metrics:      m,
		onReady:      func() { close(ready) },
		onShutdown:   func() {},
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- p.Run(ctx) }()

	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("listeners did not become ready")
	}

	// Cancel to shut down. The accept loop should exit cleanly.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for shutdown")
	}

	// After clean shutdown, acceptErrors should be 0.
	if got := testutil.ToFloat64(m.acceptErrors); got != 0 {
		t.Errorf("acceptErrors = %v after clean shutdown, want 0", got)
	}
}

// rejectResolver rejects all destinations as non-local.
type rejectResolver struct{}

func (r *rejectResolver) Resolve(podIP string) (string, bool) { return podIP, false }
func (r *rejectResolver) ValidateOutboundDest(ip string) (bool, string) {
	return false, outboundRejectHostAddr
}
func (r *rejectResolver) ValidateLocalDest(ip string) bool { return false }

func TestInboundDestRejected(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)

	m := testMetrics()
	p := &Proxy{
		serverTLS:         serverTLS,
		destHeaderTimeout: 5 * time.Second,
		resolver:          &rejectResolver{},
		logger:            testLogger(),
		metrics:           m,
	}

	ctx := t.Context()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tlsLn := tls.NewListener(ln, serverTLS)

	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go p.handleInbound(ctx, conn)
		}
	}()

	// Send a valid destination header that the resolver rejects.
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "10.99.99.99:8080\n")
	conn.CloseWrite()
	io.ReadAll(conn)
	conn.Close()

	assertEventually(t, time.Second, func() bool {
		return testutil.ToFloat64(m.inboundDestRejected) > 0
	}, "inboundDestRejected did not advance for a non-local destination")

	if testutil.ToFloat64(m.connectionsTotal.WithLabelValues("inbound", "success")) != 0 {
		t.Error("expected no successful inbound connections")
	}
}
