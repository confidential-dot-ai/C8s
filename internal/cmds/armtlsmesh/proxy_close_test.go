//go:build linux

package armtlsmesh

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// startMeshChain wires app -> outbound proxy -> ARmTLS -> inbound proxy ->
// backend, mirroring TestEndToEnd, and returns the outbound listener address.
func startMeshChain(t *testing.T, backend string, idle time.Duration) string {
	t.Helper()
	serverTLS, clientTLS := testTLSConfigs(t)
	ctx := t.Context()

	inLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { inLn.Close() })
	inTLSLn := tls.NewListener(inLn, serverTLS)
	inbound := &Proxy{logger: testLogger(), metrics: testMetrics(), resolver: &staticResolver{nodeIP: "127.0.0.1"}, idleTimeout: idle}
	go func() {
		for {
			c, err := inTLSLn.Accept()
			if err != nil {
				return
			}
			go inbound.handleInbound(ctx, c)
		}
	}()

	inPort := inLn.Addr().(*net.TCPAddr).Port
	outbound := &Proxy{
		nodeIP:      "1.1.1.1",
		inboundPort: inPort,
		clientTLS:   clientTLS,
		resolver:    &fixedRemoteResolver{nodeIP: "127.0.0.1"},
		origDstFunc: func(net.Conn) (string, error) { return backend, nil },
		logger:      testLogger(),
		metrics:     testMetrics(),
		idleTimeout: idle,
	}
	outLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outLn.Close() })
	go func() {
		for {
			c, err := outLn.Accept()
			if err != nil {
				return
			}
			go outbound.handleOutbound(ctx, c)
		}
	}()
	return outLn.Addr().String()
}

// readThenEOF reads exactly want from c, then asserts the next read is EOF
// within the deadline.
func readThenEOF(t *testing.T, c net.Conn, want string, within time.Duration) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(within))
	buf := make([]byte, len(want))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(buf) != want {
		t.Fatalf("got %q, want %q", buf, want)
	}
	n, err := c.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("after server close: got n=%d err=%v, want io.EOF within %v", n, err, within)
	}
}

// TestServerClosePropagatesToClient reproduces an HTTP keep-alive server
// closing an idle connection: the client never half-closes, so it must learn
// about the server's FIN through both proxy legs or it will reuse a dead
// pooled connection.
func TestServerClosePropagatesToClient(t *testing.T) {
	for _, idle := range []time.Duration{0, time.Minute} {
		t.Run(fmt.Sprintf("idle=%v", idle), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				buf := make([]byte, 4)
				io.ReadFull(c, buf)
				c.Write([]byte("resp"))
				c.Close()
			}()

			conn, err := net.Dial("tcp", startMeshChain(t, ln.Addr().String(), idle))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.Write([]byte("req1"))
			readThenEOF(t, conn, "resp", time.Second)
		})
	}
}

// TestServerHalfClosePropagates checks that a server CloseWrite reaches the
// client as EOF while the client->server direction stays usable.
func TestServerHalfClosePropagates(t *testing.T) {
	for _, idle := range []time.Duration{0, time.Minute} {
		t.Run(fmt.Sprintf("idle=%v", idle), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { ln.Close() })
			gotAfter := make(chan string, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				buf := make([]byte, 4)
				io.ReadFull(c, buf)
				c.Write([]byte("resp"))
				c.(*net.TCPConn).CloseWrite()
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				rest, _ := io.ReadAll(c)
				gotAfter <- string(rest)
			}()

			conn, err := net.Dial("tcp", startMeshChain(t, ln.Addr().String(), idle))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.Write([]byte("req1"))
			readThenEOF(t, conn, "resp", time.Second)

			// Write side must still reach the server after its half-close.
			conn.Write([]byte("tail"))
			conn.(*net.TCPConn).CloseWrite()
			select {
			case got := <-gotAfter:
				if got != "tail" {
					t.Fatalf("server got %q after half-close, want %q", got, "tail")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server did not see client data/EOF after half-close")
			}
		})
	}
}

// TestPipeBackendResetIsNotACleanClose checks that a backend reset mid-stream
// reaches the app as an error, not as EOF after a truncated response.
func TestPipeBackendResetIsNotACleanClose(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backendLn.Close() })
	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			return
		}
		_, _ = c.Write([]byte("partial"))
		time.Sleep(100 * time.Millisecond)
		_ = c.(*net.TCPConn).SetLinger(0)
		_ = c.Close()
	}()

	app, err := net.Dial("tcp", startMeshChain(t, backendLn.Addr().String(), 0))
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	if err := app.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("partial"))
	if _, err := io.ReadFull(app, buf); err != nil {
		t.Fatalf("read partial response: %v", err)
	}
	n, err := app.Read(make([]byte, 1))
	if err == nil || err == io.EOF {
		t.Fatalf("after backend reset: got n=%d err=%v, want a reset error", n, err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("after backend reset: timed out, want a reset error")
	}
}
