package cdsattest

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// echoUpgradeServer answers a WebSocket upgrade with 101 and then echoes
// every line it reads back on the hijacked connection.
func echoUpgradeServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
			http.Error(w, "Invalid transport", http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		for {
			line, err := rw.ReadString('\n')
			if err != nil {
				return
			}
			rw.WriteString(line)
			rw.Flush()
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A WebSocket upgrade passes through the lb forwarder, and a bound change
// closes the upgraded connection like any other forwarded request.
func TestLBForwarderWebSocketUpgrade(t *testing.T) {
	upstream := echoUpgradeServer(t)
	backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fence := newRollout("", "")
	fence.lease = time.Hour
	fence.seenAt = time.Now()
	forwarder, err := newLBForwarder(fence, backend, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(forwarder)
	defer front.Close()

	conn, err := net.Dial("tcp", front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET /ws/socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: example.com\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+connectionTimeHeader+": 0\r\n\r\n")
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("upgrade status = %d %q, want 101", resp.StatusCode, body)
	}
	io.WriteString(conn, "frame\n")
	if got, err := br.ReadString('\n'); err != nil || got != "frame\n" {
		t.Fatalf("echo = %q, %v; want %q", got, err, "frame\n")
	}

	fence.mu.Lock()
	fence.resetGen(errBoundChanged)
	fence.mu.Unlock()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := br.ReadString('\n'); err != io.EOF {
		t.Fatalf("after bound change read %q, %v; want the upgraded connection closed (EOF)", got, err)
	}
}
