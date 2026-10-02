//go:build unix

package cdsattest

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"
)

func lbForwarderFor(t *testing.T, base string, opts HTTPBackendOptions) http.Handler {
	t.Helper()
	backend, err := NewHTTPBackend(base, opts)
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
	return forwarder
}

func forwardOnce(forwarder http.Handler) (int, time.Duration) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set(connectionTimeHeader, "0")
	w := httptest.NewRecorder()
	start := time.Now()
	forwarder.ServeHTTP(w, req)
	return w.Code, time.Since(start)
}

// blackholedAddr returns a loopback address whose SYNs are dropped: a
// listener that never accepts, with its accept queue already full. A dial to
// it hangs like a dial to a killed pod's IP.
func blackholedAddr(t *testing.T) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", sa.(*syscall.SockaddrInet4).Port)
	for range 1024 {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return addr
			}
			t.Fatalf("fill accept queue: %v", err)
		}
		t.Cleanup(func() { c.Close() })
	}
	t.Skip("accept queue never filled; cannot blackhole a loopback address here")
	return ""
}

// A dead upstream pod IP must fail with 502 within the dial timeout, not
// hang until nginx's read timeout gives up.
func TestLBForwarderDeadUpstreamFailsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the dial timeout")
	}
	forwarder := lbForwarderFor(t, "http://"+blackholedAddr(t), HTTPBackendOptions{})
	code, took := forwardOnce(forwarder)
	if code != http.StatusBadGateway {
		t.Fatalf("blackholed upstream = %d after %v, want 502", code, took)
	}
	if took < 4*time.Second || took > 7*time.Second {
		t.Fatalf("blackholed upstream failed after %v, want the 5s dial timeout", took)
	}
}

// A non-streaming completion sends headers only when it is done. The
// forwarder must wait for it: no response-header timeout, and the backend's
// client timeout (used by Forward) must not apply to this path.
func TestLBForwarderWaitsForSlowHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Write([]byte("done"))
	}))
	defer upstream.Close()
	forwarder := lbForwarderFor(t, upstream.URL, HTTPBackendOptions{Timeout: time.Second})
	if code, took := forwardOnce(forwarder); code != http.StatusOK {
		t.Fatalf("slow upstream = %d after %v, want 200", code, took)
	}
}
