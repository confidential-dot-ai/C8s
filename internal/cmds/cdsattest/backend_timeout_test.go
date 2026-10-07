//go:build unix

package cdsattest

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/types"
)

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

// A dead upstream pod IP must fail within the dial timeout, not hang until
// the request timeout or nginx gives up.
func TestHTTPBackendDeadUpstreamFailsFast(t *testing.T) {
	backend, err := NewHTTPBackend("http://"+blackholedAddr(t), HTTPBackendOptions{Timeout: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = backend.Forward(context.Background(), types.TunnelRequest{Method: "POST", Path: "/v1/chat/completions"})
	if took := time.Since(start); err == nil || took > 15*time.Second {
		t.Fatalf("Forward() to a dead upstream = %v after %s, want a dial error within the 5s dial timeout", err, took)
	}
}
