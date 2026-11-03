//go:build linux

package connectbroker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// startBroker serves one peer from a temporary volume to the test's own UID
// and group, so it needs no privilege.
func startBroker(t *testing.T, peers []netip.AddrPort, dial func(context.Context, string) (net.Conn, error)) string {
	t.Helper()
	dir := t.TempDir()
	listener, err := Listen(openRoot(t, dir), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Peers: peers, UID: uint32(os.Getuid()), Dial: dial, Timeout: 2 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return filepath.Join(dir, SocketName)
}

func TestBrokerHandsBackAConnectionToAnAdvertisedPeerOnly(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	peer := netip.MustParseAddrPort(echo.Addr().String())
	// The guest dials where the test's loopback echo listens, whatever tuple the pod named.
	dial := func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", echo.Addr().String())
	}
	advertised := netip.MustParseAddrPort("203.0.113.1:15006")
	socket := startBroker(t, []netip.AddrPort{advertised}, dial)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, socket, advertised)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.WriteString(conn, "through the guest"); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, len("through the guest"))
	if _, err := io.ReadFull(conn, answer); err != nil || string(answer) != "through the guest" {
		t.Fatalf("echo through the brokered socket: %q %v", answer, err)
	}
	if _, err := Dial(ctx, socket, peer); !errors.Is(err, ErrRefused) {
		t.Fatalf("a tuple the launch did not advertise was connected: %v", err)
	}
	if _, err := Dial(ctx, socket, netip.MustParseAddrPort("[2001:db8::1]:15006")); !errors.Is(err, ErrRefused) {
		t.Fatalf("an IPv6 tuple was requested: %v", err)
	}
}

func TestBrokerRefusesOtherOwnersAndMalformedRequests(t *testing.T) {
	advertised := netip.MustParseAddrPort("203.0.113.1:15006")
	var dialed atomic.Int32
	// start serves one broker to the given UID and returns its socket and a stop
	// that also checks the socket is gone; each case gets its own server, so the
	// test never mutates one the accept loop is reading.
	start := func(uid uint32) (string, func()) {
		dir := t.TempDir()
		listener, err := Listen(openRoot(t, dir), os.Getgid())
		if err != nil {
			t.Fatal(err)
		}
		server := &Server{Peers: []netip.AddrPort{advertised}, UID: uid, Timeout: 2 * time.Second,
			Dial: func(context.Context, string) (net.Conn, error) {
				dialed.Add(1)
				return nil, errors.New("must not dial")
			}}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx, listener) }()
		socket := filepath.Join(dir, SocketName)
		return socket, func() {
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("the broker socket outlived its server")
			}
		}
	}
	other, stopOther := start(uint32(os.Getuid()) + 1)
	if _, err := Dial(context.Background(), other, advertised); !errors.Is(err, ErrRefused) {
		t.Fatalf("another socket owner was served: %v", err)
	}
	stopOther()
	socket, stop := start(uint32(os.Getuid()))
	for _, request := range []string{"c8s-mesh-connect/0 203.0.113.1:15006\n", "c8s-mesh-connect/1 203.0.113.1:15006", "c8s-mesh-connect/1 203.0.113.1\n", "c8s-mesh-connect/1 203.0.113.1:0\n", "GET / HTTP/1.0\r\n\r\n"} {
		conn, err := net.Dial("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(conn, request)
		reply, _ := io.ReadAll(conn)
		conn.Close()
		if string(reply) == replyOK {
			t.Fatalf("malformed request %q was served", request)
		}
	}
	stop()
	if dialed.Load() != 0 {
		t.Fatal("a refused request reached the guest dialer")
	}
}

func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestListenRefusesANonSocketInTheWay(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, SocketName), []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(openRoot(t, dir), os.Getgid()); err == nil {
		t.Fatal("a regular file at the socket path was replaced")
	}
}

// A kubelet volume path is longer than a unix socket address allows; the
// socket is bound through the held directory, so the path length is immaterial.
func TestListenBindsInsideAVolumeWhosePathExceedsASocketAddress(t *testing.T) {
	dir := filepath.Join(t.TempDir(), strings.Repeat("v", 110-len(t.TempDir())+len(SocketName)))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if len(filepath.Join(dir, SocketName)) <= 108 {
		t.Fatalf("test path %d bytes is not longer than sun_path", len(filepath.Join(dir, SocketName)))
	}
	listener, err := Listen(openRoot(t, dir), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Peers: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.1:15006")}, UID: uint32(os.Getuid()), Timeout: 2 * time.Second,
		Dial: func(context.Context, string) (net.Conn, error) { return nil, errors.New("not dialled in this test") }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	// The endpoint connects by its short in-container path; here the directory stands in for it.
	volume, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer volume.Close()
	if _, err := Dial(ctx, fmt.Sprintf("/proc/self/fd/%d/%s", volume.Fd(), SocketName), netip.MustParseAddrPort("203.0.113.1:15006")); !errors.Is(err, ErrRefused) {
		t.Fatalf("the broker did not answer through the long volume path: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, SocketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the socket outlived its server")
	}
}
