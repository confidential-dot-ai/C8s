//go:build integration && linux

package cdsha_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// proxyPair starts a target listener and a proxy in front of it whose
// dialer counts as replica 0 and target as replica 1. It returns a client
// connection through the proxy and the target side of it.
func proxyPair(t *testing.T) (*faultNet, net.Conn, net.Conn) {
	t.Helper()
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	f := newFaultNet()
	t.Cleanup(f.close)
	if err := f.listen("127.0.0.1:0", target.Addr().String(), 1, func(string) int { return 0 }); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := target.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", f.lns[0].Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	select {
	case server := <-accepted:
		t.Cleanup(func() { server.Close() })
		return f, client, server
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not connect to the target")
	}
	return nil, nil, nil
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

// expectSilence: nothing arrives on c for d.
func expectSilence(t *testing.T, c net.Conn, d time.Duration) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	var one [1]byte
	if n, err := c.Read(one[:]); n > 0 || err == nil {
		t.Fatalf("bytes crossed a blackhole: n=%d err=%v", n, err)
	}
	_ = c.SetReadDeadline(time.Time{})
}

func readAllWithin(t *testing.T, c net.Conn, d time.Duration) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	got, err := io.ReadAll(c)
	if err != nil {
		t.Fatalf("read: %v after %d bytes", err, len(got))
	}
	return got
}

// TestProxyBlackholeStallsIntact: bytes sent while blackholed are held
// and arrive intact and in order after the heal, then the close; in both
// directions; past the proxy's own queue (sender pushed back).
func TestProxyBlackholeStallsIntact(t *testing.T) {
	for _, dir := range []string{"dialer-to-target", "target-to-dialer"} {
		t.Run(dir, func(t *testing.T) {
			f, client, server := proxyPair(t)
			src, dst, from, to := client, server, 0, 1
			if dir == "target-to-dialer" {
				src, dst, from, to = server, client, 1, 0
			}
			before := pattern(4096)
			if _, err := src.Write(before); err != nil {
				t.Fatal(err)
			}
			_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
			if got := make([]byte, len(before)); func() bool { _, err := io.ReadFull(dst, got); return err != nil || !bytes.Equal(got, before) }() {
				t.Fatal("bytes before the blackhole did not arrive intact")
			}
			_ = dst.SetReadDeadline(time.Time{})
			f.Set(from, to, Link{Blackhole: true})
			// 48 MiB: more than the proxy queue (1024 chunks of at most
			// 32 KiB) holds, so the sender must be pushed back.
			during := pattern(48 << 20)
			wrote := make(chan error, 1)
			go func() {
				_, err := src.Write(during)
				if err == nil {
					err = src.(*net.TCPConn).CloseWrite()
				}
				wrote <- err
			}()
			expectSilence(t, dst, 1500*time.Millisecond)
			select {
			case err := <-wrote:
				t.Fatalf("a 48 MiB write finished through a blackhole (no backpressure): %v", err)
			default:
			}
			f.HealAll()
			got := readAllWithin(t, dst, 30*time.Second)
			if err := <-wrote; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, during) {
				t.Fatalf("after heal: got %d bytes, want %d, equal prefix %d", len(got), len(during), commonPrefix(got, during))
			}
		})
	}
}

// TestProxyBlackholeOnlyThatDirection: the other direction still flows.
func TestProxyBlackholeOnlyThatDirection(t *testing.T) {
	f, client, server := proxyPair(t)
	f.Set(0, 1, Link{Blackhole: true})
	msg := []byte("reply while the request direction is blackholed")
	if _, err := server.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(client, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("reverse direction: %q %v", got, err)
	}
}

// TestProxyCorruptDropsBytes: Corrupt (not Blackhole) leaves holes.
func TestProxyCorruptDropsBytes(t *testing.T) {
	for _, chance := range []float64{1, 0.5} {
		f, client, server := proxyPair(t)
		f.Set(0, 1, Link{Corrupt: chance})
		sent := 0
		for range 200 {
			// Small writes, a pause between, so they reach the proxy as
			// separate chunks.
			n, err := client.Write(pattern(1000))
			if err != nil {
				t.Fatal(err)
			}
			sent += n
			time.Sleep(time.Millisecond)
		}
		_ = client.(*net.TCPConn).CloseWrite()
		got := readAllWithin(t, server, 10*time.Second)
		t.Logf("corrupt %.1f: sent %d, received %d", chance, sent, len(got))
		if chance == 1 && len(got) != 0 {
			t.Errorf("corrupt 1: %d bytes arrived", len(got))
		}
		if chance < 1 && (len(got) == 0 || len(got) >= sent) {
			t.Errorf("corrupt %.1f: received %d of %d", chance, len(got), sent)
		}
	}
}

// TestProxyLossAndLatencyNeverDrop: Loss and Latency delay, never drop.
func TestProxyLossAndLatencyNeverDrop(t *testing.T) {
	f, client, server := proxyPair(t)
	f.Set(0, 1, Link{Loss: 0.5, Latency: 5 * time.Millisecond, Jitter: 5 * time.Millisecond})
	want := pattern(2 << 20)
	go func() {
		for off := 0; off < len(want); off += 8192 {
			_, _ = client.Write(want[off:min(off+8192, len(want))])
		}
		_ = client.(*net.TCPConn).CloseWrite()
	}()
	got := readAllWithin(t, server, 60*time.Second)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %d bytes, want %d, equal prefix %d", len(got), len(want), commonPrefix(got, want))
	}
}

func commonPrefix(a, b []byte) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}
