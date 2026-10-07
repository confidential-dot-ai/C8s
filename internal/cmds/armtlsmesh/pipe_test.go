//go:build linux

package armtlsmesh

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair is a connected pair of loopback TCP connections.
func tcpPair(t *testing.T) (local, remote *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dialed.Close() })
	served, ok := <-accepted
	if !ok {
		t.Fatal("accept on the loopback pair failed")
	}
	t.Cleanup(func() { served.Close() })
	return dialed.(*net.TCPConn), served.(*net.TCPConn)
}

// readToEnd reads conn until it ends, with a deadline so a connection that was
// neither closed nor reset fails the test rather than hanging it.
func readToEnd(t *testing.T, conn net.Conn) ([]byte, error) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return io.ReadAll(conn)
}

// A complete copy half-closes its destination, so the peer reads the end of
// the stream.
func TestCopyDirHalfClosesAfterACompleteCopy(t *testing.T) {
	source, sender := tcpPair(t)
	destination, peer := tcpPair(t)
	if _, err := sender.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	sender.Close()

	copyDir(newBufPool(), destination, source)

	carried, err := readToEnd(t, peer)
	if err != nil {
		t.Fatalf("the peer read %q and then %v, want the end of the stream", carried, err)
	}
	if string(carried) != "ping" {
		t.Errorf("the peer read %q, want %q", carried, "ping")
	}
}

// A failed copy resets its destination, so the peer reads a cut-short stream
// as cut short rather than as complete.
func TestCopyDirResetsTheDestinationAfterAFailedCopy(t *testing.T) {
	source, _ := tcpPair(t)
	destination, peer := tcpPair(t)
	source.Close()

	copyDir(newBufPool(), destination, source)

	assertNotEndedCleanly(t, peer)
}

// abort resets a connection it wrapped itself, through the TLS layer.
func TestAbortResetsTheTransportUnderATLSConnection(t *testing.T) {
	transport, peer := tcpPair(t)

	abort(tls.Client(transport, &tls.Config{
		ServerName: "peer.example",
		MinVersion: tls.VersionTLS13,
	}))

	assertNotEndedCleanly(t, peer)
}

// assertNotEndedCleanly asserts that the peer of an aborted connection reads a
// reset rather than the end of the stream.
func assertNotEndedCleanly(t *testing.T, peer net.Conn) {
	t.Helper()
	read, err := readToEnd(t, peer)
	if err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("the peer read %q and then %v, want a reset", read, err)
	}
}
