package cdsha

// Bounded transport lifetime regressions.
// No load generation: one local attested connection, with explicit teardown.
import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestR3SurfaceStalledRaftTargetSurvivesClose(t *testing.T) {
	a, b, v, fixture := muxPeers(t, nil)
	// Stop fixture accept loop. Route one owned socket ourselves so completion is observable.
	_ = fixture.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	m := &mux{ln: ln, tls: a.tls, verifier: v, advert: fixture.advert,
		raftConn: make(chan net.Conn), done: make(chan struct{}), conns: map[*peerConn]struct{}{}, refused: newLogOnce()}
	routed := make(chan struct{})
	accepted := make(chan net.Conn, 1)
	go func() {
		defer close(routed)
		raw, e := ln.Accept()
		if e != nil {
			return
		}
		accepted <- raw
		m.route(raw)
	}()
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", ln.Addr().String(), b.tls)
	if err != nil {
		_ = ln.Close()
		<-routed
		t.Fatal(err)
	}
	raw := <-accepted
	defer func() {
		_ = raw.Close() // raw socket close cannot block on TLS close_notify
		_ = c.Close()
		_ = m.Close()
		select {
		case <-routed:
		case <-time.After(time.Second):
			t.Error("owned route did not stop after raw close")
		}
	}()
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte{muxRaft}); err != nil {
		t.Fatal(err)
	}
	// Wait for tracking rather than depending on a fixed sleep.
	eventually(t, time.Second, "tracked", func() bool {
		m.connMu.Lock()
		defer m.connMu.Unlock()
		return len(m.conns) == 1
	})
	_ = m.Close()
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err = io.ReadFull(c, make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Error("mux.Close left stalled Raft target alive; deadline had been cleared before target")
	}
}

func TestMuxInboundAdmissionAndShutdown(t *testing.T) {
	_, _, _, m := muxPeers(t, nil)
	clients := make([]net.Conn, 0, maxInboundConnections)
	for i := 0; i < maxInboundConnections; i++ {
		a, b := net.Pipe()
		clients = append(clients, b)
		if m.admit(a) == nil {
			t.Fatal("premature cap")
		}
	}
	defer func() {
		for _, c := range clients {
			c.Close()
		}
	}()
	a, b := net.Pipe()
	defer b.Close()
	if m.admit(a) != nil {
		t.Fatal("over cap admitted")
	}
	m.Close()
	m.connMu.Lock()
	count := len(m.inbound)
	m.connMu.Unlock()
	if count != 0 {
		t.Fatalf("%d sockets retained", count)
	}
	for _, c := range clients {
		closedByPeer(t, c, "shutdown raw socket")
	}
	a, b = net.Pipe()
	defer b.Close()
	if m.admit(a) != nil {
		t.Fatal("admitted after close")
	}
}
func TestMuxRaftTargetDeadline(t *testing.T) {
	_, b, v, m := muxPeers(t, nil)
	c, _, err := dialKind(m.ln.Addr().String(), time.Second, b.tls, v, muxRaft, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Only length, no target bytes: must time out under initial framing deadline.
	c.Write([]byte{2})
	c.SetReadDeadline(time.Now().Add(handshakeTimeout + 2*time.Second))
	_, err = c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("target read has no server deadline")
	}
	eventually(t, time.Second, "released inbound", func() bool { m.connMu.Lock(); defer m.connMu.Unlock(); return len(m.inbound) == 0 && len(m.conns) == 0 })
}
