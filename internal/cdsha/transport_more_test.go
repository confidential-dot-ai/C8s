package cdsha

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// closedByPeer reads until the mux closes the connection.
func closedByPeer(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	var ne net.Error
	if n != 0 || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("%s: the mux kept the connection (%d bytes, %v)", what, n, err)
	}
}

// The mux closes connections that end before saying what they are for, and
// connections from a partitioned peer.
func TestMuxClosesIncompleteConnections(t *testing.T) {
	al, sec, led := testStores(t)
	mk := func(name string) *Node {
		n, err := NewNode(Config{ClusterID: testCluster, NodeName: name, Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1",
			Attestor: testAttestor{"m1"}, Seats: 3, Allowlist: al, Secrets: sec, Ledger: led})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	a, b := mk("a"), mk("b")
	v := peerVerifier{clusterID: testCluster, att: testAttestor{}, anchor: "", pins: func() []string { return nil }}
	answered := make(chan struct{}, 1)
	control := func(Claims, controlRequest) controlResponse { answered <- struct{}{}; return controlResponse{} }
	m, err := newMux("127.0.0.1:0", "127.0.0.1:1", string(a.id), a.tls, v, control, nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := m.ln.Addr().String()

	// TLS, then nothing: no kind byte.
	tc, err := tls.Dial("tcp", addr, b.tls)
	if err != nil {
		t.Fatal(err)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	closedByPeer(t, tc, "no kind")
	tc.Close()

	// Raft, then nothing: no target member.
	rc, err := dialKind(addr, time.Second, b.tls, muxRaft, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.CloseWrite()
	closedByPeer(t, rc, "no raft target")
	rc.Close()

	// Control, then a request that is not JSON.
	cc, err := dialKind(addr, time.Second, b.tls, muxControl, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = cc.Write([]byte("{"))
	_ = cc.CloseWrite()
	closedByPeer(t, cc, "bad control request")
	cc.Close()
	select {
	case <-answered:
		t.Fatal("a malformed control request reached the handler")
	default:
	}

	// A raft connection for this member that nobody accepts is closed with the mux.
	bm := &mux{tls: b.tls, verifier: v, advert: raftAddr{tcp: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, id: string(b.id)}, conns: map[*peerConn]struct{}{}}
	pc, err := bm.Dial(raft.ServerAddress(addr+"#"+string(a.id)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let the mux route it
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	closedByPeer(t, pc, "unaccepted raft connection")
	pc.Close()
	if _, err := m.Accept(); err == nil {
		t.Fatal("accepted from a closed mux")
	}

	// A partitioned peer is cut before TLS.
	cut, err := newMux("127.0.0.1:0", "127.0.0.1:1", string(a.id), a.tls, v, control, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	defer cut.Close()
	raw, err := net.Dial("tcp", cut.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	closedByPeer(t, raw, "partitioned peer")
	raw.Close()
	if _, err := cut.Dial(raft.ServerAddress(addr+"#x/1-a"), time.Second); err == nil {
		t.Fatal("dialed out of a partition")
	}
}
