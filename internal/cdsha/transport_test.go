package cdsha

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// closedByPeer reads until the mux closes the connection; a read timeout
// means the mux kept it.
func closedByPeer(t *testing.T, c net.Conn, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := c.Read(make([]byte, 1))
	var ne net.Error
	if n != 0 || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("%s: the mux kept the connection (%d bytes, %v)", what, n, err)
	}
}

// muxPeers are two replicas' TLS configs and a mux for the first, with
// verifier v (no pins, empty anchor) and control handler control.
func muxPeers(t *testing.T, control controlHandler) (a, b *Node, v peerVerifier, m *mux) {
	t.Helper()
	al, sec, led := testStores(t)
	mk := func(name string) *Node {
		n, err := NewNode(Config{ClusterID: testCluster, NodeName: name, Bind: "127.0.0.1:0", Advertise: "127.0.0.1:1",
			Attestor: testAttestor{"m1"}, Seats: 3, Allowlist: al, Secrets: sec, Ledger: led})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	a, b = mk("a"), mk("b")
	v = peerVerifier{clusterID: testCluster, att: testAttestor{}, anchor: "", pins: func() []string { return nil }}
	m, err := newMux("127.0.0.1:0", "127.0.0.1:1", string(a.id), a.tls, v, control, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return a, b, v, m
}

// The mux refuses whatever is not an attested connection of a known kind for
// this member, and Dial refuses an address that names no member.
func TestMuxRefusals(t *testing.T) {
	a, b, v, m := muxPeers(t, nil)
	addr := m.ln.Addr().String()
	// Not TLS at all.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	closedByPeer(t, c, "plain connection")
	c.Close()
	// Attested, but an unknown kind byte.
	tc, _, err := dialKind(addr, time.Second, b.tls, v, 'Z', nil)
	if err != nil {
		t.Fatal(err)
	}
	closedByPeer(t, tc, "unknown kind")
	tc.Close()
	// A control request when the mux has no handler: closed without answer.
	if _, err := callControl(addr, b.tls, v, time.Second, controlRequest{Op: ctlStatus}, nil); err == nil {
		t.Fatal("a control answer without a handler")
	}
	// Raft for another member: refused after the target ID.
	bm := &mux{tls: b.tls, verifier: v, advert: raftAddr{tcp: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, id: string(b.id)}, conns: map[*peerConn]struct{}{}}
	rc, err := bm.Dial(raft.ServerAddress(addr+"#someone-else/1-x"), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	closedByPeer(t, rc, "raft connection for another member")
	rc.Close()
	if _, err := bm.Dial(raft.ServerAddress(addr), time.Second); err == nil {
		t.Fatal("dialed a raft address without a member id")
	}
	if _, _, err := dialKind("127.0.0.1:1", 200*time.Millisecond, b.tls, v, muxRaft, nil); err == nil {
		t.Fatal("dial to a closed port")
	}
	if m.Addr().String() != "127.0.0.1:1#"+string(a.id) {
		t.Fatalf("advertised %s", m.Addr())
	}
	// Each side checks the other's evidence: a dialer of another cluster
	// refuses this mux, and this mux refuses a peer of another cluster.
	other := v
	other.clusterID = "another-cluster"
	if _, _, err := dialKind(addr, time.Second, b.tls, other, muxControl, nil); err == nil {
		t.Fatal("dialer accepted a peer of another cluster")
	}
	answer := func(Claims, controlRequest) controlResponse { return controlResponse{Member: true} }
	om, err := newMux("127.0.0.1:0", "127.0.0.1:1", string(a.id), a.tls, other, answer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer om.Close()
	if _, err := callControl(om.ln.Addr().String(), b.tls, v, time.Second, controlRequest{Op: ctlStatus}, nil); err == nil {
		t.Fatal("the mux answered a peer of another cluster")
	}
	if _, err := v.peer(tls.Server(nil, &tls.Config{})); err == nil {
		t.Error("connection without a peer certificate accepted")
	}
}

// The mux closes connections that end before saying what they are for, and
// connections from a partitioned peer.
func TestMuxClosesIncompleteConnections(t *testing.T) {
	answered := make(chan struct{}, 1)
	control := func(Claims, controlRequest) controlResponse { answered <- struct{}{}; return controlResponse{} }
	a, b, v, m := muxPeers(t, control)
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
	rc, _, err := dialKind(addr, time.Second, b.tls, v, muxRaft, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = rc.CloseWrite()
	closedByPeer(t, rc, "no raft target")
	rc.Close()

	// Control, then a request that is not JSON.
	cc, _, err := dialKind(addr, time.Second, b.tls, v, muxControl, nil)
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
	eventually(t, 5*time.Second, "the mux tracks the raft connection", func() bool {
		m.connMu.Lock()
		defer m.connMu.Unlock()
		return len(m.conns) == 1
	})
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

// logEvery allows one line a minute per key.
func TestLogEvery(t *testing.T) {
	var l logEvery
	now := time.Now()
	for i, c := range []struct {
		key  string
		at   time.Duration
		want bool
	}{{"a", 0, true}, {"a", 30 * time.Second, false}, {"b", 30 * time.Second, true}, {"a", time.Minute, true}, {"a", time.Minute + time.Second, false}} {
		if got := l.ok(c.key, now.Add(c.at)); got != c.want {
			t.Errorf("call %d (%s at %v): %v, want %v", i, c.key, c.at, got, c.want)
		}
	}
}
