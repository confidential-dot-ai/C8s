package cdsha

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// The mux refuses whatever is not an attested connection of a known kind for
// this member, and Dial refuses an address that names no member.
func TestMuxRefusals(t *testing.T) {
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
	m, err := newMux("127.0.0.1:0", "127.0.0.1:1", string(a.id), a.tls, v, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	addr := m.ln.Addr().String()
	// Not TLS at all.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := c.Read(make([]byte, 1)); n != 0 {
		t.Fatal("answered a plain connection")
	}
	c.Close()
	// Attested, but an unknown kind byte.
	tc, err := dialKind(addr, time.Second, b.tls, 'Z', nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = tc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := tc.Read(make([]byte, 1)); n != 0 {
		t.Fatal("answered an unknown kind")
	}
	tc.Close()
	// A control request when the mux has no handler: closed without answer.
	if _, err := callControl(addr, b.tls, time.Second, controlRequest{Op: ctlStatus}, nil); err == nil {
		t.Fatal("a control answer without a handler")
	}
	// Raft for another member: refused after the target ID.
	bm := &mux{tls: b.tls, verifier: v, advert: raftAddr{tcp: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}, id: string(b.id)}, conns: map[*peerConn]struct{}{}}
	rc, err := bm.Dial(raft.ServerAddress(addr+"#someone-else/1-x"), time.Second)
	if err == nil {
		_ = rc.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, _ := rc.Read(make([]byte, 1)); n != 0 {
			t.Fatal("a raft connection for another member was served")
		}
		rc.Close()
	}
	if _, err := bm.Dial(raft.ServerAddress(addr), time.Second); err == nil {
		t.Fatal("dialed a raft address without a member id")
	}
	if _, err := dialKind("127.0.0.1:1", 200*time.Millisecond, b.tls, muxRaft, nil); err == nil {
		t.Fatal("dial to a closed port")
	}
	if m.Addr().String() != "127.0.0.1:1#"+string(a.id) {
		t.Fatalf("advertised %s", m.Addr())
	}
	_ = tls.VersionTLS13
}
