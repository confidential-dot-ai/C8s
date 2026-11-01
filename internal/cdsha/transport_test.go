package cdsha

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// Raft RPCs and the control channel share one attested port, told apart by
// the first byte, and a Raft connection reaches the stream layer Raft accepts
// from.
func TestRaftConnectionReachesTheStreamLayer(t *testing.T) {
	dialing, listening := servingPair(t)

	outbound, err := dialing.mux.Dial(raft.ServerAddress(listening.raftAddress()), testCallTimeout)
	if err != nil {
		t.Fatalf("dial a peer: %v", err)
	}
	inbound := acceptRaft(t, listening.mux)
	if inbound == nil {
		t.Fatal("the stream layer accepted no connection")
	}

	if _, err := outbound.Write([]byte("rpc")); err != nil {
		t.Fatalf("write to a peer: %v", err)
	}
	read := make([]byte, 3)
	if _, err := inbound.Read(read); err != nil {
		t.Fatalf("read from a peer: %v", err)
	}
	if string(read) != "rpc" {
		t.Fatalf("the stream layer read %q, want rpc", read)
	}
}

// A Raft address names the member, so a process that took over an address
// does not answer for the member that held it.
func TestRaftDialRefusesAnotherMemberAtTheAddress(t *testing.T) {
	dialing, listening := servingPair(t)

	address := raft.ServerAddress(listening.peerAddress().String() + "#member-gone")
	if _, err := dialing.mux.Dial(address, testCallTimeout); err == nil {
		t.Fatal("dialled a member that does not answer at this address")
	}
}

// The receiver checks the same thing from its side: a Raft connection
// addressed to the member that held this address before is refused, so no
// vote or acknowledgement is counted for a member whose log is gone.
func TestRaftConnectionForAnotherMemberIsRefused(t *testing.T) {
	dialing, listening := servingPair(t)

	connection, _, err := dialing.mux.dial(listening.peerAddress().String(), muxRaft, testCallTimeout)
	if err != nil {
		t.Fatalf("dial a peer: %v", err)
	}
	defer connection.Close()
	if err := writeTarget(connection, "member-gone", testCallTimeout); err != nil {
		t.Fatalf("name the target member: %v", err)
	}

	if inbound := acceptRaft(t, listening.mux); inbound != nil {
		t.Fatal("the stream layer accepted a connection meant for another member")
	}
	if !closedByPeer(t, connection) {
		t.Fatal("the receiver kept a connection addressed to another member")
	}
}

// A control request carries the attested peer that made it, and its answer
// comes back over the same connection, which carries every request after it.
func TestControlRequestNamesTheAttestedPeer(t *testing.T) {
	dialing, listening := servingPair(t)

	held, err := dialing.mux.connect(listening.peerAddress(), testCallTimeout)
	if err != nil {
		t.Fatalf("connect to a peer: %v", err)
	}
	defer held.close()
	if held.member != listening.member {
		t.Fatalf("the handshake named member %q, want %q", held.member, listening.member)
	}
	for range 2 {
		answer, err := held.exchange(controlRequest{Op: opMember}, testCallTimeout)
		if err != nil {
			t.Fatalf("control request: %v", err)
		}
		if answer.Member != listening.member {
			t.Fatalf("answered by member %q, want %q", answer.Member, listening.member)
		}
		select {
		case from := <-listening.answered:
			if from.member != dialing.member {
				t.Fatalf("the handler was given member %q, want %q", from.member, dialing.member)
			}
		case <-time.After(testCallTimeout):
			t.Fatal("the handler was given no peer")
		}
	}
}

// Every answer names the member it comes from, and one from another member is
// no answer at all: a fork of this cluster answering where a member is known
// gives no status, no barrier and no write of that member's log.
func TestAnAnswerFromAnotherMemberIsRefused(t *testing.T) {
	dialing, listening := servingPair(t)

	held, err := dialing.mux.connect(listening.peerAddress(), testCallTimeout)
	if err != nil {
		t.Fatalf("connect to a peer: %v", err)
	}
	expecting := &controlConn{
		member: "member-gone",
		conn:   held.conn,
		stream: held.stream,
	}
	if _, err := expecting.exchange(controlRequest{Op: opMember}, testCallTimeout); err == nil {
		t.Fatal("an answer from another member was taken")
	}
	if _, err := held.exchange(controlRequest{Op: opMember}, testCallTimeout); err == nil {
		t.Fatal("the connection carried another request after an answer from another member")
	}
}

// Neither side speaks to a replica it does not admit, in either direction.
func TestConnectionBetweenReplicasThatDoNotAdmitEachOtherFails(t *testing.T) {
	t.Run("the receiver does not admit the dialer", func(t *testing.T) {
		dialing, listening := servingPair(t)
		listening.admits.hold(imagePin(t, otherImage, testLaunchFile))

		outbound, err := dialing.mux.Dial(raft.ServerAddress(listening.raftAddress()), testCallTimeout)
		if err == nil {
			t.Cleanup(func() { outbound.Close() })
		}
		if inbound := acceptRaft(t, listening.mux); inbound != nil {
			t.Fatal("the receiver handed Raft a peer it does not admit")
		}
	})

	t.Run("the dialer does not admit the receiver", func(t *testing.T) {
		dialing, listening := servingPair(t)
		dialing.admits.hold(imagePin(t, otherImage, testLaunchFile))

		_, err := dialing.mux.Dial(raft.ServerAddress(listening.raftAddress()), testCallTimeout)
		if !errors.Is(err, errPeerIdentity) {
			t.Fatalf("connected to a replica this one does not admit: %v", err)
		}
	})
}

// TLS admits a peer once, at the handshake, and Raft keeps its connections
// open. Every change of the admission set — joining a cluster included — cuts
// the connections the new set no longer admits.
func TestRecheckCutsAPeerTheAdmissionSetDropped(t *testing.T) {
	dialing, listening := servingPair(t)
	outbound, err := dialing.mux.Dial(raft.ServerAddress(listening.raftAddress()), testCallTimeout)
	if err != nil {
		t.Fatalf("dial a peer: %v", err)
	}
	inbound := acceptRaft(t, listening.mux)
	if inbound == nil {
		t.Fatal("the stream layer accepted no connection")
	}

	listening.admits.hold(imagePin(t, otherImage, testLaunchFile))
	listening.mux.recheck()

	if !closedByPeer(t, outbound) {
		t.Fatal("a peer the admission set dropped is still connected")
	}
	if live := livePeers(listening.mux); live != 0 {
		t.Fatalf("%d connections survived the admission-set change", live)
	}
}

// A connection the admission set still admits stays up: a recheck cuts what
// left the set, not every peer.
func TestRecheckKeepsAnAdmittedPeer(t *testing.T) {
	dialing, listening := servingPair(t)
	outbound, err := dialing.mux.Dial(raft.ServerAddress(listening.raftAddress()), testCallTimeout)
	if err != nil {
		t.Fatalf("dial a peer: %v", err)
	}
	if inbound := acceptRaft(t, listening.mux); inbound == nil {
		t.Fatal("the stream layer accepted no connection")
	}

	listening.mux.recheck()

	if closedByPeer(t, outbound) {
		t.Fatal("a recheck cut a peer the admission set still admits")
	}
}

// The port bounds the sockets it holds, handshakes included, so a host that
// opens connections cannot exhaust the replica.
func TestInboundSocketsAreBounded(t *testing.T) {
	listening := newSNPReplica(t, "member-b")
	listening.serve(t)

	for range maxInboundSockets {
		held, err := net.Dial("tcp", listening.peerAddress().String())
		if err != nil {
			t.Fatalf("dial the peer port: %v", err)
		}
		defer held.Close()
	}

	beyond, err := net.Dial("tcp", listening.peerAddress().String())
	if err != nil {
		t.Fatalf("dial the peer port: %v", err)
	}
	defer beyond.Close()
	if !closedByPeer(t, beyond) {
		t.Fatalf("the peer port holds more than %d sockets", maxInboundSockets)
	}
}

// Shutting the port down closes every connection behind it, and the stream
// layer stops handing Raft new ones.
func TestCloseCutsEveryConnection(t *testing.T) {
	dialing, listening := servingPair(t)
	outbound, err := dialing.mux.Dial(raft.ServerAddress(listening.raftAddress()), testCallTimeout)
	if err != nil {
		t.Fatalf("dial a peer: %v", err)
	}
	if inbound := acceptRaft(t, listening.mux); inbound == nil {
		t.Fatal("the stream layer accepted no connection")
	}

	if err := listening.mux.Close(); err != nil {
		t.Fatalf("close the peer port: %v", err)
	}

	if !closedByPeer(t, outbound) {
		t.Fatal("a connection survived shutdown")
	}
	if _, err := listening.mux.Accept(); !errors.Is(err, errTransportClosed) {
		t.Fatalf("the stream layer answered %v after shutdown", err)
	}
	if _, err := net.Dial("tcp", listening.peerAddress().String()); err == nil {
		t.Fatal("the peer port still listens after shutdown")
	}
}

// A Raft address is an endpoint and the member answering there.
func TestRaftAddressNamesEndpointAndMember(t *testing.T) {
	for _, tc := range []struct {
		name    string
		address string
		want    string
	}{
		{"an endpoint and a member", "10.1.0.4:8444#MEMBER1", "10.1.0.4:8444#MEMBER1"},
		{"an IPv6 endpoint", "[2001:db8::5]:8444#MEMBER1", "[2001:db8::5]:8444#MEMBER1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := parseRaftAddr(raft.ServerAddress(tc.address))
			if err != nil {
				t.Fatalf("parse %q: %v", tc.address, err)
			}
			if address.String() != tc.want {
				t.Fatalf("parsed %q as %q", tc.address, address)
			}
		})
	}

	for _, tc := range []struct {
		name    string
		address string
	}{
		{"no member", "10.1.0.4:8444"},
		{"an empty member", "10.1.0.4:8444#"},
		{"a name instead of an address", "replica-1.example.org:8444#MEMBER1"},
		{"no port", "10.1.0.4#MEMBER1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseRaftAddr(raft.ServerAddress(tc.address)); err == nil {
				t.Fatalf("parsed %q as a Raft address", tc.address)
			}
		})
	}
}

// A peer refused for good must show in the log, and a peer that keeps
// retrying must not fill it.
func TestRefusalIsLoggedOncePerInterval(t *testing.T) {
	log := newRefusalLog()
	now := time.Now()

	if !log.claim("host-1 handshake", now) {
		t.Fatal("the first refusal was not logged")
	}
	if log.claim("host-1 handshake", now.Add(refusalLogInterval/2)) {
		t.Fatal("a repeated refusal was logged again inside the interval")
	}
	if !log.claim("host-1 handshake", now.Add(refusalLogInterval)) {
		t.Fatal("a refusal was not logged again after the interval")
	}
}

// A refused peer chooses its own source host, so the keys are bounded, and
// filling them cannot flush the slot another host already holds.
func TestRefusalKeysAreBoundedAndNotFlushable(t *testing.T) {
	log := newRefusalLog()
	now := time.Now()
	log.claim("host-1 handshake", now)

	for key := range maxRefusalKeys * 2 {
		log.claim(fmt.Sprintf("10.0.0.%d handshake", key), now)
	}

	if len(log.seen) > maxRefusalKeys {
		t.Fatalf("the refusal log holds %d keys, over the bound of %d", len(log.seen), maxRefusalKeys)
	}
	if log.claim("host-1 handshake", now.Add(refusalLogInterval/2)) {
		t.Fatal("a flood of hosts flushed the slot another host held")
	}
	if !log.claim("host-1 handshake", now.Add(refusalLogInterval)) {
		t.Fatal("a refusal was not logged again after the interval")
	}
}

// servingPair is two replicas of this cluster's image, each serving its own
// peer port and admitting the other.
func servingPair(t *testing.T) (dialing, listening *testReplica) {
	t.Helper()
	dialing = newSNPReplica(t, "member-a")
	listening = newSNPReplica(t, "member-b")
	dialing.serve(t)
	listening.serve(t)
	return dialing, listening
}

// livePeers counts the attested connections the port still holds.
func livePeers(m *mux) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.peers)
}

// acceptRaft waits for a Raft connection to reach the stream layer, and
// reports none when the receiver refused it.
func acceptRaft(t *testing.T, m *mux) net.Conn {
	t.Helper()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := m.Accept()
		if err != nil {
			return
		}
		accepted <- connection
	}()
	select {
	case connection := <-accepted:
		return connection
	case <-time.After(time.Second):
		return nil
	}
}

// closedByPeer reports whether the other side closed the connection.
func closedByPeer(t *testing.T, connection net.Conn) bool {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set a read deadline: %v", err)
	}
	_, err := connection.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}
