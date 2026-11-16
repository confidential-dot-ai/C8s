package cdsha

import (
	"net/netip"
	"testing"
	"time"
)

const testDeadAfter = 20 * time.Second

// A member is known at the address it answered at, and every exchange with it
// goes over the connection it answered on.
func TestAMemberIsKnownWhereItAnswered(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	address := netip.MustParseAddrPort("10.0.0.1:8444")
	answering := &controlConn{member: "member-a"}

	if cut := m.answeredAt(address, answering, time.Now()); len(cut) != 0 {
		t.Fatalf("the answer of a member at an address of its own was not kept: %+v", cut)
	}

	held, reached := m.knownAt("member-a")
	if !reached || held.address != address || held.control != answering {
		t.Fatalf("the member is reached at %+v, it answered at %s", held, address)
	}
	if dial := m.toDial([]netip.AddrPort{address}, time.Now()); len(dial) != 0 {
		t.Fatalf("an address a member is known at is dialled again: %v", dial)
	}
}

// An address whose live members hand it back and forth is no replica's own:
// the host routes one address to several replicas, or the address is a
// load-balanced one. No member is known there, so it never becomes a Raft
// address.
func TestAnAddressItsMembersTakeTurnsAtIsNoReplicasOwn(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	address := netip.MustParseAddrPort("10.0.0.1:8444")
	at := time.Now()
	first := &controlConn{member: "member-a"}
	m.answeredAt(address, first, at)
	m.lost(m.reachedOrFail(t, "member-a"))
	m.answeredAt(address, &controlConn{member: "member-b"}, at.Add(time.Second))

	cut := m.answeredAt(address, first, at.Add(2*time.Second))

	if len(cut) != 2 {
		t.Fatalf("an address its members take turns at kept %d connections, want neither", 2-len(cut))
	}
	if !m.takingTurns(address) {
		t.Fatal("an address its members handed back and forth is one replica's own")
	}
	for _, member := range []string{"member-a", "member-b"} {
		if _, reached := m.knownAt(member); reached {
			t.Fatalf("%s is known at an address its members take turns at", member)
		}
	}
	if dial := m.toDial([]netip.AddrPort{address}, at.Add(2*time.Second)); len(dial) != 0 {
		t.Fatalf("an address its members take turns at is dialled again at once: %v", dial)
	}
}

// A replica restarted at its own address is a new member taking the address
// over, not two replicas sharing it: the new member is known there at once,
// whatever the clock says, because a restart is seconds and nothing hands the
// address back.
func TestAMemberThatTookOverAnAddressIsKnownThere(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	address := netip.MustParseAddrPort("10.0.0.1:8444")
	at := time.Now()
	gone := &controlConn{member: "member-a"}
	m.answeredAt(address, gone, at)
	m.lost(m.reachedOrFail(t, "member-a"))

	took := &controlConn{member: "member-b"}
	if cut := m.answeredAt(address, took, at.Add(time.Second)); len(cut) != 0 {
		t.Fatalf("the answer of the member that took the address was not kept: %+v", cut)
	}

	if m.takingTurns(address) {
		t.Fatal("one member replacing another at an address is taken for two taking turns")
	}
	if held, reached := m.knownAt("member-b"); !reached || held.control != took {
		t.Fatalf("the member that took the address is reached at %+v", held)
	}
}

// A member that answers where this replica already knows it is one member,
// not two: it stays known at the address it answered at first, so the
// cluster's Raft address for it does not follow every name the host answers.
func TestAMemberStaysKnownAtTheAddressItAnsweredAt(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	first := netip.MustParseAddrPort("10.0.0.1:8444")
	second := netip.MustParseAddrPort("10.0.0.2:8444")
	at := time.Now()
	m.answeredAt(first, &controlConn{member: "member-a"}, at)

	cut := m.answeredAt(second, &controlConn{member: "member-a"}, at)

	if len(cut) != 1 {
		t.Fatalf("the second address of one member kept %d connections", 1-len(cut))
	}
	if known, _ := m.knownAt("member-a"); known.address != first {
		t.Fatalf("the member is known at %s, it answered first at %s", known.address, first)
	}
}

// This replica's own address is one it answers at itself: it holds no
// connection to itself and asks itself to join no cluster.
func TestThisReplicasOwnAddressHoldsNoMember(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	address := netip.MustParseAddrPort("10.0.0.1:8444")

	cut := m.answeredAt(address, &controlConn{member: "own"}, time.Now())

	if len(cut) != 1 {
		t.Fatal("this replica holds a connection to itself")
	}
	if reached := m.reached(); len(reached) != 0 {
		t.Fatalf("this replica reached %+v", reached)
	}
}

// An address that did not answer is left alone for a while, so discovery
// costs one dial per address and backoff, not one per tick.
func TestAnAddressThatDidNotAnswerIsLeftAlone(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	address := netip.MustParseAddrPort("10.0.0.1:8444")
	resolved := []netip.AddrPort{address}
	at := time.Now()

	m.failed(address, at)

	if dial := m.toDial(resolved, at.Add(dialBackoff/2)); len(dial) != 0 {
		t.Fatalf("an address that failed is dialled again at once: %v", dial)
	}
	if dial := m.toDial(resolved, at.Add(dialBackoff)); len(dial) != 1 {
		t.Fatalf("an address that failed is never dialled again: %v", dial)
	}
}

// An address a complete pass of discovery no longer resolves to is no
// replica of this cluster. A pass that did not resolve every entry changes
// nothing: one lookup that failed is no evidence that a member left.
func TestAnAddressDiscoveryNoLongerFindsIsForgotten(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	address := netip.MustParseAddrPort("10.0.0.1:8444")
	answering := &controlConn{member: "member-a"}
	m.answeredAt(address, answering, time.Now())

	cut := m.forgetUnresolved(discovered{complete: true})

	if len(cut) != 1 || cut[0] != answering {
		t.Fatalf("forgetting the address cut %+v", cut)
	}
	if _, reached := m.knownAt("member-a"); reached {
		t.Fatal("a member is known at an address the cluster no longer names")
	}
}

// An incomplete pass of discovery forgets nothing.
func TestAnIncompletePassOfDiscoveryForgetsNoAddress(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	address := netip.MustParseAddrPort("10.0.0.1:8444")
	answering := &controlConn{member: "member-a"}
	m.answeredAt(address, answering, time.Now())

	if cut := m.forgetUnresolved(discovered{}); len(cut) != 0 {
		t.Fatalf("an incomplete pass cut %+v", cut)
	}
	if _, reached := m.knownAt("member-a"); !reached {
		t.Fatal("an incomplete pass of discovery forgot a member it had reached")
	}
}

// An address that answers with another member every time it is dialled is no
// replica's own. A replica entry resolving to a load-balanced address is what
// does that, and a member known at such an address would be unreachable at
// it: every Raft connection would land on another member and be refused.
func TestAnAddressAnsweringForSeveralMembersIsNoReplicasOwn(t *testing.T) {
	c := newLiveCluster(t)
	first := c.start()
	second := c.start()
	balanced := newRelay(t, 10*testTiming.Tick, first.peerAddress(), second.peerAddress())
	dialling := c.start()

	dialling.resolve.holds(balanced.address())

	eventually(t, 15*time.Second, "the load-balanced address answering for several members", func() bool {
		return dialling.node.peers.takingTurns(balanced.address())
	})
	for _, answering := range []*liveReplica{first, second} {
		if _, reached := dialling.node.peers.knownAt(string(answering.node.member)); reached {
			t.Fatalf("member %s is known at an address several members answer at", answering.node.member)
		}
	}
}

// takingTurns reports an address this replica took away from every member.
func (m *members) takingTurns(address netip.AddrPort) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	answering, known := m.addresses[address]
	return known && answering.takingTurns()
}

// reachedOrFail is the member this replica reached.
func (m *members) reachedOrFail(t *testing.T, member string) reachedMember {
	t.Helper()
	held, reached := m.knownAt(member)
	if !reached {
		t.Fatalf("member %s was not reached", member)
	}
	return held
}
