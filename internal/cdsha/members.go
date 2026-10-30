// Membership: where the members of this cluster answer.
//
// The host routes every packet and answers every name, so an address is only
// where to look. What counts is the member that answers there with its
// attested id: a member is known at the address it answered at, the cluster's
// Raft addresses are built from those answers, and an address whose replicas
// take turns answering is no replica's own. One connection per member carries
// every exchange with it, so discovery costs one handshake per member.

package cdsha

import (
	"context"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// dialBackoff is how long an address whose dial failed is left alone. A
// replica still booting answers nothing yet, so the wait is short.
const dialBackoff = 2 * time.Second

// members is what this replica knows about the addresses discovery resolves.
type members struct {
	// own is this replica's own member id: it holds no connection to itself.
	own       string
	deadAfter time.Duration

	mu        sync.Mutex
	addresses map[netip.AddrPort]*answeringAddress
}

// turnsShared is how many handovers make an address its replicas take turns
// at rather than one having replaced another: a restarted replica answers as
// a new member at the address the old one held, and hands it over once; a
// load-balanced address hands it back and forth.
const turnsShared = 2

// answeringAddress is one resolved address as this replica last reached it.
type answeringAddress struct {
	// seen is when each member answered here, while that answer is live.
	seen map[string]time.Time
	// turns counts the handovers between live members here, and answered is
	// the member that answered last.
	turns    int
	answered string
	// held is the connection to the member known here. It is nil for an
	// address of no member's own: this replica's own, one its replicas take
	// turns at, and one answering for a member known elsewhere.
	held *controlConn
	// quiet is when this replica dials an address it holds no connection to
	// again.
	quiet time.Time
}

// takingTurns reports an address whose live members have handed it back and
// forth, which one replacing another at it never does.
func (a *answeringAddress) takingTurns() bool {
	return a.turns >= turnsShared
}

func (a *answeringAddress) holds(member string) bool {
	return a.held != nil && a.held.member == member
}

// holdOff leaves an address that is no member's own alone until the answers
// that made it so have aged out, and reports the connection held there.
func (a *answeringAddress) holdOff(now time.Time, deadAfter time.Duration) []*controlConn {
	a.quiet = now.Add(deadAfter)
	held := a.held
	a.held = nil
	if held == nil {
		return nil
	}
	return []*controlConn{held}
}

// forgetStaleAnswers: a member counts as answering here only while its answer
// is live, and handovers between members no longer both here count for
// nothing.
func (a *answeringAddress) forgetStaleAnswers(now time.Time, deadAfter time.Duration) {
	for member, at := range a.seen {
		if now.Sub(at) >= deadAfter {
			delete(a.seen, member)
		}
	}
	if len(a.seen) < 2 {
		a.turns = 0
	}
}

type reachedMember struct {
	member  string
	address netip.AddrPort
	control *controlConn
}

func newMembers(own string, deadAfter time.Duration) *members {
	return &members{
		own:       own,
		deadAfter: deadAfter,
		addresses: map[netip.AddrPort]*answeringAddress{},
	}
}

// reached is every member this replica holds a connection to.
func (m *members) reached() []reachedMember {
	m.mu.Lock()
	defer m.mu.Unlock()
	var reached []reachedMember
	for address, answering := range m.addresses {
		if answering.held != nil {
			reached = append(reached, reachedMember{
				member:  answering.held.member,
				address: address,
				control: answering.held,
			})
		}
	}
	return reached
}

// knownAt is a member as this replica reached it.
func (m *members) knownAt(member string) (reachedMember, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for address, answering := range m.addresses {
		if answering.holds(member) {
			return reachedMember{
				member:  member,
				address: address,
				control: answering.held,
			}, true
		}
	}
	return reachedMember{}, false
}

func (m *members) toDial(resolved []netip.AddrPort, now time.Time) []netip.AddrPort {
	m.mu.Lock()
	defer m.mu.Unlock()
	var dial []netip.AddrPort
	for _, address := range resolved {
		if m.toLookAt(address, now) {
			dial = append(dial, address)
		}
	}
	return dial
}

// toLookAt: no connection held to it, and it is not held off (m.mu held).
func (m *members) toLookAt(address netip.AddrPort, now time.Time) bool {
	answering, known := m.addresses[address]
	if !known {
		return true
	}
	return answering.held == nil && !now.Before(answering.quiet)
}

// answeredAt records the member that answered at an address, on the
// connection it answered on, and reports the connections to close: the one
// that answered, where the address is no member's own, and the one held there
// before it.
func (m *members) answeredAt(address netip.AddrPort, control *controlConn, now time.Time) []*controlConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	answering := m.record(address, control.member, now)
	if answering.takingTurns() {
		m.alarmTakingTurns(address, answering)
		return append(answering.holdOff(now, m.deadAfter), control)
	}
	if control.member == m.own || m.knownElsewhere(address, control.member) {
		// This replica answers here itself, or the member answering is known
		// at another address: a second name for one replica names no second
		// replica.
		return append(answering.holdOff(now, m.deadAfter), control)
	}
	answering.held = control
	return nil
}

// stillThere records a member answering where it is known, so the answers of
// every other member there age out.
func (m *members) stillThere(held reachedMember, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if answering := m.addresses[held.address]; answering != nil && answering.held == held.control {
		m.record(held.address, held.member, now)
	}
}

// lost forgets a member whose connection failed. Its address is dialled
// again: the member may have moved, or another may have taken the address.
func (m *members) lost(held reachedMember) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if answering := m.addresses[held.address]; answering != nil && answering.held == held.control {
		answering.held = nil
	}
}

func (m *members) failed(address netip.AddrPort, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.address(address).quiet = now.Add(dialBackoff)
}

// forgetUnresolved drops every address a complete pass of discovery no longer
// resolves to, and reports the connections to close with them. A pass that
// did not resolve every entry changes nothing: an entry that failed to
// resolve is no evidence that a member left.
func (m *members) forgetUnresolved(found discovered) []*controlConn {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !found.complete {
		return nil
	}
	var cut []*controlConn
	for address, answering := range m.addresses {
		if slices.Contains(found.addresses, address) {
			continue
		}
		if answering.held != nil {
			cut = append(cut, answering.held)
		}
		delete(m.addresses, address)
	}
	return cut
}

// address is what this replica knows about one address (m.mu held).
func (m *members) address(address netip.AddrPort) *answeringAddress {
	answering, known := m.addresses[address]
	if !known {
		answering = &answeringAddress{seen: map[string]time.Time{}}
		m.addresses[address] = answering
	}
	return answering
}

// record is the answer of a member at an address: it counts a handover where
// the member answering is not the one that answered last here (m.mu held).
func (m *members) record(address netip.AddrPort, member string, now time.Time) *answeringAddress {
	answering := m.address(address)
	answering.forgetStaleAnswers(now, m.deadAfter)
	if answering.answered != "" && answering.answered != member {
		answering.turns++
	}
	answering.answered = member
	answering.seen[member] = now
	return answering
}

// knownElsewhere (m.mu held).
func (m *members) knownElsewhere(address netip.AddrPort, member string) bool {
	for known, answering := range m.addresses {
		if known != address && answering.holds(member) {
			return true
		}
	}
	return false
}

// alarmTakingTurns: no member is known at such an address, so it never
// becomes a Raft address (m.mu held).
func (m *members) alarmTakingTurns(address netip.AddrPort, answering *answeringAddress) {
	slog.Error("cds-ha: ALARM: the replicas of this cluster take turns answering at one address, so none of them is known there; a replica entry resolves to the replicas themselves, never to a load-balanced address",
		"address", address, "members", slices.Sorted(maps.Keys(answering.seen)), "turns", answering.turns)
}

// reachMembers keeps this replica's picture of its cluster current until ctx
// ends.
func (n *Node) reachMembers(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	for {
		n.reachPeers(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// reachPeers is one pass of discovery.
func (n *Node) reachPeers(ctx context.Context) {
	found := n.discover(ctx)
	n.forgetUnresolved(found)
	n.recheckReached()
	n.dialUnknown(found)
}

func (n *Node) forgetUnresolved(found discovered) {
	closeAll(n.peers.forgetUnresolved(found))
}

func (n *Node) recheckReached() {
	atOnce(n.peers.reached(), n.recheck)
}

// dialUnknown dials the resolved addresses this replica knows no member at.
func (n *Node) dialUnknown(found discovered) {
	atOnce(n.peers.toDial(found.addresses, time.Now()), n.reach)
}

// atOnce runs work for every address of a pass at the same time, so one that
// waits on the network does not hold up the rest of the pass.
func atOnce[T any](items []T, work func(T)) {
	var running sync.WaitGroup
	for _, item := range items {
		running.Add(1)
		go func() {
			defer running.Done()
			work(item)
		}()
	}
	running.Wait()
}

func (n *Node) recheck(held reachedMember) {
	if _, err := held.control.exchange(controlRequest{Op: opMember}, controlTimeout); err != nil {
		slog.Info("cds-ha: a member of this cluster stopped answering where this replica reached it", "member", held.member, "address", held.address, "error", err)
		n.peers.lost(held)
		return
	}
	n.peers.stillThere(held, time.Now())
}

// reach holds the connection to whichever member answers at an address.
func (n *Node) reach(address netip.AddrPort) {
	control, err := n.mux.connect(address, controlTimeout)
	if err != nil {
		n.peers.failed(address, time.Now())
		return
	}
	closeAll(n.peers.answeredAt(address, control, time.Now()))
}

func closeAll(connections []*controlConn) {
	for _, connection := range connections {
		connection.close()
	}
}
