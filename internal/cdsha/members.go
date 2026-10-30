// Membership: where the members of this cluster answer, and how a replica
// gets into its configuration.
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
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/raft"
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
	// replied is when repliedBy last answered a request of this replica.
	replied   time.Time
	repliedBy string
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

// raftAddress is where Raft reaches this member.
func (r reachedMember) raftAddress() raft.ServerAddress {
	return raftAddr{
		endpoint: r.address,
		member:   r.member,
	}.serverAddress()
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

// A handshake is no answer: a peer that refuses this replica completes one
// and then carries nothing.
func (m *members) lastAnswer(member string) time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	var last time.Time
	for _, answering := range m.addresses {
		if answering.repliedBy == member && answering.replied.After(last) {
			last = answering.replied
		}
	}
	return last
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

// The answers of every other member at that address age out.
func (m *members) stillThere(held reachedMember, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if answering := m.addresses[held.address]; answering != nil && answering.held == held.control {
		m.record(held.address, held.member, now)
		answering.replied = now
		answering.repliedBy = held.member
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
		found := n.reachPeers(ctx)
		if n.settled() {
			n.followMoves()
			n.askBackIn()
		} else {
			n.joinOrStart(found)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// reachPeers is one pass of discovery.
func (n *Node) reachPeers(ctx context.Context) discovered {
	found := n.discover(ctx)
	n.forgetUnresolved(found)
	n.recheckReached()
	n.dialUnknown(found)
	return found
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

// settled reports a replica the cluster's configuration names and that holds
// the cluster's state. One that is not asks the members it reached to let it
// in, or starts the cluster the operator decreed it starts.
func (n *Node) settled() bool {
	return n.inConfiguration() && n.fsm.ClusterState().Joined()
}

func (n *Node) inConfiguration() bool {
	return n.memberOfCluster(string(n.member))
}

func (n *Node) memberOfCluster(member string) bool {
	_, named := n.configuredAs(member)
	return named
}

// configuredAs is a member's place in the cluster's configuration: the vote
// it holds and the address the cluster reaches it at.
func (n *Node) configuredAs(member string) (raft.Server, bool) {
	for _, server := range n.configuration() {
		if server.ID == raft.ServerID(member) {
			return server, true
		}
	}
	return raft.Server{}, false
}

func (n *Node) configuration() []raft.Server {
	future := n.raft.Load().GetConfiguration()
	if err := future.Error(); err != nil {
		return nil
	}
	return future.Configuration().Servers
}

// followMoves gives Raft the address a member answers at now: the host routes
// every packet, so the address in the configuration may reach it no longer.
func (n *Node) followMoves() {
	if !n.leading() {
		return
	}
	for _, server := range n.configuration() {
		if moved, elsewhere := n.movedTo(server); elsewhere {
			n.moveMember(server, moved)
		}
	}
}

// movedTo is where a non-voter of the cluster answers now, when that is not
// the address the configuration holds. A voter stays where it is: its vote
// must not leave the configuration to come back, and a voter no one can reach
// is a dead voter.
func (n *Node) movedTo(server raft.Server) (reachedMember, bool) {
	if server.Suffrage == raft.Voter {
		return reachedMember{}, false
	}
	held, reached := n.peers.knownAt(string(server.ID))
	if !reached || server.Address == held.raftAddress() {
		return reachedMember{}, false
	}
	return held, true
}

func (n *Node) moveMember(server raft.Server, moved reachedMember) {
	slog.Info("cds-ha: a member of this cluster answers at another address", "member", server.ID, "was", server.Address, "now", moved.raftAddress())
	if err := n.raft.Load().RemoveServer(server.ID, 0, n.cfg.Timing.Apply).Error(); err != nil {
		slog.Warn("cds-ha: this leader could not take out a member that moved", "member", server.ID, "error", err)
		return
	}
	if err := n.addNonVoter(moved); err != nil {
		slog.Warn("cds-ha: this leader could not take in a member that moved", "member", server.ID, "address", moved.raftAddress(), "error", err)
	}
}

// joinOrStart is what a replica outside its cluster does every tick: take the
// images the operator decreed it admits, ask the members it reached to take
// it in, and, where the operator decreed this process the start of the
// cluster, start it.
func (n *Node) joinOrStart(found discovered) {
	n.admitAsDecreed()
	answers := n.askToJoin()
	if answers.cluster {
		return
	}
	decree, decreed := n.decreedGenesis()
	if !decreed {
		return
	}
	if err := n.startable(decree.Decree.Alone, found, answers); err != nil {
		if n.genesisLog.changed(err.Error()) {
			slog.Warn("cds-ha: this replica is decreed the start of its cluster and starts none", "error", err)
		}
		return
	}
	n.startCluster(decree)
}

// askBackIn asks the members this replica reached to take it back in, while
// it holds the cluster and follows no leader: a cluster that re-formed
// without this member takes it back, and one that cut this member out
// answers so, which only a restart of this process cures (fence.go).
func (n *Node) askBackIn() {
	if n.following().known() {
		return
	}
	for _, held := range n.peers.reached() {
		answer, _, err := n.askMember(held)
		if err == nil && answer.Excluded {
			n.excluded.Store(true)
			return
		}
	}
}

// peerAnswers is what the members this replica reached said of the cluster.
type peerAnswers struct {
	// cluster reports a cluster that exists: this replica is in it, or a
	// member that holds it answered. Either keeps this replica from starting
	// one.
	cluster bool
	// answered reports a member that answered at all, which is how this
	// replica knows a cluster would not be a second one.
	answered bool
}

// askToJoin asks every member this replica reached to take it in.
func (n *Node) askToJoin() peerAnswers {
	var answers peerAnswers
	for _, held := range n.peers.reached() {
		answer, joined, err := n.askMember(held)
		if err != nil {
			continue
		}
		answers.answered = true
		answers.cluster = answers.cluster || joined
		if answer.Err == "" {
			answers.cluster = true
			n.logInTheCluster(held)
			return answers
		}
		n.logNotTakenIn(held, answer.Err)
	}
	return answers
}

// askMember asks one member to take this replica in, and the leader it names
// where that member follows one. Either of them holding a cluster keeps this
// replica from starting another.
func (n *Node) askMember(held reachedMember) (controlAnswer, bool, error) {
	request := controlRequest{
		Op:     opJoin,
		Policy: n.fsm.LocalPolicy(),
	}
	answer, err := held.control.exchange(request, controlTimeout)
	if err != nil {
		return answer, false, err
	}
	leader, follows := n.leaderBesides(held, answer)
	if !follows {
		return answer, answer.Joined, nil
	}
	fromLeader, err := leader.control.exchange(request, controlTimeout)
	if err != nil {
		return answer, answer.Joined, nil
	}
	return fromLeader, answer.Joined || fromLeader.Joined, nil
}

// leaderBesides is the leader an answer names, where it is another member
// this replica reached.
func (n *Node) leaderBesides(held reachedMember, answer controlAnswer) (reachedMember, bool) {
	if answer.Leader == "" || answer.Leader == held.member {
		return reachedMember{}, false
	}
	return n.peers.knownAt(answer.Leader)
}

func (n *Node) logInTheCluster(held reachedMember) {
	if n.joinLog.changed(held.member) {
		slog.Info("cds-ha: this replica is in its cluster", "via", held.member, "member", n.member)
	}
}

func (n *Node) logNotTakenIn(held reachedMember, refused string) {
	if n.joinLog.changed(held.member + " " + refused) {
		slog.Info("cds-ha: a member of this cluster did not take this replica in", "member", held.member, "error", refused)
	}
}

// answerJoin takes the member asking into the cluster as a non-voter, at the
// address this leader reached it at: an address only the joiner vouches for
// is no address of the cluster's.
func (n *Node) answerJoin(from peer, policy Policy, answer controlAnswer) controlAnswer {
	if !n.leading() {
		return n.redirectToLeader(answer)
	}
	if err := n.admissible(policy); err != nil {
		answer.Err = err.Error()
		return answer
	}
	if server, named := n.configuredAs(from.member); named {
		if server.Address == excludedAddress {
			return cutOutOfCluster(from.member, answer)
		}
		// The member is in the configuration: its vote and its address are
		// the cluster's to change, not a joiner's.
		return answer
	}
	if n.nonVotersFull() {
		answer.Err = fmt.Sprintf("this cluster follows its log with the %d non-voters it takes",
			maxNonVoters)
		return answer
	}
	held, reached := n.peers.knownAt(from.member)
	if !reached {
		answer.Err = "this leader has reached no member " + from.member + " at any address of its cluster"
		return answer
	}
	if err := n.addNonVoter(held); err != nil {
		answer.Err = err.Error()
	}
	return answer
}

// cutOutOfCluster answers a member this cluster cut out: its log may hold
// entries of a recovered cluster, which no replica can tell from this
// cluster's, so only a restart of that process rejoins (fence.go).
func cutOutOfCluster(member string, answer controlAnswer) controlAnswer {
	slog.Warn("cds-ha: a member this cluster cut out asked to come back; it rejoins only as a new member", "member", member)
	answer.Excluded = true
	answer.Err = "this cluster cut member " + member + " out; restart the replica to rejoin as a new member"
	return answer
}

// admissible refuses a replica whose stores hold other limits than the
// cluster's policy: it could not apply the log it would be sent.
func (n *Node) admissible(policy Policy) error {
	core := n.fsm.ClusterState()
	switch {
	case !core.Joined():
		return errors.New("this cluster has not started yet")
	case policy != core.Policy:
		return fmt.Errorf("the cluster applies commands under %+v, and the replica asking holds %+v", core.Policy, policy)
	}
	return nil
}

// addNonVoter adds a member that follows the log and serves reads; voter
// seats are filled from the members that caught up.
func (n *Node) addNonVoter(held reachedMember) error {
	if err := n.raft.Load().AddNonvoter(raft.ServerID(held.member), held.raftAddress(), 0, n.cfg.Timing.Apply).Error(); err != nil {
		return err
	}
	slog.Info("cds-ha: a replica joined this cluster as a non-voter", "member", held.member, "address", held.raftAddress())
	return nil
}
