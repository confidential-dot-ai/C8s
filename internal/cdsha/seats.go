// The voter seats of a cluster: N seats the first caught-up members fill,
// while every other replica follows the log as a non-voter and serves reads.
// A Genesis takes N from the configuration its replicas booted, and a
// SetVoters decree moves it afterwards.
//
// Only the leader seats a member, and it makes one change at a time: the next
// waits until every voter that stays holds the last one. Raft counts a vote
// only from a member its receiver holds as a voter, so a voter that holds an
// older configuration refuses the votes of the member just seated, and a
// group that lost this leader would elect none.
//
// A dead voter keeps its vote until a caught-up non-voter sits beside it. The
// log lives in the replicas' memory, so a configuration whose majority does
// not carry the log is a lost cluster, and a host that cuts a voter off must
// not cost the cluster a copy of it.
//
// A seat change never moves a member: a voter's address stays as it is, and a
// non-voter that answers elsewhere is moved before it takes a seat
// (members.go).

package cdsha

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// Bounded because the host chooses which of its replicas ask to follow.
const maxNonVoters = 16

func (n *Node) seats() int {
	return n.fsm.ClusterState().Voters
}

// seating is one leader pass's view: voters are staying plus deadVoters.
type seating struct {
	seats int
	// A voter set confirmed in one term is confirmed for that term alone.
	term          uint64
	voters        []raft.Server
	staying       []raft.Server
	deadVoters    []raft.Server
	nonVoters     []raft.Server
	deadNonVoters []raft.Server
	members       []raft.ServerID
}

func (s seating) freeSeats() int {
	return max(0, s.seats-len(s.staying))
}

func (s seating) surplusVoters() int {
	return max(0, len(s.staying)-s.seats)
}

func (s seating) filled() bool {
	return s.freeSeats() == 0 && len(s.deadVoters) == 0
}

// seatBook carries the seats between this leader's passes.
type seatBook struct {
	mu      sync.Mutex
	sighted map[raft.ServerID]time.Time
	agreed  []raft.ServerID
	term    uint64
}

func newSeatBook() *seatBook {
	return &seatBook{sighted: map[raft.ServerID]time.Time{}}
}

// Records now as the first sight of a member not seen before.
func (b *seatBook) sightedAt(member raft.ServerID, now time.Time) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, seen := b.sighted[member]; !seen {
		b.sighted[member] = now
	}
	return b.sighted[member]
}

func (b *seatBook) firstSight(member raft.ServerID) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sighted[member]
}

func (b *seatBook) forgetMembersGone(members []raft.ServerID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for member := range b.sighted {
		if !slices.Contains(members, member) {
			delete(b.sighted, member)
		}
	}
}

func (b *seatBook) agreesOn(term uint64, voters []raft.ServerID) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.term == term && slices.Equal(b.agreed, voters)
}

func (b *seatBook) agree(term uint64, voters []raft.ServerID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.term = term
	b.agreed = voters
}

// Sorted, so two voter sets compare whatever order a configuration holds them in.
func voterSet(servers []raft.Server) []raft.ServerID {
	members := make([]raft.ServerID, 0, len(servers))
	for _, server := range servers {
		members = append(members, server.ID)
	}
	slices.Sort(members)
	return members
}

// A loop of its own: asking a member where it stands waits on the network.
func (n *Node) keepSeating(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n.keepSeats()
		n.raiseFormat()
	}
}

// One change a pass, in the order that keeps a majority carrying the log.
func (n *Node) keepSeats() {
	if !n.leading() {
		return
	}
	seen, held := n.seatingNow()
	if !held {
		return
	}
	n.seatbook.forgetMembersGone(seen.members)
	n.confirmVoters(seen)
	if n.takeOutDeadNonVoter(seen) {
		return
	}
	if n.fillFreeSeat(seen) {
		return
	}
	if n.retireDeadVoter(seen) {
		return
	}
	n.demoteSurplusVoter(seen)
}

// Reports no seating before the cluster has started.
func (n *Node) seatingNow() (seating, bool) {
	core := n.fsm.ClusterState()
	servers := n.configuration()
	if !core.Joined() || len(servers) == 0 {
		return seating{}, false
	}
	now := time.Now()
	seen := seating{seats: core.Voters, term: n.raft.Load().CurrentTerm()}
	for _, server := range servers {
		seen.members = append(seen.members, server.ID)
		dead := n.countsDead(seen.term, server.ID, now)
		switch {
		case server.Suffrage == raft.Voter:
			seen.voters = append(seen.voters, server)
			if dead {
				seen.deadVoters = append(seen.deadVoters, server)
				continue
			}
			seen.staying = append(seen.staying, server)
		case dead:
			seen.deadNonVoters = append(seen.deadNonVoters, server)
		default:
			seen.nonVoters = append(seen.nonVoters, server)
		}
	}
	return seen, true
}

// Dead to this leader: silent for DeadAfter, or its heartbeats failing that
// long in the term this leader holds (liveness.go).
func (n *Node) countsDead(term uint64, member raft.ServerID, now time.Time) bool {
	if string(member) == string(n.member) {
		return false
	}
	return now.Sub(n.lastAnswerOrFirstSight(member, now)) >= n.cfg.Timing.DeadAfter ||
		n.failures.failingFor(term, member, now) >= n.cfg.Timing.DeadAfter
}

// A leader that has just taken over has reached nobody, so first sight gives
// every member DeadAfter to answer.
func (n *Node) lastAnswerOrFirstSight(member raft.ServerID, now time.Time) time.Time {
	if answered := n.peers.lastAnswer(string(member)); !answered.IsZero() {
		return answered
	}
	return n.seatbook.sightedAt(member, now)
}

func (n *Node) takeOutDeadNonVoter(seen seating) bool {
	if len(seen.deadNonVoters) == 0 {
		return false
	}
	leaving := seen.deadNonVoters[0]
	if !n.takeOut(leaving.ID) {
		return false
	}
	slog.Info("cds-ha: a non-voter of this cluster stopped answering and left it",
		"member", leaving.ID)
	return true
}

func (n *Node) fillFreeSeat(seen seating) bool {
	if seen.freeSeats() == 0 || !n.everyVoterHolds(seen) {
		return false
	}
	candidate, found := n.nextToSeat(seen)
	if !found {
		return false
	}
	// INVARIANT: the seat is taken at the configuration's own address; a
	// member that answers elsewhere moves as a non-voter (members.go).
	if err := n.raft.Load().AddVoter(candidate.ID, candidate.Address, 0, n.cfg.Timing.Apply).Error(); err != nil {
		slog.Warn("cds-ha: this leader could not seat a voter of its cluster",
			"member", candidate.ID,
			"error", err)
		return false
	}
	slog.Info("cds-ha: a replica of this cluster took a voter seat",
		"member", candidate.ID,
		"seats", seen.seats)
	return true
}

// A replica the host restarts answers at the address of the process it
// replaces, so a claim on a dead voter's address comes before any spare.
func (n *Node) nextToSeat(seen seating) (raft.Server, bool) {
	if claiming := n.replacements(seen); len(claiming) > 0 {
		return n.firstCaughtUp(claiming)
	}
	return n.firstCaughtUp(n.spares(seen))
}

func (n *Node) replacements(seen seating) []raft.Server {
	vacated := vacatedAddresses(seen)
	var claiming []raft.Server
	for _, candidate := range seen.nonVoters {
		if n.answersAtOneOf(candidate.ID, vacated) {
			claiming = append(claiming, candidate)
		}
	}
	return claiming
}

func (n *Node) spares(seen seating) []raft.Server {
	vacated := vacatedAddresses(seen)
	var free []raft.Server
	for _, candidate := range seen.nonVoters {
		if !n.answersAtOneOf(candidate.ID, vacated) {
			free = append(free, candidate)
		}
	}
	return free
}

func (n *Node) firstCaughtUp(candidates []raft.Server) (raft.Server, bool) {
	for _, candidate := range candidates {
		if n.caughtUp(candidate.ID) {
			return candidate, true
		}
	}
	return raft.Server{}, false
}

func vacatedAddresses(seen seating) []netip.AddrPort {
	var vacated []netip.AddrPort
	for _, server := range seen.deadVoters {
		address, err := parseRaftAddr(server.Address)
		if err != nil {
			continue
		}
		vacated = append(vacated, address.endpoint)
	}
	return vacated
}

// No member is known at an address its replicas take turns at, so none
// supersedes a voter by it (members.go).
func (n *Node) answersAtOneOf(member raft.ServerID, addresses []netip.AddrPort) bool {
	held, reached := n.peers.knownAt(string(member))
	return reached && slices.Contains(addresses, held.address)
}

// A trailing member would raise the majority the cluster needs without adding
// a copy of the log that majority must hold.
func (n *Node) caughtUp(member raft.ServerID) bool {
	appliedBeforeAsking := n.fsm.AppliedIndex()
	answer, err := n.askStanding(member)
	if err != nil {
		slog.Info("cds-ha: this leader could not ask a replica how far it has followed the log",
			"member", member,
			"error", err)
		return false
	}
	return answer.Applied >= appliedBeforeAsking
}

// Whichever staying voter survives this leader must already hold a
// configuration that elects a leader without the voter that left.
func (n *Node) retireDeadVoter(seen seating) bool {
	if len(seen.deadVoters) == 0 || seen.freeSeats() > 0 || !n.everyVoterHolds(seen) {
		return false
	}
	retiring := seen.deadVoters[0]
	if !n.takeOut(retiring.ID) {
		return false
	}
	slog.Info("cds-ha: a dead voter of this cluster gave up its seat",
		"audit", true,
		"member", retiring.ID)
	return true
}

func (n *Node) demoteSurplusVoter(seen seating) bool {
	if seen.surplusVoters() == 0 || !n.everyVoterHolds(seen) {
		return false
	}
	surplus, found := n.quietestVoter(seen)
	if !found {
		return false
	}
	if err := n.raft.Load().DemoteVoter(surplus.ID, 0, n.cfg.Timing.Apply).Error(); err != nil {
		slog.Warn("cds-ha: this leader could not take the vote of a surplus voter",
			"member", surplus.ID,
			"error", err)
		return false
	}
	slog.Info("cds-ha: a voter of this cluster gave up its seat; the cluster holds fewer",
		"member", surplus.ID,
		"seats", seen.seats)
	return true
}

// This leader is no candidate: taking its own vote calls an election for itself.
func (n *Node) quietestVoter(seen seating) (raft.Server, bool) {
	var quietest raft.Server
	var since time.Time
	now := time.Now()
	for _, server := range seen.staying {
		if string(server.ID) == string(n.member) {
			continue
		}
		answered := n.lastAnswerOrFirstSight(server.ID, now)
		if quietest.ID == "" || answered.Before(since) {
			quietest = server
			since = answered
		}
	}
	return quietest, quietest.ID != ""
}

func (n *Node) takeOut(member raft.ServerID) bool {
	if err := n.raft.Load().RemoveServer(member, 0, n.cfg.Timing.Apply).Error(); err != nil {
		slog.Warn("cds-ha: this leader could not take a member out of its cluster",
			"member", member,
			"error", err)
		return false
	}
	return true
}

func (n *Node) everyVoterHolds(seen seating) bool {
	return n.seatbook.agreesOn(seen.term, voterSet(seen.voters))
}

// Asks once per change: a settled cluster asks nobody.
func (n *Node) confirmVoters(seen seating) {
	voters := voterSet(seen.voters)
	if n.seatbook.agreesOn(seen.term, voters) {
		return
	}
	if !n.everyStayingVoterHolds(seen, voters) {
		return
	}
	n.seatbook.agree(seen.term, voters)
}

func (n *Node) everyStayingVoterHolds(seen seating, voters []raft.ServerID) bool {
	for _, server := range seen.staying {
		if string(server.ID) == string(n.member) {
			continue
		}
		if !n.memberHoldsVoters(server.ID, voters) {
			return false
		}
	}
	return true
}

func (n *Node) memberHoldsVoters(member raft.ServerID, voters []raft.ServerID) bool {
	answer, err := n.askStanding(member)
	if err != nil {
		slog.Info("cds-ha: this leader could not ask a voter which voters it holds",
			"member", member,
			"error", err)
		return false
	}
	return holdsEvery(answer.Voters, voters)
}

func holdsEvery(held []string, voters []raft.ServerID) bool {
	for _, voter := range voters {
		if !slices.Contains(held, string(voter)) {
			return false
		}
	}
	return true
}

func (n *Node) askStanding(member raft.ServerID) (controlAnswer, error) {
	held, reached := n.peers.knownAt(string(member))
	if !reached {
		return controlAnswer{}, fmt.Errorf("cds-ha: this replica has reached no member %s", member)
	}
	return held.control.exchange(controlRequest{Op: opStanding}, controlTimeout)
}

func (n *Node) answerStanding(answer controlAnswer) controlAnswer {
	for _, server := range n.configuration() {
		if server.Suffrage == raft.Voter {
			answer.Voters = append(answer.Voters, string(server.ID))
		}
	}
	led := n.following()
	answer.Leader = string(led.member)
	answer.Term = led.term
	answer.Applied = n.fsm.AppliedIndex()
	answer.Stuck = n.fsm.Stuck()
	answer.Reads = n.fsm.readable
	return answer
}

func (n *Node) nonVotersFull() bool {
	taken := 0
	for _, server := range n.configuration() {
		if server.Suffrage != raft.Voter {
			taken++
		}
	}
	return taken >= maxNonVoters
}
