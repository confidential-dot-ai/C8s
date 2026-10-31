// Fencing: when a replica of this cluster serves nothing.
//
// A Recover decree hands the cluster to one voter alone (recover.go). Neither
// that voter nor the rest can tell a majority that is gone from one the host
// merely cut them off from, so each side gives the other up:
//
//   - A cluster that sees a signed Recover naming a member that does not
//     answer here commits a doubt of it. Every replica then serves nothing
//     until that member rejoins or the operator dismisses the decree, because
//     that member may be carrying the cluster on alone.
//   - A leader that cannot read the board while a member is cut off serves
//     nothing either: the decree it cannot see may name that member. In a
//     term it has read no board in, every member that has not reported it as
//     its leader counts as cut off.
//
// A member that may be carrying a recovered cluster is cut out of the
// configuration as well, so that Raft never merges two histories. A voter is
// cut out as a vote at an address that reaches nobody rather than removed:
// removing it would free its seat before a replacement held the
// configuration, and its member id could come back with a log whose entries
// share index and term with this cluster's but not their content. It leaves
// as a dead voter does, once a replacement holds a seat (seats.go), and the
// process behind it rejoins only as a new member with an empty log.

package cdsha

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// boardLease is how long a leader's reading of its cluster's board stays
// fresh. Past it, a Recover decree may be lying on the board unseen.
func (t Timing) boardLease() time.Duration {
	return 2 * t.DeadAfter
}

// recoverHold is how long the replica a Recover decree names holds off before
// it carries the cluster on alone: the board lease a cluster that still has a
// majority doubts the decree inside, the write that doubt takes, the lease the
// reads it answered run out in, and two turns of a replica's loop.
func (t Timing) recoverHold() time.Duration {
	return t.boardLease() + t.Apply + t.Lease + 2*t.Tick
}

// Fence is why a replica of this cluster serves nothing.
type Fence struct {
	Reason string `json:"reason"`
	// Doubt and Member name the Recover decree this cluster doubts, and the
	// member it hands the cluster to: the decree a DismissRecover names, and
	// the replica to bring back.
	Doubt  string `json:"doubt,omitempty"`
	Member string `json:"member,omitempty"`
	// CutOff are the members this leader counts as cut off, which are the
	// replicas to bring back.
	CutOff []string `json:"cut_off,omitempty"`
}

// ErrFenced refuses a read or a write to a fenced cluster.
var ErrFenced = errors.New("cds-ha: this cluster is fenced")

// Fenced is why this replica serves nothing, and nil where it serves: what an
// operator reads to tell a fenced cluster from a lost one. It asks no peer
// and writes nothing, so every read and write path may ask it.
func (n *Node) Fenced() *Fence {
	if fence := n.doubtFence(); fence != nil {
		return fence
	}
	return n.leaderFence()
}

// fenced is what a fenced replica answers a client read or write with, and
// nil where it serves. The entries its leader writes itself go on the log
// either way: the doubt that fences the cluster, and the decrees that lift
// the fence.
func (n *Node) fenced() error {
	fence := n.Fenced()
	if fence == nil {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrFenced, fence.Reason)
}

// alarmWhenFenced raises the alarm of a fenced replica, once for as long as
// the reason holds. Run raises it, so the fence is reported by the replica's
// own loop rather than by whichever read met it.
func (n *Node) alarmWhenFenced() {
	fence := n.Fenced()
	if fence == nil {
		return
	}
	if n.fenceLog.changed(fence.Reason) {
		slog.Error("cds-ha: ALARM: this replica is fenced: it serves no read and takes no write", "reason", fence.Reason,
			"decree", fence.Doubt, "member", fence.Member, "cut_off", strings.Join(fence.CutOff, ","))
	}
}

// doubtFence is the fence every replica of this cluster is under while it
// holds the doubt of a Recover decree whose member does not answer here: the
// operator handed that member the cluster, and no replica serves beside it.
// A member that answers again did not recover, and a DismissRecover takes the
// doubt off the log.
func (n *Node) doubtFence() *Fence {
	for _, doubt := range n.fsm.ClusterState().Doubts {
		if n.answeringMember(doubt.Member) {
			continue
		}
		return &Fence{
			Reason: fmt.Sprintf("a Recover decree hands this cluster to member %s, which does not answer here: it may be carrying the cluster on alone. Dismiss the Recover, or bring that member back", doubt.Member),
			Doubt:  doubt.Intent,
			Member: doubt.Member,
		}
	}
	return nil
}

// leaderFence is the fence this leader is under, and nil at a replica that
// does not lead: only the leader reads the board, and the replicas that
// follow it answer reads under the leases it confirms (lease.go).
func (n *Node) leaderFence() *Fence {
	if !n.leading() {
		return nil
	}
	return n.blindToTheBoard()
}

// answeringMember reports a member of this cluster's configuration that
// answers this replica. This replica answers itself.
func (n *Node) answeringMember(member string) bool {
	if member == string(n.member) {
		return true
	}
	term := n.raft.Load().CurrentTerm()
	return n.memberOfCluster(member) && !n.countsDead(term, raft.ServerID(member), time.Now())
}

// boardSighting is a leader's reading of the cluster's board: the term it was
// leading when it read it, and when that was.
type boardSighting struct {
	term uint64
	at   time.Time
}

// sightedBoard records a complete reading of the board by this leader.
func (n *Node) sightedBoard() {
	n.board.Store(&boardSighting{term: n.raft.Load().CurrentTerm(), at: time.Now()})
}

// boardSightedThisTerm is this leader's reading of the board in the term it
// leads, and whether it has one: a reading from an earlier term says nothing
// about a leader that has just taken over.
func (n *Node) boardSightedThisTerm() (time.Time, bool) {
	sighted := n.board.Load()
	if sighted == nil || sighted.term != n.raft.Load().CurrentTerm() {
		return time.Time{}, false
	}
	return sighted.at, true
}

// blindToTheBoard is why a leader that cannot see its cluster's board must
// not serve, and nil where it serves: it has read the board in this term, and
// read it inside the board lease.
func (n *Node) blindToTheBoard() *Fence {
	term := n.raft.Load().CurrentTerm()
	sighted, inThisTerm := n.boardSightedThisTerm()
	switch {
	case !inThisTerm:
		return n.fenceUntilMembersAcknowledge(term)
	case time.Since(sighted) < n.cfg.Timing.boardLease():
		return nil
	default:
		return n.fenceWhileMembersAreCutOff(term)
	}
}

// fenceUntilMembersAcknowledge fences a leader that has read no board in its
// term while a member has not reported it as its leader: that member may be
// holding a Recover decree of its own instead.
func (n *Node) fenceUntilMembersAcknowledge(term uint64) *Fence {
	unacknowledged := n.membersThatHaveNotAcknowledged(term)
	if len(unacknowledged) == 0 {
		return nil
	}
	return &Fence{
		Reason: fmt.Sprintf("this leader has read no decree of its cluster's board in its term, and members %s have not reported it as their leader", strings.Join(unacknowledged, ", ")),
		CutOff: unacknowledged,
	}
}

// fenceWhileMembersAreCutOff fences a leader whose reading of the board has
// gone stale while a member of its cluster is cut off.
func (n *Node) fenceWhileMembersAreCutOff(term uint64) *Fence {
	cut := memberIDs(n.membersCutOff(term))
	if len(cut) == 0 {
		return nil
	}
	return &Fence{
		Reason: fmt.Sprintf("this leader has not read the decrees of its cluster's board for %s while members %s do not answer: one of them may hold a Recover decree", n.cfg.Timing.boardLease(), strings.Join(cut, ", ")),
		CutOff: cut,
	}
}

// membersThatHaveNotAcknowledged are the members of this cluster that have
// not reported this leader as theirs in the term it leads.
func (n *Node) membersThatHaveNotAcknowledged(term uint64) []string {
	var unacknowledged []string
	for _, server := range n.configuration() {
		if string(server.ID) == string(n.member) || n.acks.by(server.ID, term) {
			continue
		}
		unacknowledged = append(unacknowledged, string(server.ID))
	}
	return unacknowledged
}

// membersCutOff are the members of this cluster this leader can neither reach
// nor replicate to in the term it leads.
func (n *Node) membersCutOff(term uint64) []raft.Server {
	now := time.Now()
	var cut []raft.Server
	for _, server := range n.configuration() {
		if n.countsDead(term, server.ID, now) {
			cut = append(cut, server)
		}
	}
	return cut
}

// memberIDs is the member ids of these servers.
func memberIDs(servers []raft.Server) []string {
	members := make([]string, 0, len(servers))
	for _, server := range servers {
		members = append(members, string(server.ID))
	}
	return members
}

// acknowledgements are the members that reported this leader as theirs, in
// the term they reported it in: a member following this leader is carrying no
// cluster of its own, which is what a leader that has read no board in its
// term goes by.
type acknowledgements struct {
	mu sync.Mutex
	in map[raft.ServerID]uint64
}

func newAcknowledgements() *acknowledgements {
	return &acknowledgements{in: map[raft.ServerID]uint64{}}
}

func (a *acknowledgements) by(member raft.ServerID, term uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	acknowledged, known := a.in[member]
	return known && acknowledged == term
}

func (a *acknowledgements) note(member raft.ServerID, term uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.in[member] = term
}

// noteAcknowledgements asks the members that have not reported this leader in
// its term where they stand, while it has read no board in that term: their
// answers are all it has to tell a member that follows it from one that may
// be acting alone. A leader that has read the board asks nobody. Each ask is
// bounded by the control channel's own deadline (seats.go).
func (n *Node) noteAcknowledgements() {
	if !n.leading() {
		return
	}
	if _, inThisTerm := n.boardSightedThisTerm(); inThisTerm {
		return
	}
	term := n.raft.Load().CurrentTerm()
	for _, member := range n.membersThatHaveNotAcknowledged(term) {
		answer, err := n.askStanding(raft.ServerID(member))
		if err != nil || answer.Leader != string(n.member) || answer.Term != term {
			continue
		}
		n.acks.note(raft.ServerID(member), term)
	}
}

// excludedAddress is the Raft address of a member this cluster cut out. Every
// address a member is reached at names that member (transport.go), so this
// one is no member's, and neither Raft nor a control request reaches anyone
// there.
const excludedAddress raft.ServerAddress = "excluded"

// excludeSuspects cuts the members that may be carrying a recovered cluster
// out of the configuration.
func (n *Node) excludeSuspects() {
	if !n.leading() {
		return
	}
	for _, suspect := range n.suspects() {
		n.cutOut(suspect)
	}
}

// suspects are the members of this cluster that answer no more and may hold a
// Recover decree: while this leader is blind to the board, every one of them,
// since the decree it cannot see may name any member; and the member of every
// doubt the cluster holds once it has seen such a decree.
func (n *Node) suspects() []raft.Server {
	blind := n.blindToTheBoard() != nil
	doubted := n.doubtedMembers()
	if !blind && len(doubted) == 0 {
		return nil
	}
	var suspects []raft.Server
	for _, server := range n.membersCutOff(n.raft.Load().CurrentTerm()) {
		if server.Address == excludedAddress {
			continue
		}
		if blind || slices.Contains(doubted, string(server.ID)) {
			suspects = append(suspects, server)
		}
	}
	return suspects
}

// doubtedMembers are the members every Recover doubt of this cluster names.
// The fence names the one doubt it reports; every doubted member is cut out.
func (n *Node) doubtedMembers() []string {
	var members []string
	for _, doubt := range n.fsm.ClusterState().Doubts {
		members = append(members, doubt.Member)
	}
	return members
}

// cutOut stops Raft from reaching a member of this cluster: a voter keeps its
// vote at the excluded address, and a non-voter, whose vote no majority waits
// for, is taken out.
func (n *Node) cutOut(suspect raft.Server) {
	if suspect.Suffrage != raft.Voter {
		if n.takeOut(suspect.ID) {
			slog.Error("cds-ha: ALARM: a member of this cluster may be carrying a recovered cluster of its own; it is out of this one and rejoins only as a new member", "member", suspect.ID)
		}
		return
	}
	if err := n.raft.Load().AddVoter(suspect.ID, excludedAddress, 0, n.cfg.Timing.Apply).Error(); err != nil {
		slog.Warn("cds-ha: this leader could not cut a member out of its cluster", "member", suspect.ID, "error", err)
		return
	}
	slog.Error("cds-ha: ALARM: a voter of this cluster may be carrying a recovered cluster of its own; this cluster reaches it no more, and it rejoins only as a new member", "member", suspect.ID)
}

// endsExcluded is the exit of a member its own cluster cut out: its log may
// hold the entries of a recovered cluster, which no replica can tell from
// this cluster's, so only a restart, as a new member with an empty log,
// rejoins (stuck.go).
func (n *Node) endsExcluded() error {
	if !n.excluded.Load() {
		return nil
	}
	return fmt.Errorf("%w: its cluster cut this member out", ErrLeftItsCluster)
}
