package cdsha

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

// Membership: joining, the leader's seat logic and its failure bookkeeping.

// member reports whether this replica is in a Raft configuration.
func (n *Node) member() bool {
	if n.r() == nil {
		return false
	}
	return slices.ContainsFunc(n.servers(), func(s raft.Server) bool { return s.ID == n.id })
}

// joinOrBootstrap asks the replicas it can reach to add it. A replica named
// by a pending Genesis decree starts the group instead, but only when no
// reachable replica already belongs to one.
func (n *Node) joinOrBootstrap(ctx context.Context) {
	peers, err := n.cfg.Peers(ctx)
	switch {
	case err != nil:
		// A replica that cannot find its peers can never join: say so.
		n.joinRefused("peer discovery", err)
	case len(peers) == 0:
		n.joinRefused("peer discovery", errors.New("no other replica found"))
	}
	anyMember := false
	for _, p := range peers {
		resp, err := n.askJoin(p)
		switch {
		case err != nil:
		case resp.Err == "":
			if !n.joinLogged {
				n.log.Info("joined the CDS cluster", "via", p, "id", n.id)
				n.joinLogged = true
			}
			return
		case resp.Member:
			anyMember = true
		default:
			n.lastLoner.Store(time.Now().UnixMilli())
		}
		if err == nil {
			err = errors.New(resp.Err)
		}
		n.joinRefused(p, err)
	}
	if anyMember {
		n.lastMember.Store(time.Now().UnixMilli())
		return
	}
	if g, ok := n.pendingDecree(ctx, Genesis); ok {
		n.bootstrap(ctx, g)
	}
}

// joinRefused logs why a peer would not add this replica, at Info once a
// minute per peer and reason: a replica that can never join (a release too
// old for the cluster's format, an image not pinned) must say so.
func (n *Node) joinRefused(peer string, err error) {
	if n.joinRefusedLog.ok(peer+" "+err.Error(), time.Now()) {
		n.log.Info("join refused", "peer", peer, "err", err)
	}
}

// rejoin asks reachable replicas to add this member, as a joiner would; a
// leader that already has it answers without change.
func (n *Node) rejoin(ctx context.Context) {
	peers, _ := n.cfg.Peers(ctx)
	for _, p := range peers {
		if resp, err := n.askJoin(p); err == nil && resp.Err == "" {
			return
		}
	}
}

// askJoin asks peer p to add this replica, following one redirect to the
// leader.
func (n *Node) askJoin(p string) (controlResponse, error) {
	req := controlRequest{Op: ctlJoin, ID: string(n.id), Address: string(n.raftAddress()), Reads: n.fsm.readable}
	resp, err := n.call(p, 5*time.Second, req)
	if err != nil || resp.Leader == "" || resp.Leader == p || resp.Leader == n.cfg.Advertise {
		return resp, err
	}
	// Whoever answers next, the first peer belongs to a cluster: that alone
	// must keep this replica from starting another.
	member := resp.Member
	resp, err = n.call(resp.Leader, 5*time.Second, req)
	resp.Member = resp.Member || member
	if err != nil && member {
		return controlResponse{Member: true, Err: err.Error()}, nil
	}
	return resp, err
}

func (n *Node) handleJoin(req controlRequest) controlResponse {
	id := raft.ServerID(req.ID)
	hostport, addrID := splitRaftAddr(req.Address)
	if nodeOf(id) == "" || hostport == "" || addrID != req.ID {
		return controlResponse{Member: true, Err: "bad join request"}
	}
	if agreed := n.fsm.Core().format(); req.Reads < agreed {
		// It could not apply the log it would receive.
		return controlResponse{Member: true, Err: fmt.Sprintf("replica reads format %d, the cluster writes %d", req.Reads, agreed)}
	}
	f := n.r().GetConfiguration()
	if err := f.Error(); err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	nonVoters := 0
	for _, s := range f.Configuration().Servers {
		if s.ID == id {
			return controlResponse{Member: true}
		}
		if hp, _ := splitRaftAddr(string(s.Address)); hp == hostport && s.ID != n.id {
			// Only one process listens on an address: the member there is a
			// dead earlier incarnation, and its seat is the joiner's.
			if err := n.r().RemoveServer(s.ID, 0, n.cfg.Timing.Apply).Error(); err != nil {
				return controlResponse{Member: true, Err: err.Error()}
			}
			n.log.Info("member replaced at its address", "old", s.ID, "new", id)
			continue
		}
		if s.Suffrage != raft.Voter {
			nonVoters++
		}
	}
	if max := n.cfg.MaxNonVoters; max > 0 && nonVoters >= max {
		return controlResponse{Member: true, Err: "no room for another replica"}
	}
	if err := n.r().AddNonvoter(id, raft.ServerAddress(req.Address), 0, n.cfg.Timing.Apply).Error(); err != nil {
		return controlResponse{Member: true, Err: err.Error()}
	}
	n.mu.Lock()
	n.joinedAt[id] = time.Now()
	n.addedAt[id] = n.joinedAt[id]
	n.reads[id] = req.Reads
	delete(n.failing, id) // failures of an earlier membership (see noteFailure)
	n.mu.Unlock()
	n.log.Info("replica joined as non-voter", "id", id, "address", req.Address)
	return controlResponse{Member: true}
}

// nodeOf is the node name a member ID carries.
func nodeOf(id raft.ServerID) string {
	node, _, ok := strings.Cut(string(id), "/")
	if !ok {
		return ""
	}
	return node
}

// bornOf orders two members of one node: the later start replaces the other.
func bornOf(id raft.ServerID) int64 {
	_, rest, _ := strings.Cut(string(id), "/")
	ms, _, _ := strings.Cut(rest, "-")
	v, _ := strconv.ParseInt(ms, 10, 64)
	return v
}

func (n *Node) observe(ch <-chan raft.Observation) {
	for o := range ch {
		n.mu.Lock()
		switch d := o.Data.(type) {
		case raft.FailedHeartbeatObservation:
			n.noteFailure(d.PeerID, d.LastContact, time.Now())
		case raft.ResumedHeartbeatObservation:
			delete(n.failing, d.PeerID)
		}
		n.mu.Unlock()
	}
}

// clearReachable probes the members due for removal as dead and forgets the
// failures of any that answers: a removal is for a member unreachable now,
// not for a stale observation.
func (n *Node) clearReachable(servers []raft.Server, now time.Time) {
	n.mu.Lock()
	var suspects []raft.Server
	for _, s := range servers {
		if since, bad := n.failing[s.ID]; bad && s.ID != n.id && now.Sub(since) >= n.cfg.Timing.DeadAfter {
			suspects = append(suspects, s)
		}
	}
	n.mu.Unlock()
	for _, s := range suspects {
		// The same member must answer, not a later process at its address.
		if st, err := n.peerStatus(s.Address, time.Second); err == nil && st.ID == string(s.ID) {
			n.log.Info("member answers; its heartbeat failures were stale", "id", s.ID)
			n.mu.Lock()
			delete(n.failing, s.ID)
			n.mu.Unlock()
		}
	}
}

// noteFailure records that heartbeats to a member fail, as of its last
// successful contact. A replication stream outlives the member's removal, so
// a member removed and added again can still see failures from the stream of
// its earlier membership, after the new stream already reaches it; nothing
// would clear them (the new stream never "resumes"), and the member would be
// removed again after dead_after. Those failures carry a last contact from
// before the member was added; they are ignored. Callers hold n.mu.
func (n *Node) noteFailure(id raft.ServerID, lastContact, now time.Time) {
	joined, ok := n.addedAt[id]
	if ok && !lastContact.IsZero() && lastContact.Before(joined) {
		return
	}
	if _, already := n.failing[id]; already {
		return
	}
	since := lastContact
	if since.IsZero() {
		since = now
	}
	n.failing[id] = since
}

// reconcile keeps the voter seats filled with one healthy replica per node:
// it removes members that are dead or were replaced by a restart of the
// same node, and promotes stable non-voters into free seats.
func (n *Node) reconcile() {
	servers := n.servers()
	if servers == nil {
		return
	}
	now := time.Now()
	n.clearReachable(servers, now)
	n.mu.Lock()
	failingSince := func(id raft.ServerID) (time.Time, bool) { t, ok := n.failing[id]; return t, ok }
	healthy := func(id raft.ServerID) bool {
		if id == n.id {
			return true
		}
		_, bad := failingSince(id)
		j, ok := n.joinedAt[id]
		if !ok {
			n.joinedAt[id] = now
			j = now
		}
		return !bad && now.Sub(j) >= n.cfg.Timing.Stabilize
	}
	var remove []raft.ServerID
	newest := map[string]raft.ServerID{}
	for _, s := range servers {
		node := nodeOf(s.ID)
		if cur, ok := newest[node]; !ok || bornOf(s.ID) > bornOf(cur) {
			newest[node] = s.ID
		}
	}
	for _, s := range servers {
		if s.ID == n.id {
			continue
		}
		if since, bad := failingSince(s.ID); bad && now.Sub(since) >= n.cfg.Timing.DeadAfter {
			remove = append(remove, s.ID)
			continue
		}
		if nw := newest[nodeOf(s.ID)]; nw != s.ID && nw != n.id && healthy(nw) {
			remove = append(remove, s.ID) // restarted: the new member takes over
		}
	}
	voters, voterNodes := 0, map[string]bool{}
	for _, s := range servers {
		if s.Suffrage == raft.Voter && !slices.Contains(remove, s.ID) {
			voters++
			voterNodes[nodeOf(s.ID)] = true
		}
	}
	var promote []raft.Server
	for _, s := range servers {
		if voters+len(promote) >= n.seats() {
			break
		}
		if s.Suffrage == raft.Voter || slices.Contains(remove, s.ID) || voterNodes[nodeOf(s.ID)] || !healthy(s.ID) {
			continue
		}
		voterNodes[nodeOf(s.ID)] = true
		promote = append(promote, s)
	}
	n.mu.Unlock()
	for _, id := range remove {
		if err := n.r().RemoveServer(id, 0, n.cfg.Timing.Apply).Error(); err != nil {
			n.log.Warn("remove member", "id", id, "err", err)
			continue
		}
		n.mu.Lock()
		delete(n.failing, id)
		delete(n.joinedAt, id)
		delete(n.addedAt, id)
		delete(n.reads, id)
		n.mu.Unlock()
		n.log.Info("member removed", "id", id)
	}
	for _, s := range promote {
		if err := n.r().AddVoter(s.ID, s.Address, 0, n.cfg.Timing.Apply).Error(); err != nil {
			n.log.Warn("promote member", "id", s.ID, "err", err)
			continue
		}
		n.log.Info("member promoted to voter", "id", s.ID)
	}
	if len(remove) == 0 && len(promote) == 0 {
		n.demoteExtraVoter(servers)
	}
	if len(remove) == 0 {
		n.raiseFormat(servers)
	}
}

// demoteExtraVoter (leader) demotes one voter when there are more voters than
// seats: a failing one first, never itself. One per pass, so the group never
// loses more than one vote at a time.
func (n *Node) demoteExtraVoter(servers []raft.Server) {
	var voters []raft.ServerID
	for _, s := range servers {
		if s.Suffrage == raft.Voter {
			voters = append(voters, s.ID)
		}
	}
	if len(voters) <= n.seats() {
		return
	}
	n.mu.Lock()
	var pick raft.ServerID
	for _, id := range voters {
		if id == n.id {
			continue
		}
		if _, bad := n.failing[id]; bad || pick == "" {
			pick = id
			if bad {
				break
			}
		}
	}
	n.mu.Unlock()
	if pick == "" {
		return
	}
	if err := n.r().DemoteVoter(pick, 0, n.cfg.Timing.Apply).Error(); err != nil {
		n.log.Warn("demote voter", "id", pick, "err", err)
		return
	}
	n.log.Info("voter demoted: more voters than seats", "id", pick, "seats", n.seats())
}

// raiseFormat (leader): once every voter seat is filled and every member
// reads a newer format than the agreed one, the cluster agrees on it, so the
// new encoding is only written after the last old replica left. Waiting for
// the seats keeps a group that shrank to new replicas (an old one crashed
// mid-rollout) from locking the old release out before the operator chose to
// move on. A member that joined under an earlier leader is asked what it
// reads; one that does not answer holds the format.
func (n *Node) raiseFormat(servers []raft.Server) {
	agreed := n.fsm.Core().format()
	low := n.fsm.readable
	if low <= agreed || !n.seatsFilled() {
		return
	}
	for _, s := range servers {
		if s.ID == n.id {
			continue
		}
		n.mu.Lock()
		v, ok := n.reads[s.ID]
		n.mu.Unlock()
		if !ok {
			st, err := n.peerStatus(s.Address, time.Second)
			if err != nil || st.ID != string(s.ID) {
				return
			}
			v = st.Reads
			n.mu.Lock()
			n.reads[s.ID] = v
			n.mu.Unlock()
		}
		low = min(low, v)
	}
	if low <= agreed {
		return
	}
	if _, err := n.applyEntry(Entry{Kind: KindFormat, SetFormat: low}); err != nil {
		n.log.Warn("raise cluster format", "to", low, "err", err)
		return
	}
	n.log.Info("cluster format raised: every member reads it", "from", agreed, "to", low)
}

// seatsFilled (leader): the configuration has Seats voters and none of them
// is failing heartbeats.
func (n *Node) seatsFilled() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	voters := 0
	for _, s := range n.servers() {
		if s.Suffrage != raft.Voter {
			continue
		}
		if _, bad := n.failing[s.ID]; bad && s.ID != n.id {
			return false
		}
		voters++
	}
	return voters >= n.seats()
}

// seats is the voter seat count: the agreed one once a SetVoters decree
// set it, the launch configuration's before.
func (n *Node) seats() int {
	return cmp.Or(n.fsm.Core().Seats, n.cfg.Seats)
}

// isVoter reports whether this member holds a voter seat.
func (n *Node) isVoter() bool {
	ss := n.servers()
	i := slices.IndexFunc(ss, func(s raft.Server) bool { return s.ID == n.id })
	return i >= 0 && ss[i].Suffrage == raft.Voter
}

// refreshSeats asks the leader whether every seat is filled (non-voters
// only; see Ready).
func (n *Node) refreshSeats() {
	if n.isVoter() {
		return
	}
	addr, _ := n.r().LeaderWithID()
	if addr == "" {
		return
	}
	if st, err := n.peerStatus(addr, time.Second); err == nil && st.SeatsFilled {
		n.seatsOKAt.Store(time.Now().UnixMilli())
	}
}
