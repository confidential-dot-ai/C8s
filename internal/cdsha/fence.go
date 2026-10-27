package cdsha

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/raft"
)

// Fencing against a Recover split brain.
//
// A Recover decree names one replica; that replica cannot tell a dead
// majority from one the host merely cut it off from. Only the majority can
// refuse such a decree, and only if it sees the decree objects. So a leader
// that has not seen them for decreeLease while one of its members is cut off
// (a possible Recover target) serves nothing, and the named replica waits
// recoverHold after it first sees the decree: by then the majority has either
// rejected it, or stopped serving. A Recover the majority did not reject in
// time may have been applied: the leader drops the member it names from its
// configuration, so Raft never merges the two histories, and stays fenced
// until that member is back as a healthy member (it did not recover) or the
// operator deletes the decree object.

// decreeLease (F) is how long a leader's decree view stays fresh.
func (t Timing) decreeLease() time.Duration { return 2 * t.DeadAfter }

// recoverHold (H) is how long a Recover decree must stay pending, as seen by
// the replica it names, before that replica acts: a fresh majority writes its
// rejection within F+Apply, and a stale one stops serving within F+Lease.
func (t Timing) recoverHold() time.Duration {
	return t.decreeLease() + t.Apply + t.Lease + 2*t.Tick
}

// ErrRecoverLate rejects a Recover decree that a leader saw only after its
// decree view went stale: the replica it names may already have acted.
var ErrRecoverLate = errors.New("refused late: this cluster could not see decrees for a while and the replica this decree names may have recovered; the cluster stays fenced until that replica rejoins it or the decree object is deleted")

// ErrFenced refuses reads and writes on a fenced leader (Status.Fenced says why).
var ErrFenced = errors.New("cds-ha: the leader is fenced")

// Fence is why a leader serves nothing (Status.Fenced).
type Fence struct {
	Reason  string `json:"reason"`
	SinceMS int64  `json:"since_ms"`
	// StaleForMS is the age of the leader's decree view; 0 if it has none
	// in this term.
	StaleForMS   int64    `json:"stale_for_ms,omitempty"`
	CutOffVoters []string `json:"cut_off_voters,omitempty"`
	Decree       string   `json:"decree,omitempty"`
	Member       string   `json:"member,omitempty"`
}

// decreeView is the start of the last decree cycle that listed the decree
// objects and stored every Recover rejection, within Timing.Apply.
type decreeView struct {
	term uint64
	at   time.Time
}

// recoverDoubt is a Recover decree this cluster did not reject in time.
type recoverDoubt struct {
	decree string
	member raft.ServerID
	fork   bool // another replica reports it applied
}

// recoverSighting is the Recover decree a leaderless replica holds off on.
type recoverSighting struct {
	intent string
	at     time.Time
}

// fence is why this leader must not serve, or nil.
func (n *Node) fence() *Fence {
	r := n.r()
	if n.cfg.Decrees == nil || r == nil || r.State() != raft.Leader {
		n.fencedSince.Store(0)
		return nil
	}
	now, term := time.Now(), r.CurrentTerm()
	servers := n.servers()
	healthy := func(id raft.ServerID) bool {
		_, bad := n.failing[id]
		return !bad && slices.ContainsFunc(servers, func(s raft.Server) bool { return s.ID == id })
	}
	var f *Fence
	n.mu.Lock()
	var cut []string
	for _, s := range servers {
		if !healthy(s.ID) && s.ID != n.id {
			cut = append(cut, string(s.ID))
		}
	}
	for id := range n.blindRemoved {
		cut = append(cut, string(id))
	}
	if p := n.doubts.Load(); p != nil {
		for _, d := range *p {
			// It, or a later process on its node, follows this leader: the
			// process the decree names did not recover, or is gone.
			if d.member == n.id || slices.ContainsFunc(servers, func(s raft.Server) bool {
				return (s.ID == d.member || nodeOf(s.ID) == nodeOf(d.member) && bornOf(s.ID) > bornOf(d.member)) && healthy(s.ID)
			}) {
				continue
			}
			why := "Recover decree may have been applied by " + string(d.member) + " while this cluster could not see decrees (" + ErrRecoverLate.Error() + ")"
			if d.fork {
				why = "Recover decree was applied by " + string(d.member) + ": this cluster is a fork; restart its replicas to join the recovered cluster, or delete the decree object to keep this one"
			}
			f = &Fence{Reason: why, Decree: d.decree, Member: string(d.member)}
			break
		}
	}
	n.mu.Unlock()
	v := n.decreeView.Load()
	fresh := v != nil && v.term == term && now.Sub(v.at) < n.cfg.Timing.decreeLease()
	// Without a view in this term, only members that have reported this
	// leader in this term (noteAcks) are known not to be acting alone.
	var unacked []string
	if v == nil || v.term != term {
		n.mu.Lock()
		for _, s := range servers {
			if s.ID != n.id && n.acked[s.ID] != term {
				unacked = append(unacked, string(s.ID))
			}
		}
		n.mu.Unlock()
	}
	if f == nil && !fresh && (len(cut) > 0 || len(unacked) > 0) {
		f = &Fence{Reason: fmt.Sprintf("this leader has not seen the decree objects for %s while members are cut off (a Recover decree may be pending); restore the leader's API access or the cut-off members", n.cfg.Timing.decreeLease())}
		if len(cut) == 0 {
			f.Reason = fmt.Sprintf("this leader has not yet seen the decree objects in its term and members %v have not yet reported it as their leader; restore its API access", unacked)
		}
	}
	if f == nil {
		n.fencedSince.Store(0)
		return nil
	}
	f.CutOffVoters = cut
	if v != nil && v.term == term {
		f.StaleForMS = now.Sub(v.at).Milliseconds()
	}
	n.fencedSince.CompareAndSwap(0, now.UnixMilli())
	f.SinceMS = n.fencedSince.Load()
	if logOnce(n.fenceLog, f.Reason) {
		n.log.Error("cds-ha: FENCED: this cluster serves no reads or writes", "reason", f.Reason, "decree", f.Decree,
			"cut_off", strings.Join(cut, ","), "stale_for_ms", f.StaleForMS)
	}
	return f
}

// fenced is ErrFenced with the reason, or nil.
func (n *Node) fenced() error {
	if f := n.fence(); f != nil {
		return fmt.Errorf("%w: %s", ErrFenced, f.Reason)
	}
	return nil
}

// judgeRecovers rejects the pending Recover decrees in ds and returns the
// ones this cluster did not reject in time. fresh says the previous decree
// view of this term is younger than decreeLease. ok is false if a rejection
// could not be stored.
func (n *Node) judgeRecovers(ctx context.Context, ds []PendingDecree, core Core, fresh bool) (doubts []recoverDoubt, ok bool) {
	ok = true
	for _, d := range ds {
		sd := d.Decree
		if d.Err != nil || sd.Decree.Kind != Recover || slices.Contains(core.AppliedDecrees, sd.Decree.IntentID) {
			continue
		}
		// Only an operator's Recover can fork the cluster.
		signed := sd.Decree.ClusterID == core.ClusterID && VerifyDecreeSignature(sd, core.OperatorPubKey) == nil
		doubt := recoverDoubt{decree: d.Name, member: raft.ServerID(sd.Decree.TargetMember)}
		switch {
		case d.Status == nil && fresh:
			// A leader holds a majority: nothing was lost for good. Applied
			// here, the decree would only bump the epoch, and the replica it
			// names, if merely cut off, would come back to an epoch it did
			// not see.
			n.log.Warn("Recover decree refused: the cluster has a leader with a majority", "decree", d.Name)
			ok = n.setStatus(ctx, d.Name, DecreeStatus{RejectedReason: ErrRecoverWithQuorum.Error()}) && ok
		case d.Status == nil:
			n.log.Error("Recover decree refused late: its replica may have recovered; this cluster stays fenced", "decree", d.Name, "member", doubt.member)
			ok = n.setStatus(ctx, d.Name, DecreeStatus{RejectedReason: ErrRecoverLate.Error()}) && ok
			if signed {
				doubts = append(doubts, doubt)
			}
		case !signed:
		case d.Status.AppliedEpoch != nil:
			doubt.fork = true
			doubts = append(doubts, doubt)
		case d.Status.RejectedReason == ErrRecoverLate.Error():
			doubts = append(doubts, doubt)
		}
	}
	return doubts, ok
}

// dropSuspects (leader) removes from the configuration every member a
// Recover decree names that this cluster did not reject in time and, while
// the decree view is stale, every member cut off for DeadAfter: either may
// lead a recovered cluster, and Raft must never merge it back.
func (n *Node) dropSuspects() {
	if n.cfg.Decrees == nil {
		return
	}
	r := n.r()
	v := n.decreeView.Load()
	stale := r == nil || v == nil || v.term != r.CurrentTerm() || time.Since(v.at) >= n.cfg.Timing.decreeLease()
	var doubted []raft.ServerID
	if p := n.doubts.Load(); p != nil {
		for _, d := range *p {
			doubted = append(doubted, d.member)
		}
	}
	if !stale && len(doubted) == 0 {
		return
	}
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	if r == nil || r != n.r() || n.stoppingReads.Load() == r || r.State() != raft.Leader {
		return
	}
	now := time.Now()
	for _, s := range n.servers() {
		if s.ID == n.id {
			continue
		}
		n.mu.Lock()
		since, bad := n.failing[s.ID]
		n.mu.Unlock()
		blind := stale && bad && now.Sub(since) >= n.cfg.Timing.DeadAfter
		if !blind && (!bad || !slices.Contains(doubted, s.ID)) {
			continue
		}
		if n.removeMember(r, s.ID) {
			n.log.Error("cds-ha: removed a cut-off member that may lead a recovered cluster; it rejoins if it did not recover", "id", s.ID, "decree_view_stale", stale)
			if blind {
				n.mu.Lock()
				n.blindRemoved[s.ID] = struct{}{}
				n.mu.Unlock()
			}
		}
	}
}

// noteAcks (leader, Run loop) records the members that report this leader
// in this term over an attested status probe, while this leader has no
// decree view in its term. Such a member had a leader when it answered, so
// its Recover hold starts over (recoverReady); were it cut off since, its
// heartbeats fail long before that hold ends, and it counts as cut off.
func (n *Node) noteAcks() {
	r := n.r()
	if n.cfg.Decrees == nil || r == nil || r.State() != raft.Leader {
		return
	}
	term := r.CurrentTerm()
	if v := n.decreeView.Load(); v != nil && v.term == term {
		return
	}
	for _, s := range n.servers() {
		n.mu.Lock()
		_, bad := n.failing[s.ID]
		done := n.acked[s.ID] == term
		n.mu.Unlock()
		if s.ID == n.id || bad || done {
			continue
		}
		st, err := n.peerStatus(s.Address, min(time.Second, n.cfg.Timing.Lease/2))
		if err != nil || st.ID != string(s.ID) || st.Term != term || st.Leader != n.cfg.Advertise {
			continue
		}
		n.mu.Lock()
		n.acked[s.ID] = term
		n.mu.Unlock()
	}
}

// recoverReady (the named replica, leaderless) reports whether Recover p may
// act now: seen pending for recoverHold, and no member of the last
// configuration answers with a leader.
func (n *Node) recoverReady(p PendingDecree) bool {
	intent, now := p.Decree.Decree.IntentID, time.Now()
	// Any contact from a leader since the sighting starts the hold over:
	// Run's ticks alone can miss a short one.
	if lc := n.r().LastContact(); n.recoverSeen.intent == intent && lc.After(n.recoverSeen.at) {
		n.recoverSeen = recoverSighting{}
	}
	if n.recoverSeen.intent != intent {
		n.recoverSeen = recoverSighting{intent: intent, at: now}
		n.log.Warn("Recover decree names this replica: acting after the hold unless the cluster rejects it or answers", "decree", p.Name, "hold", n.cfg.Timing.recoverHold())
		return false
	}
	if now.Sub(n.recoverSeen.at) < n.cfg.Timing.recoverHold() {
		return false
	}
	for _, s := range n.servers() {
		if s.ID == n.id {
			continue
		}
		// A survivor that sees no leader either is no sign of a majority.
		if st, err := n.peerStatus(s.Address, time.Second); err == nil && st.ID == string(s.ID) && st.Leader != "" {
			n.log.Warn("Recover refused: a member of the cluster answers and has a leader", "decree", p.Name, "member", s.ID, "leader", st.Leader)
			n.recoverSeen = recoverSighting{}
			return false
		}
	}
	return true
}
