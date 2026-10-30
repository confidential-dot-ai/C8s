// The leader decides whether the replicas of its cluster hold one state. A
// replica reports where its chain stands and the state digests it recorded
// (digest.go) with every read it asks the leader to confirm (lease.go). A
// report whose chain the leader's own contradicts makes it propose a
// checkpoint, where the majority of the voters decides:
//
//   - A majority holding what the leader holds stops every member that
//     holds another state, or recorded none although it applied past that
//     checkpoint: each is refused its next read, and restarts into the
//     state the majority vouched for.
//   - A majority holding one other state makes the leader the replica that
//     diverged: it stops itself, hands the cluster over and takes no
//     snapshot, so it seeds no replica.
//   - No majority for one state raises an alarm and stops nobody.
//
// A committed entry is held by a majority, so a state only a minority
// applied always loses.

package cdsha

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

var ErrDiverged = errors.New("cds-ha: this replica holds another state than the majority of its cluster")

// What a replica tells its leader with a read.
type DigestReport struct {
	// The first index its chain vouches for: the snapshot it installed, or
	// none.
	Base        uint64  `json:"base"`
	Latest      Point   `json:"latest"`
	Checkpoints []Point `json:"checkpoints,omitempty"`
}

// What the leader makes of the reports its members send.
type divergence struct {
	mu      sync.Mutex
	reports map[raft.ServerID]*DigestReport
	// Members found to hold another state than the majority; each stops at
	// its next read.
	verdicts map[raft.ServerID]string
	// A disagreement nothing has settled, and the verdict this leader last
	// reached.
	alarm string
	found string
	// soon asks for a checkpoint at the next tick.
	soon       bool
	proposedAt time.Time
}

// "" where this cluster agrees.
func (d *divergence) status() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return cmp.Or(d.alarm, d.found)
}

// A loop of its own, so no other duty of the leader holds up a checkpoint.
func (n *Node) watchDivergence(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n.decideAtCheckpoint()
		n.proposeCheckpoint()
	}
}

// takeReport records one member's report and answers why that member
// diverged, or "". This leader's chain answers for every index through
// appliedHere.
func (n *Node) takeReport(member raft.ServerID, report *DigestReport, appliedHere uint64) string {
	if report == nil {
		return ""
	}
	contradicted := report.Latest.Index <= appliedHere && n.fsm.dig.disagreesWith(report.Latest)
	verdict, asked := n.div.hold(member, report, contradicted)
	if asked {
		slog.Warn("cds-ha: a replica of this cluster reports another chain than this leader applied; a checkpoint decides what the cluster holds",
			"member", member, "index", report.Latest.Index, "member_chain", report.Latest.Chain)
	}
	return verdict
}

func (d *divergence) hold(member raft.ServerID, report *DigestReport, contradicted bool) (verdict string, asked bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if held := d.verdicts[member]; held != "" {
		return held, false
	}
	if d.reports == nil {
		d.reports = map[raft.ServerID]*DigestReport{}
	}
	d.reports[member] = report
	if !contradicted {
		return "", false
	}
	return "", d.askForACheckpoint()
}

// first is the first ask since the last checkpoint. A disagreement already
// open has its checkpoints, one every Timing.Checkpoint (d.mu held).
func (d *divergence) askForACheckpoint() (first bool) {
	if d.alarm != "" || d.soon {
		return false
	}
	d.soon = true
	return true
}

// Asks every replica to record the digest of its state.
func (n *Node) proposeCheckpoint() {
	if !n.leading() || n.fsm.Stuck() != "" {
		return
	}
	recorded := n.fsm.dig.lastCheckpoint()
	if !n.div.claimCheckpoint(n.cfg.Timing.Checkpoint, n.fsm.AppliedIndex(), recorded.Index) {
		return
	}
	if _, err := n.propose(Entry{Kind: KindCheckpoint}); err != nil {
		slog.Warn("cds-ha: the checkpoint the replicas record their state digest at did not commit", "error", err)
	}
}

// A checkpoint is due where a report asked for one, or the state has moved
// and a whole period has passed.
func (d *divergence) claimCheckpoint(every time.Duration, applied, recorded uint64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	due := applied > recorded && time.Since(d.proposedAt) >= every
	if !d.soon && !due {
		return false
	}
	d.proposedAt = time.Now()
	d.soon = false
	return true
}

// Acts on the majority's verdict at the newest checkpoint the replicas have
// answered for.
func (n *Node) decideAtCheckpoint() {
	if !n.leading() || n.fsm.Stuck() != "" {
		return
	}
	servers := n.configuration()
	if len(servers) == 0 {
		return
	}
	n.actOn(n.div.decide(n.fsm.dig.checkpoints(), servers, raft.ServerID(n.member)))
}

// What the majority decided at one checkpoint, as an operator reads it.
type decision struct {
	found  string
	detail string
	// A majority of the voters holds one state that is not this leader's.
	leaderDiverged bool
}

// Runs outside the divergence lock.
func (n *Node) actOn(decided decision) {
	if decided.found == "" {
		return
	}
	if n.divergenceLog.changed(decided.found + decided.detail) {
		slog.Error("cds-ha: ALARM: "+decided.found, "detail", decided.detail)
	}
	if decided.leaderDiverged {
		_ = n.fsm.stopLocal(fmt.Errorf("%w: %s", ErrDiverged, decided.detail))
	}
}

// Records the verdict the voters reached at the newest checkpoint they
// answered for.
func (d *divergence) decide(checkpoints []Point, servers []raft.Server, leader raft.ServerID) decision {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.forgetMembersGone(servers)
	checkpoint, counted, answered := d.answeredCheckpoint(checkpoints, servers, leader)
	if !answered {
		return decision{}
	}
	if len(counted.differingMembers) == 0 {
		d.agreed(checkpoint)
		return decision{}
	}
	detail := describe(checkpoint, leader, counted)
	switch {
	case counted.leaderAgreed():
		d.stopTheOutvoted(checkpoint, counted, detail)
		return decision{
			found:  "the replicas that hold another state than the majority of the voters are stopped; each of them restarts into the cluster's state",
			detail: detail,
		}
	case counted.leaderOutvoted():
		d.alarm = "this leader holds another state than the majority of its voters: " + detail
		return decision{
			found:          "this leader holds another state than the majority of its voters; it stops and hands its cluster over",
			detail:         detail,
			leaderDiverged: true,
		}
	}
	d.alarm = "no majority of the voters holds one state: " + detail
	return decision{
		found:  "no majority of the voters holds one state; this cluster stops no replica of it",
		detail: detail,
	}
}

// A replica this leader stopped comes back as a new member, with the state
// the majority vouched for (d.mu held).
func (d *divergence) forgetMembersGone(servers []raft.Server) {
	held := func(member raft.ServerID) bool {
		return slices.ContainsFunc(servers, func(server raft.Server) bool { return server.ID == member })
	}
	maps.DeleteFunc(d.reports, func(member raft.ServerID, _ *DigestReport) bool { return !held(member) })
	maps.DeleteFunc(d.verdicts, func(member raft.ServerID, _ string) bool { return !held(member) })
}

// agreed records a checkpoint every member reported alike. The verdict stands
// while a member it stopped is still one of the cluster's (d.mu held).
func (d *divergence) agreed(checkpoint Point) {
	if d.alarm == "" && (d.found == "" || len(d.verdicts) > 0) {
		return
	}
	slog.Info("cds-ha: the replicas of this cluster hold one state again", "checkpoint", checkpoint.Index)
	d.alarm = ""
	d.found = ""
}

// Each outvoted member is refused its next read, and stops (d.mu held).
func (d *divergence) stopTheOutvoted(checkpoint Point, counted tally, detail string) {
	if d.verdicts == nil {
		d.verdicts = map[raft.ServerID]string{}
	}
	for _, member := range counted.differingMembers {
		d.verdicts[member.member] = fmt.Sprintf("at checkpoint %d this replica holds %s, and a majority of this cluster's voters holds %s",
			checkpoint.Index, member.holds, holdsOf(checkpoint))
	}
	d.alarm = ""
	d.found = "stopped the replicas that hold another state: " + detail
}

// A report is one read behind the log, so replicas that have yet to report
// the newest checkpoint are counted at an older one (d.mu held).
func (d *divergence) answeredCheckpoint(checkpoints []Point, servers []raft.Server, leader raft.ServerID) (Point, tally, bool) {
	for _, checkpoint := range slices.Backward(checkpoints) {
		counted := d.countAt(checkpoint, servers, leader)
		if counted.answeringVoters() >= counted.majority() {
			return checkpoint, counted, true
		}
	}
	return Point{}, tally{}, false
}

// What the cluster's members reported at one checkpoint: the voters decide,
// and every member is judged.
type tally struct {
	voters         int
	agreeingVoters int
	otherVoters    int
	// Members, voters or not, that do not hold what this leader holds, and
	// the most voters behind one state that is not this leader's.
	differingMembers []difference
	largestOther     int
}

type difference struct {
	member raft.ServerID
	holds  string
}

func (t tally) majority() int {
	return t.voters/2 + 1
}

// A checkpoint counts once a majority of the voters answered for it.
func (t tally) answeringVoters() int {
	return t.agreeingVoters + t.otherVoters
}

func (t tally) leaderAgreed() bool {
	return t.agreeingVoters >= t.majority()
}

func (t tally) leaderOutvoted() bool {
	return t.largestOther >= t.majority()
}

// d.mu held.
func (d *divergence) countAt(checkpoint Point, servers []raft.Server, leader raft.ServerID) tally {
	counted := tally{}
	others := map[Point]int{}
	for _, server := range servers {
		voter := server.Suffrage == raft.Voter
		if voter {
			counted.voters++
		}
		if server.ID == leader {
			// The checkpoints counted are this leader's own.
			counted.agreeingVoters += oneVote(voter)
			continue
		}
		d.countReport(server, voter, checkpoint, &counted, others)
	}
	for _, behind := range others {
		counted.largestOther = max(counted.largestOther, behind)
	}
	return counted
}

// d.mu held.
func (d *divergence) countReport(server raft.Server, voter bool, checkpoint Point, counted *tally, others map[Point]int) {
	report := d.reports[server.ID]
	if report == nil {
		return
	}
	held, reported := reportedAt(report, checkpoint.Index)
	switch {
	case reported && held == checkpoint:
		counted.agreeingVoters += oneVote(voter)
	case reported:
		counted.otherVoters += oneVote(voter)
		counted.differingMembers = append(
			counted.differingMembers,
			difference{
				member: server.ID,
				holds:  holdsOf(held),
			},
		)
		others[held] += oneVote(voter)
	case missedTheCheckpoint(report, checkpoint.Index):
		counted.otherVoters += oneVote(voter)
		counted.differingMembers = append(
			counted.differingMembers,
			difference{
				member: server.ID,
				holds:  "no state digest",
			},
		)
	case report.Base >= checkpoint.Index:
		// Only a newer checkpoint counts the state of a replica that
		// installed a snapshot past this one.
		d.askForACheckpoint()
	}
}

func oneVote(voter bool) int {
	if voter {
		return 1
	}
	return 0
}

func reportedAt(report *DigestReport, index uint64) (Point, bool) {
	at := slices.IndexFunc(report.Checkpoints, func(p Point) bool { return p.Index == index })
	if at < 0 {
		return Point{}, false
	}
	return report.Checkpoints[at], true
}

// A replica that applied past the checkpoint and recorded no state digest at
// it. One whose checkpoints all lie above that index answers for nothing.
func missedTheCheckpoint(report *DigestReport, index uint64) bool {
	if report.Base >= index || index > report.Latest.Index {
		return false
	}
	return len(report.Checkpoints) == 0 || report.Checkpoints[0].Index <= index
}

func holdsOf(p Point) string {
	return fmt.Sprintf("%s/%s", p.Chain, p.State)
}

func describe(checkpoint Point, leader raft.ServerID, counted tally) string {
	differing := make([]string, 0, len(counted.differingMembers))
	for _, member := range counted.differingMembers {
		differing = append(differing, fmt.Sprintf("%s holds %s", member.member, member.holds))
	}
	return fmt.Sprintf("at checkpoint %d leader %s holds %s, %d of %d voters hold it (a majority is %d); %s",
		checkpoint.Index, leader, holdsOf(checkpoint), counted.agreeingVoters, counted.voters, counted.majority(), strings.Join(differing, ", "))
}
