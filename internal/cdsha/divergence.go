package cdsha

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

// The leader compares the replicas' digests (digest.go). A follower sends
// its chain and recent checkpoints with every read barrier it asks for
// (about every Lease/3), so the comparison costs no connection of its own.
//
//   - Each report's latest chain point is checked against the leader's own
//     chain at that index. A mismatch only makes the leader propose a
//     checkpoint at once: two replicas cannot tell which of them is wrong.
//   - At the leader's latest checkpoint the majority decides. When at least
//     a majority of the voters (the leader included) hold the leader's
//     digest there, every member that holds another one, or none although
//     its chain covers that index, has diverged: its next read barrier is
//     refused with Diverged, and it stops (FSM.stop), stops serving, and is
//     restarted to take the leader's state from a snapshot this majority
//     vouched for. When a majority of the voters other than the leader hold
//     one digest that is not the leader's, the leader has diverged and stops
//     itself: a stuck leader hands off leadership, snapshots nothing (so it
//     seeds no replica and no backup) and exits. With 3 voters that takes
//     both followers; one corrupt follower never unseats a healthy leader.
//     With no majority either way the leader raises an alarm and stops
//     no one, and backups wait until a later checkpoint settles it.
//
// A committed entry is held by a majority, so the majority's digest is the
// committed history; an entry only a minority applied (the uncommitted
// write of hashicorp/raft #695) always loses.

// DigestReport is a follower's digests, sent with a read barrier.
type DigestReport struct {
	// Base is the first index the chain vouches for (a restored snapshot).
	Base        uint64  `json:"base"`
	Latest      Point   `json:"latest"`
	Checkpoints []Point `json:"checkpoints,omitempty"`
}

// divergence is the leader's view of the replicas' digests.
type divergence struct {
	mu       sync.Mutex
	reports  map[raft.ServerID]*DigestReport
	verdicts map[raft.ServerID]string // members found to differ from the majority
	// confirmed is the leader's latest checkpoint a majority matched; alarm
	// an unresolved disagreement; episode the alarm or verdict last logged.
	confirmed uint64
	alarm     string
	last      string
	episode   string
	// soon asks for a checkpoint now (a chain mismatch, or a backup that
	// waits for one). checkpointAt is when this leader last proposed one.
	soon         bool
	checkpointAt time.Time
}

func (d *divergence) status() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return cmp.Or(d.alarm, d.last)
}

// backupBlocked (leader) says why the state may not be sealed yet, or "".
// A backup waits for a checkpoint taken since the last backup that a
// majority confirmed, and for no disagreement to be open; it asks for the
// checkpoint if there is none yet.
func (n *Node) backupBlocked() string {
	var latest uint64
	if cps := n.fsm.dig.checkpointsCopy(); len(cps) > 0 {
		latest = cps[len(cps)-1].Index
	}
	d := &n.div
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.alarm != "":
		return d.alarm
	case latest == 0 || latest <= n.backupIndex:
		d.soon = true
		return "a checkpoint since the last backup"
	case d.confirmed != latest:
		return fmt.Sprintf("checkpoint %d to be confirmed by a majority", latest)
	}
	return ""
}

// observeReport (leader) records a follower's digests and returns why it
// diverged, or "". last is an index the leader's FSM has applied through.
func (n *Node) observeReport(id raft.ServerID, rep *DigestReport, last uint64) string {
	if id == "" || rep == nil {
		return ""
	}
	d := &n.div
	d.mu.Lock()
	defer d.mu.Unlock()
	if why := d.verdicts[id]; why != "" {
		return why
	}
	if d.reports == nil {
		d.reports = map[raft.ServerID]*DigestReport{}
	}
	d.reports[id] = rep
	p := rep.Latest
	chain, found, none := n.fsm.dig.chainAt(p.Index)
	// An open alarm already has its checkpoints (one per Timing.Checkpoint).
	if d.alarm == "" && ((found && chain != p.Chain) || (!found && none && p.Index <= last)) {
		if !d.soon {
			n.log.Warn("cds-ha: replica chain differs from the leader's; checking at a checkpoint",
				"member", id, "index", p.Index, "member_chain", p.Chain, "leader_chain", chain, "leader_has_command", found)
		}
		d.soon = true
	}
	return ""
}

// maybeCheckpoint (leader) proposes a checkpoint when the state changed
// since the last one and Timing.Checkpoint passed, or at once (one per
// Tick) when a chain mismatch was seen.
func (n *Node) maybeCheckpoint() {
	if n.fsm.Stuck() != "" {
		return
	}
	var latest uint64
	if cps := n.fsm.dig.checkpointsCopy(); len(cps) > 0 {
		latest = cps[len(cps)-1].Index
	}
	d := &n.div
	d.mu.Lock()
	since := time.Since(d.checkpointAt)
	due := (d.soon && since >= n.cfg.Timing.Tick) || (n.fsm.AppliedIndex() > latest && since >= n.cfg.Timing.Checkpoint)
	if due {
		d.checkpointAt, d.soon = time.Now(), false
	}
	d.mu.Unlock()
	if !due {
		return
	}
	if _, err := n.applyEntry(Entry{Kind: KindCheckpoint}); err != nil {
		n.log.Warn("cds-ha: checkpoint", "err", err)
	}
}

// checkDivergence (leader) decides at the leader's latest checkpoint.
func (n *Node) checkDivergence() {
	if n.fsm.Stuck() != "" {
		return
	}
	cps := n.fsm.dig.checkpointsCopy()
	servers := n.servers()
	if len(cps) == 0 || servers == nil {
		return
	}
	c := cps[len(cps)-1]
	voter, voters := map[raft.ServerID]bool{}, 0
	for _, s := range servers {
		voter[s.ID] = s.Suffrage == raft.Voter
		if voter[s.ID] {
			voters++
		}
	}
	need := voters/2 + 1
	d := &n.div
	d.mu.Lock()
	defer d.mu.Unlock()
	agree := 0
	if voter[n.id] {
		agree++
	}
	type differ struct {
		id    raft.ServerID
		value string // chain/state, or "none" for a missing checkpoint
	}
	var differs []differ
	groups := map[string]int{} // voters other than the leader, by value
	for _, s := range servers {
		rep := d.reports[s.ID]
		if s.ID == n.id || rep == nil {
			continue
		}
		i := slices.IndexFunc(rep.Checkpoints, func(p Point) bool { return p.Index == c.Index })
		switch {
		case i >= 0 && rep.Checkpoints[i] == c:
			if voter[s.ID] {
				agree++
			}
		case i >= 0:
			v := rep.Checkpoints[i].Chain + "/" + rep.Checkpoints[i].State
			differs = append(differs, differ{s.ID, v})
			if voter[s.ID] {
				groups[v]++
			}
		case rep.Base < c.Index && c.Index <= rep.Latest.Index:
			differs = append(differs, differ{s.ID, "none"})
		case rep.Base >= c.Index:
			// Restored from a snapshot past the checkpoint (a replica that
			// just joined): only a newer checkpoint can judge its state.
			d.soon = true
		}
	}
	if len(differs) == 0 {
		if agree >= need {
			d.confirmed = c.Index
		}
		if d.alarm != "" && agree >= need {
			n.log.Info("cds-ha: replica divergence resolved", "checkpoint", c.Index)
			d.alarm, d.episode = "", ""
		}
		return
	}
	var parts []string
	for _, x := range differs {
		parts = append(parts, fmt.Sprintf("%s=%s", x.id, x.value))
	}
	detail := fmt.Sprintf("checkpoint %d: leader %s=%s/%s, %d of %d voters agree with it (majority %d); differ: %s",
		c.Index, n.id, c.Chain, c.State, agree, voters, need, strings.Join(parts, ", "))
	// One log line per episode: the same replicas found the same way.
	logOnce := func(msg string) {
		var ids []string
		for _, x := range differs {
			ids = append(ids, string(x.id))
		}
		if key := msg + " " + strings.Join(ids, ","); d.episode != key {
			d.episode = key
			n.log.Error("cds-ha: replica divergence: "+msg, "checkpoint", c.Index, "detail", detail)
		}
	}
	switch {
	case agree >= need:
		if d.verdicts == nil {
			d.verdicts = map[raft.ServerID]string{}
		}
		for _, x := range differs {
			d.verdicts[x.id] = fmt.Sprintf("at checkpoint %d this replica holds %s, the majority %s/%s", c.Index, x.value, c.Chain, c.State)
		}
		d.confirmed, d.alarm = c.Index, ""
		d.last = "stopped diverged replicas: " + detail
		logOnce("replicas that differ from the majority are stopped and re-seeded from this leader")
	case maxGroup(groups) >= need:
		d.alarm = "this leader differs from the majority: " + detail
		logOnce("this leader differs from the majority; it stops and hands off leadership")
		_ = n.fsm.stopLocal(fmt.Errorf("%w: %s", ErrDiverged, detail))
	default:
		d.alarm = "no majority: " + detail
		logOnce("no majority holds one state; nothing is stopped and backups wait (see the runbook in docs/cds-ha.md)")
	}
}

func maxGroup(g map[string]int) int {
	m := 0
	for _, n := range g {
		m = max(m, n)
	}
	return m
}
