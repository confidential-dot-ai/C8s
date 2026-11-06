package cdsha

import (
	"net/netip"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// What a leader makes of the members its Raft replicates to: the wait before
// a member counts dead starts where it went silent, and the failures of a
// replication stream that outlived a re-add count for nothing.

// A replica of the test cluster that joined none: its peer port and its Raft
// are up, and no loop drives it.
func aMember(t *testing.T, timing Timing) *Node {
	t.Helper()
	c := newLiveCluster(t)
	c.timing = timing
	node, err := NewNode(c.replicaConfig(c.attestationAPI()))
	if err != nil {
		t.Fatalf("new replica: %v", err)
	}
	if err := node.Start(); err != nil {
		t.Fatalf("start replica: %v", err)
	}
	t.Cleanup(node.stop)
	return node
}

// The answer a leader counts a member live by (members.go).
func answered(m *members, address netip.AddrPort, member string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	answering := m.record(address, member, at)
	answering.replied = at
	answering.repliedBy = member
}

var theOtherReplica = netip.MustParseAddrPort("127.0.0.1:8444")

// A voter its leader cannot replicate to holds no copy of the log, however
// well it answers the control channel.
func TestAVoterItsLeaderCannotReplicateToCountsDead(t *testing.T) {
	n := aMember(t, testTiming)
	member := raft.ServerID("gkqjvjjqkqp6yqxfwqkqm5x7oe")
	term := n.raft.Load().CurrentTerm()
	now := time.Now()
	n.seatbook.sightedAt(member, now.Add(-time.Hour))
	answered(n.peers, theOtherReplica, string(member), now)

	if n.countsDead(term, member, now) {
		t.Fatal("a member that just answered counts dead")
	}
	n.noteFailure(member, now.Add(-n.cfg.Timing.DeadAfter), now)

	if failingFor := n.failures.failingFor(term, member, now); failingFor < n.cfg.Timing.DeadAfter {
		t.Errorf("the failure of a member last contacted a DeadAfter ago is %s old, want it counted from that contact",
			failingFor)
	}
	if !n.countsDead(term, member, now) {
		t.Error("a member its leader has not replicated to for DeadAfter counts alive")
	}
}

// The streams that recorded a failure are one leader's own.
func TestTheFailuresOfATermThatPassedCountForNothing(t *testing.T) {
	n := aMember(t, testTiming)
	member := raft.ServerID("d9lqkqfwqkqp6yqxfwqkqm5x7oe")
	term := n.raft.Load().CurrentTerm()
	now := time.Now()
	n.noteFailure(member, now.Add(-time.Hour), now)

	if failingFor := n.failures.failingFor(term+1, member, now); failingFor != 0 {
		t.Errorf("a failure of the term before is %s old in the term after it", failingFor)
	}
	n.failures.failing(term+1, raft.ServerID("another"), now)
	if failingFor := n.failures.failingFor(term+1, member, now); failingFor != 0 {
		t.Errorf("a failure of the term before survived a failure of the term after it, %s old",
			failingFor)
	}
}

func TestAMemberRaftReachesAgainCountsAlive(t *testing.T) {
	n := aMember(t, testTiming)
	member := raft.ServerID("b4lqkqfwqkqp6yqxfwqkqm5x7oe")
	term := n.raft.Load().CurrentTerm()
	now := time.Now()
	n.noteFailure(member, now.Add(-time.Hour), now)

	n.note(raft.Observation{Raft: n.raft.Load(), Data: raft.ResumedHeartbeatObservation{PeerID: member}})

	if failingFor := n.failures.failingFor(term, member, now); failingFor != 0 {
		t.Errorf("a member Raft replicates to again is failing for %s", failingFor)
	}
}

// Such a stream reports a contact from before this leader took the member in.
func TestTheFailuresOfAStreamThatOutlivedAReAddAreIgnored(t *testing.T) {
	n := aMember(t, testTiming)
	member := raft.ServerID("c7lqkqfwqkqp6yqxfwqkqm5x7oe")
	term := n.raft.Load().CurrentTerm()
	now := time.Now()
	n.seatbook.sightedAt(member, now)

	n.noteFailure(member, now.Add(-time.Hour), now)

	if failingFor := n.failures.failingFor(term, member, now); failingFor != 0 {
		t.Errorf("a member taken back into the cluster is failing for %s, from a stream of its earlier membership",
			failingFor)
	}
}
