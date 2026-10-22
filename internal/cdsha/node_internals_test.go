package cdsha

import (
	"bytes"
	"crypto/tls"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// syncBuffer is a log sink safe for the replica's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// A stopped replica claims no membership, seat or configuration, and
// refuses joins and writes.
func TestStoppedReplicaClaimsNothing(t *testing.T) {
	_, pub := operatorKey(t)
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	if n.member() {
		t.Fatal("an unstarted replica is a member")
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	if n.isVoter() {
		t.Fatal("a replica outside any configuration holds a seat")
	}
	if _, _, err := n.applyLocal([]byte(`{}`)); err == nil {
		t.Fatal("a replica that does not lead applied an entry")
	}
	n.shutdown()
	if n.member() || n.isVoter() || n.seatsFilled() {
		t.Fatal("a stopped replica claims membership or seats")
	}
	if resp := n.handleJoin(controlRequest{ID: "x/1-a", Address: "127.0.0.1:1#x/1-a", Reads: Format}); resp.Err == "" {
		t.Fatalf("a stopped replica took a join: %+v", resp)
	}
	if err := n.checkPinsKeepMajority([]string{"m1"}); err == nil {
		t.Fatal("pins checked without a configuration")
	}
	n.reconcile() // no configuration: nothing to do
	n.demoteExtraVoter([]raft.Server{{Suffrage: raft.Voter, ID: n.id}, {Suffrage: raft.Voter, ID: "x/1-a"}, {Suffrage: raft.Voter, ID: "y/1-a"}})
}

// Failures from before a member was added count from when it was added.
func TestNoteFailureNotBeforeJoin(t *testing.T) {
	_, pub := operatorKey(t)
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	joined := time.Now()
	id := raft.ServerID("x/1-a")
	n.addedAt[id] = joined
	n.noteFailure(id, time.Time{}, joined.Add(-time.Minute))
	if got := n.failing[id]; !got.Equal(joined) {
		t.Fatalf("failing since %v, want the join %v", got, joined)
	}
	n.noteFailure(id, joined.Add(-time.Hour), joined.Add(time.Minute))
	if got := n.failing[id]; !got.Equal(joined) {
		t.Fatalf("a failure already noted moved: %v", got)
	}
}

// A suspect member that answers as itself is not removed; one that does not
// answer stays suspect. Extra voters are demoted, a failing one first, never
// the leader.
func TestLeaderProbesSuspectsAndDemotesExtraVoters(t *testing.T) {
	logs := &syncBuffer{}
	s := newSolo(t, func(c *Config) {
		c.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	})
	n := s.node
	other, err := NewNode(soloConfig(t, "n1", freeAddr(t), n.cfg.OperatorPubKey, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.shutdown)
	dead := raft.Server{Suffrage: raft.Voter, ID: "n2/1-a", Address: "127.0.0.1:1#n2/1-a"}
	live := raft.Server{Suffrage: raft.Voter, ID: other.id, Address: other.raftAddress()}
	long := time.Now().Add(-time.Hour)
	n.mu.Lock()
	n.failing[dead.ID], n.failing[live.ID] = long, long
	n.mu.Unlock()
	n.clearReachable([]raft.Server{dead, live}, time.Now())
	n.mu.Lock()
	_, deadSuspect := n.failing[dead.ID]
	_, liveSuspect := n.failing[live.ID]
	n.mu.Unlock()
	if !deadSuspect || liveSuspect {
		t.Fatalf("suspects after the probe: dead %v, answering %v", deadSuspect, liveSuspect)
	}
	self := raft.Server{Suffrage: raft.Voter, ID: n.id, Address: n.raftAddress()}
	n.demoteExtraVoter([]raft.Server{self, self})
	if strings.Contains(logs.String(), "voter demoted") {
		t.Fatal("the leader demoted itself")
	}
	n.demoteExtraVoter([]raft.Server{self, live, dead})
	eventually(t, 5*time.Second, "demotion logged", func() bool { return strings.Contains(logs.String(), "voter demoted") })
	if out := logs.String(); !strings.Contains(out, "id="+string(dead.ID)) {
		t.Fatalf("demoted a healthy voter first:\n%s", out)
	}
}

// A peer certificate past its age is renewed, and a failed renewal is
// retried on the next tick.
func TestPeerCertificateRenewal(t *testing.T) {
	_, pub := operatorKey(t)
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	mint := n.certs.mint
	n.certs.mint = func() (tls.Certificate, error) {
		if calls.Add(1) == 1 {
			return tls.Certificate{}, errors.New("no TEE right now")
		}
		return mint()
	}
	n.certs.mu.Lock()
	n.certs.made = time.Now().Add(-7 * time.Hour)
	n.certs.mu.Unlock()
	runNode(t, n)
	eventually(t, 5*time.Second, "certificate renewed", func() bool { return n.certs.age() < time.Hour })
	if calls.Load() < 2 {
		t.Fatalf("renewed after %d mints", calls.Load())
	}
}
