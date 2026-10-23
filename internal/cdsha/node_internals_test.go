package cdsha

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
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

// A suspect member that answers as itself is not removed; one that does not
// answer, or where another process answers, stays suspect. Extra voters are demoted, a failing one first, never
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
	// An earlier member at live's address: another process answers there.
	earlier := raft.Server{Suffrage: raft.Voter, ID: "n1/1-a", Address: live.Address}
	long := time.Now().Add(-time.Hour)
	n.mu.Lock()
	n.failing[dead.ID], n.failing[live.ID], n.failing[earlier.ID] = long, long, long
	n.mu.Unlock()
	n.clearReachable([]raft.Server{dead, live, earlier}, time.Now())
	n.mu.Lock()
	_, deadSuspect := n.failing[dead.ID]
	_, liveSuspect := n.failing[live.ID]
	_, earlierSuspect := n.failing[earlier.ID]
	n.mu.Unlock()
	if !deadSuspect || liveSuspect || !earlierSuspect {
		t.Fatalf("suspects after the probe: dead %v, answering %v, replaced %v", deadSuspect, liveSuspect, earlierSuspect)
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

// flakyAttestor fails its first Evidence call.
type flakyAttestor struct {
	Attestor
	calls atomic.Int32
}

func (a *flakyAttestor) Evidence(rd [48]byte) ([]byte, error) {
	if a.calls.Add(1) == 1 {
		return nil, errors.New("no TEE right now")
	}
	return a.Attestor.Evidence(rd)
}

// A peer certificate past its age is renewed, and a failed renewal is
// retried on the next tick.
func TestPeerCertificateRenewal(t *testing.T) {
	_, pub := operatorKey(t)
	n, err := NewNode(soloConfig(t, "n0", freeAddr(t), pub, nil))
	if err != nil {
		t.Fatal(err)
	}
	flaky := &flakyAttestor{Attestor: n.cfg.Attestor}
	n.cfg.Attestor = flaky
	aged := *n.cert.Load()
	leaf := *aged.Leaf
	leaf.NotBefore = time.Now().Add(-7 * time.Hour)
	aged.Leaf = &leaf
	n.cert.Store(&aged)
	runNode(t, n)
	eventually(t, 5*time.Second, "certificate renewed", func() bool { return time.Since(n.cert.Load().Leaf.NotBefore) < time.Hour })
	if calls := flaky.calls.Load(); calls < 2 {
		t.Fatalf("renewed after %d mints", calls)
	}
}

// A replica that cannot find its peers says so (it can never join), at Info,
// rate-limited like a refused join: found on TDX, where a rebooted node's pod
// network was down and the replica waited silently.
func TestJoinReportsFailedPeerDiscovery(t *testing.T) {
	_, pub := operatorKey(t)
	for name, peers := range map[string]func(context.Context) ([]string, error){
		"lookup error": func(context.Context) ([]string, error) { return nil, errors.New("lookup c8s-cds-peers: no such host") },
		"no peers":     func(context.Context) ([]string, error) { return nil, nil },
	} {
		t.Run(name, func(t *testing.T) {
			logs := &syncBuffer{}
			cfg := soloConfig(t, "n1", freeAddr(t), pub, nil)
			cfg.Peers = peers
			cfg.Logger = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
			n, err := NewNode(cfg)
			if err != nil {
				t.Fatal(err)
			}
			n.joinOrBootstrap(context.Background())
			n.joinOrBootstrap(context.Background()) // rate-limited: logged once
			if got := strings.Count(logs.String(), "peer discovery"); got != 1 {
				t.Fatalf("peer discovery logged %d times:\n%s", got, logs.String())
			}
		})
	}
}

// A peer that belongs to a cluster keeps this replica from bootstrapping
// another, whoever answers the join redirect: a loner at the leader's
// address, or nobody.
func TestAskJoinKeepsMembershipOverRedirect(t *testing.T) {
	loner := func(Claims, controlRequest) controlResponse { return controlResponse{Err: "no cluster here"} }
	_, b, v, target := muxPeers(t, loner)
	for name, leader := range map[string]string{"loner answers": target.ln.Addr().String(), "leader unreachable": "127.0.0.1:2"} {
		redirect := func(Claims, controlRequest) controlResponse {
			return controlResponse{Member: true, Leader: leader, Err: "not the leader"}
		}
		m, err := newMux("127.0.0.1:0", "127.0.0.1:1", "a/1-x", b.tls, v, redirect, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := b.askJoin(m.ln.Addr().String())
		_ = m.Close()
		if err != nil || !resp.Member {
			t.Errorf("%s: %+v, %v: the replica would bootstrap a second cluster", name, resp, err)
		}
	}
}

// A restarted member replaces the earlier one only once it is healthy.
func TestRestartedMemberReplacesOnlyWhenHealthy(t *testing.T) {
	n := newSolo(t, nil).node
	old, restarted := raft.ServerID("x/1-a"), raft.ServerID("x/2-a")
	for _, id := range []raft.ServerID{old, restarted} {
		if err := n.r().AddNonvoter(id, raft.ServerAddress("127.0.0.1:1#"+id), 0, time.Second).Error(); err != nil {
			t.Fatal(err)
		}
	}
	n.mu.Lock()
	n.failing[restarted] = time.Now()
	n.mu.Unlock()
	time.Sleep(2 * testTiming.Stabilize)
	if !slices.ContainsFunc(n.servers(), func(s raft.Server) bool { return s.ID == old }) {
		t.Fatal("a failing restart replaced the earlier member")
	}
}
