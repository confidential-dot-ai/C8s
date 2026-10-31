package cdsha

import (
	"bytes"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func clockCluster(t *testing.T) (*liveCluster, []*atomic.Int64) {
	t.Helper()
	c := newLiveCluster(t)
	offsets := []*atomic.Int64{{}, {}, {}}
	for _, offset := range offsets {
		c.clockNow = func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
		c.start()
	}
	c.decreeGenesis(c.replicas[0], false)
	c.started(c.replicas[0])
	c.joined(3)
	c.votersSeated(3)
	c.settled(10 * time.Second)
	return c, offsets
}

func TestClockQuarantineRetainsQuorumAndHandsOverToSoleHealthyVoter(t *testing.T) {
	for _, laggingLeader := range []bool{false, true} {
		t.Run(map[bool]string{false: "followers", true: "leader and follower"}[laggingLeader], func(t *testing.T) {
			c, offsets := clockCluster(t)
			leader := c.leader()
			c.rollSafe()
			healthy := leader
			if laggingLeader {
				healthy = c.follower()
			}
			voters := c.voters(leader)
			ca := leader.node.fsm.ClusterState().MeshCACert
			watermark := leader.node.fsm.AppliedIndex()
			for i, r := range c.replicas {
				if r != healthy {
					offsets[i].Store(-int64(time.Minute))
				}
			}
			eventually(t, 5*time.Second, "both laggards quarantined", func() bool {
				for _, r := range c.replicas {
					if r != healthy && r.node.ClockError() == nil {
						return false
					}
				}
				return true
			})
			eventually(t, 10*time.Second, "healthy voter leading and serving", func() bool { return healthy.node.leading() && healthy.node.Serving().OK })
			eventually(t, 5*time.Second, "known quarantine makes rolling unsafe", func() bool {
				safe, leading := healthy.node.RollSafe()
				return leading && !safe.OK && strings.Contains(safe.Reason, "clock")
			})
			if healthy.node.ClockError() != nil {
				t.Fatal("sole healthy voter quarantined")
			}
			if _, _, err := healthy.node.Secrets().PutIfAbsent(t.Context(), "/after-clock-transfer", []byte("committed"), secrets.WorkloadHolder("web")); err != nil {
				t.Fatalf("healthy leader could not commit: %v", err)
			}
			for _, r := range c.replicas {
				eventually(t, 5*time.Second, "committed state on every voter", func() bool {
					value, err := r.node.cfg.Secrets.Get(t.Context(), "/after-clock-transfer")
					return err == nil && string(value) == "committed"
				})
				if !slices.Equal(c.voters(r), voters) || !bytes.Equal(r.node.fsm.ClusterState().MeshCACert, ca) || r.node.fsm.Stuck() != "" || r.node.fsm.AppliedIndex() < watermark {
					t.Fatal("quarantine changed voters, CA or log health")
				}
				if r != healthy && r.node.Serving().OK {
					t.Fatal("lagging voter serves")
				}
			}
		})
	}
}

func TestClockQuarantinedLeaderRemainsFencedAfterReelection(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	old := c.leader()
	healthy := c.follower()
	for _, r := range c.replicas {
		if r != healthy {
			quarantine(r.node)
		}
	}
	eventually(t, 10*time.Second, "initial handover", healthy.node.leading)
	target, ok := c.serverFor(healthy, string(old.node.member))
	if !ok {
		t.Fatal("old leader lost its vote")
	}
	old.node.transfers.send(raft.ServerID(healthy.node.member), time.Now())
	if err := healthy.node.raft.LeadershipTransferToServer(target.ID, target.Address).Error(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "quarantined replica elected again", old.node.leading)
	if _, _, err := old.node.Secrets().PutIfAbsent(t.Context(), "/blocked-election", []byte("v"), secrets.WorkloadHolder("web")); err == nil {
		t.Fatal("reelection restored authority")
	}
	eventually(t, 5*time.Second, "healthy follower knows the elected leader", func() bool { return healthy.node.following().member == raft.ServerID(old.node.member) })
	if err := healthy.node.ConfirmRead(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := healthy.node.Secrets().PutIfAbsent(t.Context(), "/blocked-forward", []byte("v"), secrets.WorkloadHolder("web")); err == nil || !strings.Contains(err.Error(), old.node.ClockError().Error()) {
		t.Fatalf("forwarded write escaped the leader's clock refusal: %v", err)
	}
	if _, found := old.node.aVoterThatApplied(old.node.fsm.AppliedIndex()); found {
		t.Fatal("quarantined or cooling-down voter selected")
	}
	old.node.transfers.forget(raft.ServerID(healthy.node.member))
	eventually(t, 10*time.Second, "handover retried after cooldown", healthy.node.leading)
}

func TestClockQuarantinedLeaderWithNoTargetKeepsItsState(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	n := c.leader().node
	quarantine(n)
	if _, found := n.aVoterThatApplied(n.fsm.AppliedIndex()); found {
		t.Fatal("target exists in a single voter cluster")
	}
	n.handOverWhenClockQuarantined()
	if !n.leading() || !n.fsm.ClusterState().Joined() || n.fsm.CA() == nil {
		t.Fatal("no-target quarantine discarded authority state")
	}
	if _, _, err := n.Secrets().PutIfAbsent(t.Context(), "/blocked", []byte("v"), secrets.WorkloadHolder("web")); err == nil {
		t.Fatal("no-target leader admitted a write")
	}
}

func TestClockHandoffRequiresCurrentAuthenticatedEligibleVoter(t *testing.T) {
	for _, name := range []string{"eligible", "old peer", "old peer with stuck leader", "quarantined during exchange", "quarantined", "sticky quarantine", "sticky old peer", "not joined", "wrong member", "removed", "version changed", "pins revoked", "nonvoter"} {
		t.Run(name, func(t *testing.T) {
			c := newLiveCluster(t)
			c.genesis(3)
			leader := c.leader().node
			candidate, ok := c.serverFor(c.leader(), string(c.follower().node.member))
			if !ok {
				t.Fatal("no target voter")
			}
			fsm := newReplica(t).FSM
			fsm.core = leader.fsm.ClusterState()
			n := &Node{cfg: leader.cfg, member: leader.member, fsm: fsm, raft: leader.raft, peers: newMembers(string(leader.member), testDeadAfter)}
			reporter := newPeerReplica(t, string(candidate.ID), teetypes.PlatformSNP, snpVerdict(testCDSImage, testLaunchFile), time.Now().Add(time.Hour))
			answer := controlAnswer{Member: reporter.member, Joined: true, Voters: []string{reporter.member}, Clock: &clockReport{AtMS: time.Now().UnixMilli()}}
			switch name {
			case "old peer", "old peer with stuck leader", "quarantined during exchange":
				answer.Clock = nil
			case "quarantined":
				answer.Clock.Quarantined = true
			case "not joined":
				answer.Joined = false
			case "wrong member":
				answer.Member = "another-process"
			case "nonvoter":
				candidate.Suffrage = raft.Nonvoter
			case "sticky quarantine", "sticky old peer":
				if name == "sticky old peer" {
					answer.Clock = nil
				}
				n.peers.recordClock(reporter.member, true, n.configuration())
			}
			if name != "old peer with stuck leader" && name != "sticky old peer" && name != "quarantined during exchange" {
				quarantine(n)
			}
			entered, release := make(chan struct{}), make(chan struct{})
			reporter.serve(t, func(_ peer, _ controlRequest) controlAnswer { close(entered); <-release; return answer })
			conn, err := leader.mux.connect(reporter.peerAddress(), testCallTimeout)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.close()
			n.peers.answeredAt(reporter.peerAddress(), conn, time.Now())
			result := make(chan bool, 1)
			go func() {
				_, eligible := n.transferStanding(candidate)
				result <- eligible
			}()
			if name != "nonvoter" {
				select {
				case <-entered:
				case <-time.After(testCallTimeout):
					t.Fatal("standing request never arrived")
				}
			}
			switch name {
			case "quarantined during exchange":
				quarantine(n)
			case "removed":
				if err := leader.raft.RemoveServer(candidate.ID, 0, testTiming.Apply).Error(); err != nil {
					t.Fatal(err)
				}
			case "version changed", "pins revoked":
				fsm.mu.Lock()
				fsm.core.Version++
				if name == "pins revoked" {
					fsm.core.PinsDecree = nil
				}
				fsm.mu.Unlock()
			}
			close(release)
			if eligible := <-result; eligible != (name == "eligible" || name == "old peer with stuck leader") {
				t.Fatalf("eligible=%v", eligible)
			}
		})
	}
}

func TestClockRollSafetyUsesOnlyCurrentVotersAndKeepsNegativeEvidence(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(4)
	c.rollSafe()
	n := c.leader().node
	seen, _ := n.seatingNow()
	n.peers.recordClock(string(seen.nonVoters[0].ID), true, n.configuration())
	if reason := n.unsafeToRoll(seen); reason != "" {
		t.Fatalf("nonvoter blocked roll: %s", reason)
	}
	voter := seen.voters[0].ID
	n.peers.recordClock(string(voter), true, n.configuration())
	n.peers.recordClock(string(voter), false, n.configuration())
	if reason := n.unsafeToRoll(seen); !strings.Contains(reason, "clock") {
		t.Fatalf("known quarantine did not block roll: %s", reason)
	}
	seen.voters = seen.voters[1:]
	if reason := n.unsafeToRoll(seen); strings.Contains(reason, "clock") {
		t.Fatalf("former voter still blocks roll: %s", reason)
	}
}
