package cdsha

import (
	"encoding/json"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
)

func TestClockReportedByMemberAndStanding(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	n := c.leader().node
	for _, op := range []controlOp{opMember, opStanding} {
		encoded, err := json.Marshal(n.answerControl(peer{}, controlRequest{Op: op}))
		if err != nil {
			t.Fatal(err)
		}
		var answer struct {
			Clock *struct {
				AtMS        int64 `json:"at_ms"`
				Quarantined bool  `json:"quarantined"`
			} `json:"clock"`
		}
		if err := json.Unmarshal(encoded, &answer); err != nil {
			t.Fatal(err)
		}
		if answer.Clock == nil || answer.Clock.AtMS <= 0 || answer.Clock.Quarantined {
			t.Errorf("%s clock = %+v, want a positive timestamp and eligible state", op, answer.Clock)
		}
	}
}

func TestClockObservationRequiresCurrentAuthenticatedMember(t *testing.T) {
	for _, name := range []string{"current", "ordinary write", "old peer", "unjoined peer", "refused", "wrong member", "discovery only", "removed", "same process returned under unchanged admission", "pins revoked", "pins changed", "version changed", "unjoined local", "delayed receipt"} {
		t.Run(name, func(t *testing.T) {
			c := newLiveCluster(t)
			c.genesis(1)
			leader := c.leader().node
			received := time.Now()
			fsm := newReplica(t).FSM
			fsm.core = leader.fsm.ClusterState()
			n := &Node{cfg: leader.cfg, member: leader.member, fsm: fsm, raft: leader.raft,
				peers: newMembers(string(leader.member), testDeadAfter), clockNow: func() time.Time { return received }}
			reporter := newPeerReplica(t, "clock-peer", teetypes.PlatformSNP,
				snpVerdict(testCDSImage, testLaunchFile), time.Now().Add(time.Hour))
			answer := controlAnswer{Member: reporter.member, Joined: true,
				Clock: &clockReport{AtMS: received.Add(time.Minute).UnixMilli(), Quarantined: true}}
			switch name {
			case "old peer":
				answer.Clock = nil
			case "unjoined peer":
				answer.Joined = false
			case "refused":
				answer.Err = "refused"
			case "wrong member":
				answer.Member = "another-member"
			case "delayed receipt":
				received = received.Add(2 * time.Minute)
			case "unjoined local":
				n.fsm = newReplica(t).FSM
			case "pins revoked":
				n.fsm.core.PinsDecree = nil
			}
			entered, release := make(chan struct{}), make(chan struct{})
			reporter.serve(t, func(_ peer, _ controlRequest) controlAnswer {
				close(entered)
				<-release
				return answer
			})
			conn, err := leader.mux.connect(reporter.peerAddress(), testCallTimeout)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.close()
			held := reachedMember{member: reporter.member, address: reporter.peerAddress(), control: conn}
			if name != "discovery only" {
				if err := n.raft.AddNonvoter(raft.ServerID(held.member), held.raftAddress(), 0, testTiming.Apply).Error(); err != nil {
					t.Fatal(err)
				}
			}
			n.peers.answeredAt(held.address, conn, time.Now())
			done := make(chan struct{})
			go func() { defer close(done); n.recheck(held) }()
			select {
			case <-entered:
			case <-time.After(testCallTimeout):
				t.Fatal("clock request did not reach the authenticated peer")
			}
			switch name {
			case "ordinary write":
				if _, err := leader.Secrets().Put(t.Context(), "/clock", []byte("value")); err != nil {
					t.Error(err)
				}
			case "removed", "same process returned under unchanged admission":
				if err := n.raft.RemoveServer(raft.ServerID(held.member), 0, testTiming.Apply).Error(); err != nil {
					t.Error(err)
				}
				if name == "same process returned under unchanged admission" {
					if err := n.raft.AddNonvoter(raft.ServerID(held.member), held.raftAddress(), 0, testTiming.Apply).Error(); err != nil {
						t.Error(err)
					}
				}
			case "pins changed", "version changed":
				n.fsm.mu.Lock()
				n.fsm.core.Version++
				if name == "pins changed" {
					n.fsm.core.PinsDecree = nil
				}
				n.fsm.mu.Unlock()
			}
			close(release)
			<-done
			eligible := name == "current" || name == "ordinary write" || name == "same process returned under unchanged admission"
			if got, want := n.ClockError() != nil, eligible; got != want {
				t.Fatalf("clock fault = %v, want fault=%v", n.ClockError(), want)
			}
			if got, want := n.peers.quarantined[held.member], eligible || name == "delayed receipt"; got != want {
				t.Fatalf("peer quarantine = %v, want %v", got, want)
			}
		})
	}
}

func TestClockLagUsesReceiptAndConfiguredAllowance(t *testing.T) {
	received := time.UnixMilli(1_000_000)
	for _, tt := range []struct {
		name string
		atMS int64
		skew time.Duration
		lag  bool
	}{
		{"below", received.Add(30*time.Second - time.Millisecond).UnixMilli(), 30 * time.Second, false},
		{"equal", received.Add(30 * time.Second).UnixMilli(), 30 * time.Second, false},
		{"above", received.Add(30*time.Second + time.Millisecond).UnixMilli(), 30 * time.Second, true},
		{"zero equal", received.UnixMilli(), 0, false},
		{"zero ahead", received.Add(time.Millisecond).UnixMilli(), 0, true},
		{"custom equal", received.Add(time.Second).UnixMilli(), time.Second, false},
		{"custom ahead", received.Add(time.Second + time.Millisecond).UnixMilli(), time.Second, true},
		{"missing", 0, 0, false},
		{"negative", -1, 0, false},
		{"extreme negative", math.MinInt64, 0, false},
		{"extreme positive", math.MaxInt64, 30 * time.Second, true},
		{"delayed receipt", received.Add(-time.Second).UnixMilli(), 0, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fault := clockLag("ahead", tt.atMS, received, tt.skew)
			if (fault != nil) != tt.lag {
				t.Fatalf("fault = %v, want lag=%v", fault, tt.lag)
			}
			if fault != nil && (fault.member != "ahead" || fault.lag <= 0 || fault.Error() == "") {
				t.Fatalf("fault lost its evidence: %+v", fault)
			}
		})
	}
}

func TestClockLagIsStickyWithTwoLaggingVoters(t *testing.T) {
	c := newLiveCluster(t)
	c.timing.DeadAfter = time.Second
	var offsets [3]atomic.Int64
	for i := range offsets {
		c.clockNow = func() time.Time { return time.Now().Add(time.Duration(offsets[i].Load())) }
		c.start()
	}
	c.decreeGenesis(c.replicas[0], false)
	c.started(c.replicas[0])
	c.joined(3)
	c.votersSeated(3)
	c.settled(10 * time.Second)
	for _, r := range c.replicas {
		if err := r.node.ClockError(); err != nil {
			t.Fatalf("equal clocks produced evidence: %v", err)
		}
	}
	offsets[0].Store(-int64(time.Minute))
	offsets[1].Store(-int64(time.Minute))
	first, second, ahead := c.replicas[0], c.replicas[1], c.replicas[2]
	eventually(t, 5*time.Second, "both laggards observing the continuing clock", func() bool {
		return first.node.ClockError() != nil && second.node.ClockError() != nil
	})
	if err := ahead.node.ClockError(); err != nil {
		t.Fatalf("two laggards quarantined the continuing clock: %v", err)
	}
	fault := first.node.ClockError()
	for i := range offsets {
		offsets[i].Store(0)
	}
	first.node.lease.Store(nil)
	first.node.clockJumps.Add(1)
	leader := c.leader()
	if err := leader.node.raft.LeadershipTransfer().Error(); err != nil {
		t.Fatal(err)
	}
	eventually(t, 5*time.Second, "healthy authority after transfer", ahead.node.leading)
	c.stop(second)
	repaired := c.startAt(second.peerAddress())
	c.settled(10 * time.Second)
	c.votersSeated(3)
	eventually(t, 5*time.Second, "replacement serving", serves(repaired.node))
	c.stop(ahead)
	c.startAt(ahead.peerAddress())
	c.settled(10 * time.Second)
	c.votersSeated(3)
	if err := first.node.ConfirmRead(); err != nil {
		t.Fatal(err)
	}
	if first.node.ClockError() != fault || second.node.ClockError() == nil {
		t.Fatal("agreement, renewed lease, term change or peer restart erased the fault")
	}
	if first.node.fsm.Stuck() != "" || len(c.voters(c.leader())) != 3 {
		t.Fatal("clock observation changed replicated health or voting")
	}
	for _, op := range []controlOp{opMember, opStanding} {
		if answer := first.node.answerControl(peer{}, controlRequest{Op: op}); answer.Clock == nil || !answer.Clock.Quarantined {
			t.Fatalf("%s lost the sticky quarantine report", op)
		}
	}
}

func TestClockPeerQuarantineSurvivesAddressLoss(t *testing.T) {
	m := newMembers("own", testDeadAfter)
	current := []raft.Server{{ID: "same-process"}}
	m.recordClock("same-process", true, current)
	m.forgetUnresolved(discovered{complete: true})
	m.recordClock("same-process", false, current)
	if !m.quarantined["same-process"] {
		t.Fatal("missing address or false report cleared the known quarantine")
	}
	m.recordClock("new-process", false, []raft.Server{{ID: "new-process"}})
	if len(m.quarantined) != 0 {
		t.Fatalf("removed member blocked its replacement: %v", m.quarantined)
	}
}
