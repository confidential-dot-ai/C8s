package cdsha

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

func quarantine(n *Node) {
	n.clockMu.Lock()
	defer n.clockMu.Unlock()
	n.clockFault = &clockFault{member: "continuing-clock", lag: time.Minute}
}

func TestClockQuarantineRefusesAuthorityAndKeepsState(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	r := c.leader()
	n := r.node
	eventually(t, time.Second, "leader serving", serves(n))
	ca, ok := n.CA()
	if !ok {
		t.Fatal("leader has no CA")
	}
	decree := c.signDecree(c.admitDecree(r, testCDSDigest))
	posted, err := json.Marshal(decree)
	if err != nil {
		t.Fatal(err)
	}
	quarantine(n)
	entry := Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/blocked", Value: []byte("v")}}
	if serving := n.Serving(); serving.OK || serving.Reason != n.ClockError().Error() {
		t.Errorf("serving = %+v", serving)
	}
	if granted, ok := n.CA(); ok || granted != nil {
		t.Error("quarantined replica granted a CA")
	}
	if _, err := n.propose(entry); err == nil {
		t.Error("direct write admitted")
	}
	if answer := n.answerWrite(marshalled(t, entry), controlAnswer{}); answer.Err == "" {
		t.Error("forwarded write admitted")
	}
	if answer := n.answerDecree(posted, controlAnswer{}); answer.Err == "" {
		t.Error("forwarded decree admitted")
	}
	if _, err := n.TakeDecree(decree); err == nil {
		t.Error("target decree admitted")
	}
	if _, _, err := n.Secrets().PutIfAbsent(t.Context(), "/client", []byte("v"), secrets.WorkloadHolder("web")); !errors.Is(err, secrets.ErrUnavailable) {
		t.Errorf("client write = %v", err)
	}
	if !n.leading() || n.fsm.Stuck() != "" || n.fsm.CA() != ca || len(c.voters(r)) != 1 {
		t.Fatal("quarantine changed leadership, state or voters")
	}
	if err := n.ConfirmRead(); err != nil {
		t.Fatalf("read barrier stopped: %v", err)
	}
}

func TestClockQuarantineFencesConfiguration(t *testing.T) {
	for _, action := range []string{"bootstrap", "add", "remove", "move"} {
		t.Run(action, func(t *testing.T) {
			c := newLiveCluster(t)
			var n *Node
			if action == "bootstrap" {
				n = c.start().node
			} else {
				c.genesis(1)
				n = c.leader().node
			}
			if action == "remove" || action == "move" {
				if err := n.raft.AddNonvoter("blocked", "127.0.0.1:1#blocked", 0, testTiming.Apply).Error(); err != nil {
					t.Fatal(err)
				}
			}
			before := n.configuration()
			quarantine(n)
			switch action {
			case "bootstrap":
				if err := n.bootstrapSolo(); err == nil {
					t.Error("bootstrap admitted")
				}
			case "add":
				if err := n.addNonVoter(reachedMember{member: "blocked"}); err == nil {
					t.Error("new member admitted")
				}
			case "remove":
				if n.takeOut("blocked") {
					t.Error("voter removed")
				}
			case "move":
				n.moveMember(raft.Server{ID: "blocked"}, reachedMember{member: "blocked"})
			}
			if !slices.Equal(n.configuration(), before) {
				t.Error("quarantined authority changed the configuration")
			}
		})
	}
}

func TestClockQuarantineRefusesLocalAdmit(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	n := c.leader().node
	d := c.admitDecree(c.leader(), testCDSDigest)
	n.posted.hold(c.signDecree(d))
	quarantine(n)
	n.admitAsDecreed()
	if n.decreedImages.Load() != nil {
		t.Fatal("quarantined target admitted new peer images")
	}
}

func TestClockQuarantineSerializesEnqueueWithoutWaitingForApply(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	n := c.leader().node
	entry := marshalled(t, Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/admitted", Value: []byte("v")}})
	admitted, completed := make(chan struct{}), make(chan error, 1)
	n.fsm.mu.Lock()
	go func() {
		completed <- n.enqueueMutation(func() raft.Future {
			future := n.raft.Apply(entry, testTiming.Apply)
			close(admitted)
			return future
		})
	}()
	<-admitted
	latched := make(chan struct{})
	go func() { quarantine(n); close(latched) }()
	select {
	case <-latched:
	case <-time.After(time.Second):
		n.fsm.mu.Unlock()
		t.Fatal("quarantine waited for the admitted future")
	}
	n.fsm.mu.Unlock()
	if err := <-completed; err != nil {
		t.Fatalf("admitted operation did not complete: %v", err)
	}
	before := n.raft.LastIndex()
	for name, submit := range map[string]func() raft.Future{
		"apply":     func() raft.Future { return n.raft.Apply(entry, testTiming.Apply) },
		"bootstrap": func() raft.Future { return n.raft.BootstrapCluster(n.solo()) },
		"voter":     func() raft.Future { return n.raft.AddVoter("blocked", "127.0.0.1:1#blocked", 0, testTiming.Apply) },
		"demote":    func() raft.Future { return n.raft.DemoteVoter(raft.ServerID(n.member), 0, testTiming.Apply) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := n.enqueueMutation(submit); err != n.ClockError() {
				t.Fatalf("enqueue = %v", err)
			}
		})
	}
	if n.raft.LastIndex() != before {
		t.Fatal("post-quarantine submission reached Raft")
	}
	if value, err := n.cfg.Secrets.Get(t.Context(), "/admitted"); err != nil || string(value) != "v" {
		t.Fatalf("admitted state = %q, %v", value, err)
	}
}

func TestClockQuarantineWinsWaitingCAAndMutationAdmission(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	n := c.leader().node
	eventually(t, time.Second, "leader serving", serves(n))
	granted, ok := n.CA()
	if !ok {
		t.Fatal("no initial issuance grant")
	}
	n.clockMu.Lock()
	caResult, writeResult := make(chan bool, 1), make(chan error, 1)
	go func() { _, issuing := n.CA(); caResult <- issuing }()
	go func() {
		_, _, err := n.commit(marshalled(t, Entry{Kind: KindSecret, Secret: &secrets.Command{Op: secrets.OpPut, Path: "/waiting", Value: []byte("v")}}))
		writeResult <- err
	}()
	n.clockFault = &clockFault{member: "ahead", lag: time.Minute}
	n.clockMu.Unlock()
	if <-caResult {
		t.Fatal("waiting acquisition obtained a CA after quarantine")
	}
	if err := <-writeResult; err != n.ClockError() {
		t.Fatalf("waiting mutation = %v", err)
	}
	if granted != n.fsm.CA() {
		t.Fatal("previous issuance grant was revoked")
	}
	if _, err := n.cfg.Secrets.Get(t.Context(), "/waiting"); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("waiting mutation changed state: %v", err)
	}
}

func TestClockQuarantineFencesDirectSeatChanges(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(4)
	c.rollSafe()
	n := c.leader().node
	seen, held := n.seatingNow()
	if !held {
		t.Fatal("no seats")
	}
	eventually(t, 5*time.Second, "spare caught up", func() bool { _, found := n.nextToSeat(seen); return found })
	for _, voter := range seen.voters {
		n.transfers.send(voter.ID, time.Now())
	}
	before := n.configuration()
	quarantine(n)
	seen.seats = 4
	if n.fillFreeSeat(seen) {
		t.Error("quarantined leader promoted a nonvoter")
	}
	seen.seats = 2
	if n.demoteSurplusVoter(seen) {
		t.Error("quarantined leader demoted a voter")
	}
	if !slices.Equal(n.configuration(), before) {
		t.Fatal("quarantine changed the voter set")
	}
}

func TestClockQuarantineAfterServiceCheckRefusesFinalCAGrant(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(1)
	n := c.leader().node
	eventually(t, time.Second, "initial service check", serves(n))
	candidate := n.fsm.CA()
	if candidate == nil {
		t.Fatal("serving replica has no CA candidate")
	}
	quarantine(n)
	if granted, ok := n.grantCA(candidate); ok || granted != nil {
		t.Fatal("final acquisition granted a CA after quarantine crossed the service check")
	}
}
