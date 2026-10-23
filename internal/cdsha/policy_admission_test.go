package cdsha

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
)

func TestJoinRejectsPolicyBeforeMembershipMutation(t *testing.T) {
	n := newSolo(t, nil).node
	before := n.servers()
	for name, p := range policyVariants(n.fsm.LocalPolicy()) {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(p)
			got := n.handleJoin(controlRequest{ID: "other/1-test", Address: "127.0.0.1:1/other/1-test", Reads: Format, Entry: raw})
			if got.Err == "" {
				t.Fatal("policy mismatch admitted")
			}
			if len(n.servers()) != len(before) {
				t.Fatal("membership changed before refusal")
			}
		})
	}
}

func TestJoinPolicyMismatchSurvivesLeaderRedirect(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	leader := c.leader()
	var via *Node
	for _, r := range c.live() {
		if r != leader {
			via = r.node
			break
		}
	}
	cfg := soloConfig(t, "mismatch", freeAddr(t), c.opPub, c.decrees)
	cfg.Ledger = sandboxledger.New(7*time.Hour, 100)
	n, err := NewNode(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Start(); err != nil {
		t.Fatal(err)
	}
	defer n.shutdown()
	before := len(leader.node.servers())
	resp, err := n.askJoin(via.cfg.Advertise)
	if err != nil || !resp.Member || !strings.Contains(resp.Err, "policy") {
		t.Fatalf("redirect: %+v %v", resp, err)
	}
	if n.member() || len(leader.node.servers()) != before {
		t.Fatal("mismatch changed membership")
	}
}
