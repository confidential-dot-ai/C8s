package cdsha

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// Another cluster's leader, of the same cluster ID and pin set (a Recover
// fork), answers at the address this cluster's leader is known by. Control
// requests name the member they are for, and no other member's answer is
// taken: not its status (seats), and so not its barrier watermark or a write
// acknowledged in its log.
func TestControlAnswerFromAnotherMemberRefused(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	f := followers(c)[0]
	fork := newCluster(t, 1)
	fork.genesis("f0")
	other := fork.leader()
	if other == nil {
		t.Fatal("no fork leader")
	}
	redirected := raft.ServerAddress(other.node.cfg.Advertise + "#" + l.node.ID())
	if st, err := f.node.peerStatus(redirected, time.Second); err == nil {
		t.Fatalf("status for %s taken from member %s", l.node.ID(), st.ID)
	}
	if _, err := f.node.peerStatus(other.node.raftAddress(), time.Second); err != nil {
		t.Fatalf("the fork's leader, asked as itself: %v", err)
	}
}

// A follower's digest report is filed under the member its connection
// attests, not under the ID the request claims.
func TestDigestReportFiledUnderTheConnectionsMember(t *testing.T) {
	c := newCluster(t, 3)
	c.genesis("n0", "n1", "n2")
	l := c.leader()
	f := followers(c)[0]
	claimed := raft.ServerID("n9/1-forged")
	req := controlRequest{Op: ctlReadBarrier, ID: string(claimed), Digests: f.node.fsm.dig.report()}
	resp, err := f.node.call(l.node.cfg.Advertise, time.Second, req)
	if err != nil || resp.Err != "" {
		t.Fatalf("read barrier: %v %s", err, resp.Err)
	}
	l.node.div.mu.Lock()
	_, underClaimed := l.node.div.reports[claimed]
	_, underOwn := l.node.div.reports[raft.ServerID(f.node.ID())]
	l.node.div.mu.Unlock()
	if underClaimed || !underOwn {
		t.Fatalf("report of %s filed under %s (claimed): %v, under its own: %v", f.node.ID(), claimed, underClaimed, underOwn)
	}
	// A join, too, is for the member the connection attests.
	var peer *replica
	for _, r := range c.others(l, f) {
		peer = r
	}
	policy, err := json.Marshal(f.node.fsm.LocalPolicy())
	if err != nil {
		t.Fatal(err)
	}
	join := controlRequest{Op: ctlJoin, ID: peer.node.ID(), Address: string(peer.node.raftAddress()), Entry: policy, Reads: f.node.fsm.readable}
	resp, err = f.node.call(l.node.cfg.Advertise, time.Second, join)
	if err == nil && resp.Err == "" {
		t.Fatalf("join as member %s accepted from %s", peer.node.ID(), f.node.ID())
	}
}
