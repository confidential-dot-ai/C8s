// The replica control channel: one request and one answer per exchange, over
// the attested connection the member map holds open to each member it knows.
//
// A request carries no member id of its own. The handshake attested the
// member asking, and its answer names the member answering, so neither side
// acts on a claim the other makes about who it is.

package cdsha

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hashicorp/raft"
)

// controlTimeout bounds one exchange that carries no write; a forwarded write
// is bounded by Timing.Apply, the budget for one replicated write.
const controlTimeout = 5 * time.Second

type controlOp string

const (
	// opMember is how a replica learns where a member is and that it is still
	// there.
	opMember controlOp = "member"
	// opJoin asks the cluster's leader to take the member asking in.
	opJoin controlOp = "join"
	// opWrite asks the leader to commit a client write another replica took.
	opWrite controlOp = "write"
	// opDecree asks the leader to apply a decree posted to another replica.
	opDecree controlOp = "decree"
	// opRead asks the leader to confirm a read: a barrier of its own, and the
	// watermark its state machine had applied behind it (lease.go).
	opRead controlOp = "read"
	// opStanding asks a member where it stands in the cluster: seats.go,
	// handoff.go and stuck.go all judge by the answer.
	opStanding controlOp = "standing"
)

type controlRequest struct {
	Op controlOp `json:"op"`
	// Policy is the limits the member asking applies commands under (opJoin).
	Policy Policy `json:"policy,omitzero"`
	// Entry is the log entry the leader is to commit (opWrite).
	Entry json.RawMessage `json:"entry,omitempty"`
	// Decree is the signed decree the leader is to apply (opDecree).
	Decree json.RawMessage `json:"decree,omitempty"`
}

// controlAnswer: Member and Joined answer every request; the rest belongs to
// the op asked.
type controlAnswer struct {
	// Member is the member that answered.
	Member string `json:"member"`
	// Joined reports a replica that holds a cluster, which keeps another from
	// starting one.
	Joined bool `json:"joined,omitempty"`
	// Leader names the member leading, where the replica answering follows it.
	Leader string `json:"leader,omitempty"`
	// Err is why the request was refused; empty is what the op asked for.
	Err string `json:"err,omitempty"`
	// Full reports a write the admission cap refused, which the store answers
	// as full rather than as one to retry.
	Full bool `json:"full,omitempty"`
	// Index is where the leader committed a forwarded write, or the watermark
	// its barrier confirmed for a read; the replica that asked waits for its
	// own state machine to reach it.
	Index uint64 `json:"index,omitempty"`
	// Voters, Applied and Reads answer opStanding.
	Voters  []string `json:"voters,omitempty"`
	Applied uint64   `json:"applied,omitempty"`
	Reads   uint32   `json:"reads,omitempty"`
	// Term and Stuck answer opStanding.
	Term  uint64 `json:"term,omitempty"`
	Stuck string `json:"stuck,omitempty"`
	// Result is what the state machine made of a forwarded write.
	Result json.RawMessage `json:"result,omitempty"`
	// Delivered is what the cluster made of a decree another replica took.
	Delivered *Delivered `json:"delivered,omitempty"`
}

// answerControl answers one control request from an admitted peer.
func (n *Node) answerControl(from peer, request controlRequest) controlAnswer {
	answer := controlAnswer{
		Member: string(n.member),
		Joined: n.fsm.ClusterState().Joined(),
	}
	switch request.Op {
	case opMember:
		return answer
	case opJoin:
		return n.answerJoin(from, request.Policy, answer)
	case opWrite:
		return n.answerWrite(request.Entry, answer)
	case opDecree:
		return n.answerDecree(request.Decree, answer)
	case opRead:
		return n.answerRead(answer)
	case opStanding:
		return n.answerStanding(answer)
	}
	answer.Err = fmt.Sprintf("unknown control op %q", request.Op)
	return answer
}

// leading reports this replica as the one that appends to the cluster's log.
func (n *Node) leading() bool {
	return n.raft.State() == raft.Leader
}

// redirectToLeader refuses a request only the cluster's leader answers,
// naming the member leading so the caller can ask it instead.
func (n *Node) redirectToLeader(answer controlAnswer) controlAnswer {
	_, leader := n.raft.LeaderWithID()
	answer.Leader = string(leader)
	answer.Err = "this replica does not lead the cluster"
	return answer
}
