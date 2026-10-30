// The replica control channel: one request and one answer per exchange, over
// the attested connection the member map holds open to each member it knows.
//
// A request carries no member id of its own. The handshake attested the
// member asking, and its answer names the member answering, so neither side
// acts on a claim the other makes about who it is.

package cdsha

import (
	"fmt"
	"time"
)

// controlTimeout bounds one exchange on the channel.
const controlTimeout = 5 * time.Second

type controlOp string

// opMember is how a replica learns where a member is and that it is still
// there.
const opMember controlOp = "member"

type controlRequest struct {
	Op controlOp `json:"op"`
}

type controlAnswer struct {
	// Member is the member that answered.
	Member string `json:"member"`
	// Err is why the request was refused.
	Err string `json:"err,omitempty"`
}

// answerControl answers one control request from an admitted peer.
func (n *Node) answerControl(_ peer, request controlRequest) controlAnswer {
	answer := controlAnswer{Member: string(n.member)}
	if request.Op != opMember {
		answer.Err = fmt.Sprintf("unknown control op %q", request.Op)
	}
	return answer
}
