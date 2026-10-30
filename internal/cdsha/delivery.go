// The decrees the operator posts to this replica: a decree reaches the
// cluster over the attested channel the replicas already answer their clients
// on, and the operator's signature over everything it says is its authority,
// so the channel only has to reach a replica of this cluster.
//
// A replica holds the decrees it acts on itself until it acts on them.

package cdsha

import (
	"fmt"
	"slices"
	"sync"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
)

// maxPostedDecrees is how many decrees a replica holds. Every one of them is
// the operator's, naming this process, and the newest of an intent replaces
// the one it repeats.
const maxPostedDecrees = 16

// Delivered is what a replica made of one posted decree.
type Delivered struct {
	// Intent names the decree.
	Intent string `json:"intent"`
	// Held reports a decree this replica keeps until it acts on it itself.
	Held bool `json:"held,omitempty"`
}

// TakeDecree takes one decree the operator posted to this replica.
func (n *Node) TakeDecree(signed cdsdecree.Signed) (Delivered, error) {
	if err := n.operatorSigned(signed); err != nil {
		return Delivered{}, err
	}
	if !actedOnByItsTarget(signed.Decree.Kind) {
		return Delivered{}, fmt.Errorf("cds-ha: a %s decree is not one a replica acts on by itself", signed.Decree.Kind)
	}
	return n.holdDecree(signed)
}

// operatorSigned reports a decree a key of this cluster's operator signed,
// with everything about it that needs no cluster state.
func (n *Node) operatorSigned(signed cdsdecree.Signed) error {
	return cdsdecree.Verify(signed, n.cfg.Launch.OperatorKeys, n.cfg.Launch.ClusterID)
}

// actedOnByItsTarget names the decree kinds the replica they name acts on.
func actedOnByItsTarget(kind cdsdecree.Kind) bool {
	switch kind {
	case cdsdecree.Genesis,
		cdsdecree.Recover,
		cdsdecree.Admit:
		return true
	}
	return false
}

// holdDecree keeps a decree until this replica acts on it. A decree of these
// kinds is bound to the member id this process minted at its start, so
// neither another replica nor a restart of this one acts on it.
func (n *Node) holdDecree(signed cdsdecree.Signed) (Delivered, error) {
	if signed.Decree.TargetMember != string(n.member) {
		return Delivered{}, fmt.Errorf("cds-ha: the decree names member %q, and this replica is member %q", signed.Decree.TargetMember, n.member)
	}
	n.posted.hold(signed)
	return Delivered{
		Intent: signed.Decree.IntentID,
		Held:   true,
	}, nil
}

// postedDecrees are the decrees a replica holds, oldest first.
type postedDecrees struct {
	mu   sync.Mutex
	held []cdsdecree.Signed
}

// hold takes one decree in, in place of the one it repeats, and drops the
// oldest where the replica holds as many as it keeps.
func (p *postedDecrees) hold(signed cdsdecree.Signed) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.held = slices.DeleteFunc(p.held, func(other cdsdecree.Signed) bool {
		return other.Decree.IntentID == signed.Decree.IntentID
	})
	p.held = append(p.held, signed)
	if len(p.held) > maxPostedDecrees {
		p.held = p.held[1:]
	}
}

func (p *postedDecrees) all() []cdsdecree.Signed {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.held)
}
