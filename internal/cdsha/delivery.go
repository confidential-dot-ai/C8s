// The decrees the operator posts to this replica: a decree reaches the
// cluster over the attested channel the replicas already answer their clients
// on, and the operator's signature over everything it says is its authority,
// so the channel only has to reach a replica of this cluster.
//
// A replica holds the decrees it acts on itself until it acts on them.

package cdsha

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
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
	// Version is the cluster version a decree the leader applied produced.
	Version uint64 `json:"applied_version,omitempty"`
	// Refused is why the cluster would not apply the decree.
	Refused string `json:"refused,omitempty"`
}

// TakeDecree takes one decree the operator posted to this replica.
func (n *Node) TakeDecree(signed cdsdecree.Signed) (Delivered, error) {
	if err := n.ClockError(); err != nil {
		return Delivered{}, err
	}
	if err := n.operatorSigned(signed); err != nil {
		return Delivered{}, err
	}
	if actedOnByItsTarget(signed.Decree.Kind) {
		return n.holdDecree(signed)
	}
	return n.applyThroughTheLeader(signed)
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
	n.clockMu.Lock()
	defer n.clockMu.Unlock()
	if n.clockFault != nil {
		return Delivered{}, n.clockFault
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

// admitAsDecreed sets the images this replica admits beside its own to the ones
// an Admit decree posted to it names, and none while it holds no such decree.
func (n *Node) admitAsDecreed() {
	images := n.anyAdmitForThisProcess()
	n.clockMu.Lock()
	defer n.clockMu.Unlock()
	if n.clockFault != nil {
		return
	}
	n.decreedImages.Store(images)
}

// anyAdmitForThisProcess is the images of an Admit decree this replica holds.
// Every decree it holds names the member id this process minted, so the newest
// Admit of them serves.
func (n *Node) anyAdmitForThisProcess() *[]remote.ImagePin {
	held := n.posted.all()
	for _, signed := range slices.Backward(held) {
		if signed.Decree.Kind != cdsdecree.Admit {
			continue
		}
		images, err := n.imagesOfAdmit(signed)
		if err != nil {
			if n.admitLog.changed(err.Error()) {
				slog.Warn("cds-ha: an Admit decree names this replica and it admits no image by it", "error", err)
			}
			continue
		}
		return &images
	}
	return nil
}

// imagesOfAdmit is the image set an Admit decree hands this replica: inside
// its expiry, and pinned to the launch file this replica booted.
func (n *Node) imagesOfAdmit(signed cdsdecree.Signed) ([]remote.ImagePin, error) {
	if expired(signed.Decree, time.Now().UnixMilli()) {
		return nil, errors.New("the Admit decree has expired")
	}
	images, err := signed.Decree.CDSPins.WithLaunchFile(n.cfg.LaunchFile)
	if err != nil {
		return nil, err
	}
	return images.Images, nil
}
