package cmdsutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// NodePins is a credential client's CDS pin set read from the policy the
// node's enforcer mounts (workloadclaims.CDSPinsPath). The enforcer rewrites
// that file in place when the operator's signed pin decree moves CDS to a new
// image; Refresh re-reads it, so a long-lived client (get-cert's renewal
// loop) follows a CDS rollout without a pod restart. A file read halfway
// through a rewrite does not parse, and leaves the set unchanged.
type NodePins struct {
	path string

	mu  sync.Mutex
	raw []byte
	cur refvalues.ReferenceValues
	gen uint64
}

// NewNodePins reads the node's policy at path.
func NewNodePins(path string) (*NodePins, error) {
	n := &NodePins{path: path}
	if _, err := n.Refresh(context.Background()); err != nil {
		return nil, err
	}
	return n, nil
}

// Current is the set read last.
func (n *NodePins) Current() refvalues.ReferenceValues {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cur
}

// Generation changes with Current.
func (n *NodePins) Generation() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.gen
}

// Refresh re-reads the file and reports whether the set changed.
func (n *NodePins) Refresh(context.Context) (bool, error) {
	data, err := os.ReadFile(n.path)
	if err != nil {
		return false, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.gen > 0 && bytes.Equal(data, n.raw) {
		return false, nil
	}
	set, err := refvalues.Parse(data)
	if err != nil {
		return false, fmt.Errorf("%s: %w", n.path, err)
	}
	n.raw, n.cur = data, set
	n.gen++
	return n.gen > 1, nil
}

// FollowNodePins is NewNodePins where the node mounts its CDS policy at
// path, and nil, nil where it mounts none. A stat error other than absent
// fails.
func FollowNodePins(path string) (*NodePins, error) {
	if mounted, err := nodeProvides(path); !mounted || err != nil {
		return nil, err
	}
	return NewNodePins(path)
}
