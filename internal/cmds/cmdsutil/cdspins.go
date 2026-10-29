package cmdsutil

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// NodePins is a credential client's CDS pin set read from the policy the
// node's enforcer mounts (workloadclaims.CDSPinsPath). The enforcer rewrites
// that file in place when the operator's signed pin decree moves CDS to a new
// image; Refresh re-reads it, so a long-lived client (get-cert's renewal
// loop) follows a CDS rollout without a pod restart. A file read halfway
// through a rewrite does not parse, and leaves the set unchanged.
//
// Generation also re-reads the file once nodePinsRecheck has passed since the
// last read, so a client whose requests keep succeeding still drops a CDS
// image the operator removed: the refreshing transport rebuilds on the new
// generation and never reuses a connection made under the old set.
type NodePins struct {
	path string

	mu   sync.Mutex
	raw  []byte
	cur  refvalues.ReferenceValues
	gen  uint64
	read time.Time
}

// nodePinsRecheck bounds how long a client keeps using a CDS that the
// enforcer's rewritten policy no longer pins (a var so tests can shorten it).
var nodePinsRecheck = 5 * time.Second

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

// Generation changes with Current. It re-reads the file when the last read
// is older than nodePinsRecheck; a read that fails keeps the set.
func (n *NodePins) Generation() uint64 {
	n.mu.Lock()
	stale := time.Since(n.read) >= nodePinsRecheck
	n.mu.Unlock()
	if stale {
		_, _ = n.Refresh(context.Background())
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.gen
}

// Refresh re-reads the file and reports whether the set changed.
func (n *NodePins) Refresh(context.Context) (bool, error) {
	n.mu.Lock()
	n.read = time.Now()
	n.mu.Unlock()
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
