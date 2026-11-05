package cmdsutil

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// NodePins is a client's CDS pin set as the node's enforcer mounts it. The
// enforcer rewrites that file in place as the cluster's pin decrees move CDS
// to another image. A file read mid-rewrite does not parse, and leaves the
// set in force.
type NodePins struct {
	path string

	mu         sync.Mutex
	document   []byte
	current    refvalues.ReferenceValues
	generation uint64
}

// nodePinsRecheck bounds how long a client holds a set the enforcer rewrote.
const nodePinsRecheck = 5 * time.Second

// FollowNodePins is the policy at path as a pin source, re-read while ctx
// runs, and nil where the node mounts none. A path that exists but cannot be
// read is a broken mount, not an absent one, and fails.
func FollowNodePins(ctx context.Context, path string) (*NodePins, error) {
	pins := &NodePins{path: path}
	switch err := pins.Refresh(); {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	go pins.reread(ctx, nodePinsRecheck)
	return pins, nil
}

// Current is the set read last.
func (n *NodePins) Current() refvalues.ReferenceValues {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.current
}

// Generation changes with Current.
func (n *NodePins) Generation() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.generation
}

func (n *NodePins) Refresh() error {
	data, err := os.ReadFile(n.path)
	if err != nil {
		return fmt.Errorf("node policy %s: %w", n.path, err)
	}
	set, err := refvalues.Parse(data)
	if err != nil {
		return fmt.Errorf("node policy %s: %w", n.path, err)
	}
	if _, err := CDSLaunchFile(set); err != nil {
		return fmt.Errorf("node policy %s %w", n.path, err)
	}
	document, err := refvalues.Format(set)
	if err != nil {
		return fmt.Errorf("node policy %s: %w", n.path, err)
	}
	n.take(document, set)
	return nil
}

// reread drops a retired CDS image without waiting for a pin miss, which a
// client whose own requests keep succeeding never has.
func (n *NodePins) reread(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = n.Refresh()
		}
	}
}

// take moves the generation only where the document says something else.
func (n *NodePins) take(document []byte, set refvalues.ReferenceValues) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if bytes.Equal(document, n.document) {
		return
	}
	n.document = document
	n.current = set
	n.generation++
}

var _ armtls.PinSource = (*NodePins)(nil)
