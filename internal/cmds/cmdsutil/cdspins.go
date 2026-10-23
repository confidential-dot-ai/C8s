package cmdsutil

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
)

// CDSDecreesInfo is what the node's enforcer needs to follow the operator's
// signed CDS pin decrees: the cluster and the decree key, from the launch
// document. Nodes of an HA cluster publish it as
// /run/c8s-node/cds-decrees.json; it is public.
type CDSDecreesInfo struct {
	ClusterID string `json:"cluster_id"`
	DecreeKey string `json:"decree_key"` // PEM public key
	// PinFloor is the lowest decree base epoch the node accepts (from its
	// launch document): an older decree the operator also signed is refused.
	PinFloor uint64 `json:"pin_floor,omitempty"`
}

// LoadCDSDecreesInfo reads the node's decree info; ok is false when the
// node publishes none (a cluster without HA CDS).
func LoadCDSDecreesInfo(path string) (info CDSDecreesInfo, ok bool, err error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return info, false, nil
	}
	if err != nil {
		return info, false, err
	}
	if err := json.Unmarshal(data, &info); err != nil {
		return info, false, fmt.Errorf("%s: %w", path, err)
	}
	if info.ClusterID == "" || info.DecreeKey == "" {
		return info, false, fmt.Errorf("%s: needs cluster_id and decree_key", path)
	}
	return info, true, nil
}

// decreeKeyDER accepts a PEM ECDSA public key and returns its PKIX DER.
func decreeKeyDER(s string) ([]byte, error) {
	b, _ := pem.Decode([]byte(strings.TrimSpace(s)))
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("decree key must be a PEM PUBLIC KEY")
	}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decree key: %w", err)
	}
	if _, ok := k.(*ecdsa.PublicKey); !ok {
		return nil, errors.New("decree key is not an ECDSA key")
	}
	return b.Bytes, nil
}

// CDSDecreeSource follows the operator's signed CDS pin decrees from the
// bootstrap set (the node's launch-document CDS policy), fetching them from
// cdsURL (GET /ha/pins). state, if set, keeps the newest decree across
// restarts.
func CDSDecreeSource(info CDSDecreesInfo, bootstrap refvalues.ReferenceValues, cdsURL, state string) (*cdspins.Source, error) {
	der, err := decreeKeyDER(info.DecreeKey)
	if err != nil {
		return nil, err
	}
	return cdspins.New(cdspins.Config{ClusterID: info.ClusterID, DecreeKey: der, Bootstrap: bootstrap,
		Fetch: cdspins.HTTPFetch(strings.TrimRight(cdsURL, "/")), StateFile: state, MinEpoch: info.PinFloor})
}

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
