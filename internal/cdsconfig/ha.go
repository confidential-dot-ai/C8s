// The ha block runs CDS as a replica set instead of a singleton. Three of the
// document's fields bootstrap the replicated log and then follow it: `nodes`,
// `workloads` and `ha.voters` seed the node images, the allowlist and the
// voter count at Genesis, and signed commands change them while the cluster
// lives. Every other field fixes the cluster for its life, because every
// replica boots one document and clients pin it.

package cdsconfig

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// HA is the replica set one cluster's CDS runs as.
type HA struct {
	// Replicas are the DNS names and IPv4 addresses discovery resolves to the
	// replicas' own addresses, never to a load-balanced address; one name may
	// resolve to several replicas.
	Replicas []string
	// Voters seeds the voter count at Genesis.
	Voters int
}

// haWire mirrors the document's ha block.
type haWire struct {
	Replicas []string `yaml:"replicas"`
	Voters   int      `yaml:"voters"`
}

// parse reads the block; a document without one runs the singleton CDS.
func (w *haWire) parse() (*HA, error) {
	if w == nil {
		return nil, nil
	}
	replicas, err := parseReplicas(w.Replicas)
	if err != nil {
		return nil, err
	}
	if err := checkVoters(w.Voters); err != nil {
		return nil, err
	}
	return &HA{
		Replicas: replicas,
		Voters:   w.Voters,
	}, nil
}

// wire renders the block; a document naming no replica set renders no ha
// block at all, and Parse reads that document back as the singleton CDS.
func (h HA) wire() *haWire {
	if h.namesNoReplicaSet() {
		return nil
	}
	return &haWire{
		Replicas: h.Replicas,
		Voters:   h.Voters,
	}
}

func (h HA) namesNoReplicaSet() bool {
	return len(h.Replicas) == 0 && h.Voters == 0
}

func parseReplicas(entries []string) ([]string, error) {
	if len(entries) == 0 {
		return nil, errors.New("ha.replicas must name at least one replica")
	}
	for i, entry := range entries {
		if err := checkReplica(entry); err != nil {
			return nil, fmt.Errorf("ha.replicas: %w", err)
		}
		if slices.Contains(entries[:i], entry) {
			return nil, fmt.Errorf("ha.replicas names %q twice", entry)
		}
	}
	return entries, nil
}

// checkReplica accepts one DNS name or IPv4 address; the replicas listen on
// one fixed port, which no entry restates.
func checkReplica(entry string) error {
	if address, err := netip.ParseAddr(entry); err == nil {
		if address.Is4() {
			return nil
		}
		return fmt.Errorf("%q must be a DNS name or an IPv4 address", entry)
	}
	if strings.Contains(entry, ":") {
		return fmt.Errorf("%q must not carry a port", entry)
	}
	return cmdsutil.ValidateDNSName(entry)
}

func checkVoters(voters int) error {
	if err := cdsdecree.CheckVoterSeats(voters); err != nil {
		return fmt.Errorf("ha.voters: %w", err)
	}
	return nil
}
