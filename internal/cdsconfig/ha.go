// The ha block runs CDS as a replica set instead of a singleton. Three of the
// document's fields bootstrap the replicated log and then follow it: `nodes`,
// `workloads` and `ha.voters` seed the node images, the allowlist and the
// voter count at Genesis, and signed commands change them while the cluster
// lives. Every other field fixes the cluster for its life, because every
// replica boots one document and clients pin it.

package cdsconfig

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
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
	// Board is the untrusted object store the operator may leave decrees in
	// beside posting them; a zero one is a cluster with no board.
	Board Board
	// RecoveryKey seals the backups; its private half stays with the operator,
	// offline.
	RecoveryKey *ecdsa.PublicKey
}

// haWire mirrors the document's ha block.
type haWire struct {
	Replicas    []string  `yaml:"replicas"`
	Voters      int       `yaml:"voters"`
	Board       boardWire `yaml:"board"`
	RecoveryKey string    `yaml:"recoveryKey,omitempty"`
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
	board, err := w.Board.parse()
	if err != nil {
		return nil, err
	}
	recoveryKey, err := parseRecoveryKey(w.RecoveryKey, board)
	if err != nil {
		return nil, err
	}
	return &HA{
		Replicas:    replicas,
		Voters:      w.Voters,
		Board:       board,
		RecoveryKey: recoveryKey,
	}, nil
}

// wire renders the block; a document naming no replica set renders no ha
// block at all, and Parse reads that document back as the singleton CDS.
func (h HA) wire() (*haWire, error) {
	if h.namesNoReplicaSet() {
		return nil, nil
	}
	recoveryKey, err := recoveryKeyPEM(h.RecoveryKey)
	if err != nil {
		return nil, fmt.Errorf("ha.recoveryKey: %w", err)
	}
	return &haWire{
		Replicas:    h.Replicas,
		Voters:      h.Voters,
		Board:       h.Board.wire(),
		RecoveryKey: recoveryKey,
	}, nil
}

// namesNoReplicaSet reports the ha block of a cluster whose CDS is the
// singleton: the operator named no replica, no voter seat, no board and no
// key to seal a backup to.
func (h HA) namesNoReplicaSet() bool {
	return len(h.Replicas) == 0 && h.Voters == 0 && !h.Board.Names() && h.RecoveryKey == nil
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

// parseRecoveryKey is the key this cluster's backups seal to, and none where
// the block names none. A key needs a board: a backup is one object the
// leader appends there, and a cluster with nowhere to put one seals nothing.
func parseRecoveryKey(pemBytes string, board Board) (*ecdsa.PublicKey, error) {
	if pemBytes == "" {
		return nil, nil
	}
	if !board.Names() {
		return nil, errors.New("ha.recoveryKey: a cluster seals its backups to this key and appends them to ha.board, which this document names none")
	}
	key, err := RecoveryKey([]byte(pemBytes))
	if err != nil {
		return nil, fmt.Errorf("ha.recoveryKey: %w", err)
	}
	return key, nil
}

// RecoveryKey is the key a cluster's backups seal to, as a PEM file carries
// it: the public half of a P-256 key, whose private half stays with the
// operator, offline. The caller names where the bytes came from.
func RecoveryKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	return runtimemeasure.ParsePublicKeyPEM(pemBytes)
}

// recoveryKeyPEM is the key a document names its backups' recipient by, and
// nothing for a replica set that seals no backup.
func recoveryKeyPEM(key *ecdsa.PublicKey) (string, error) {
	if key == nil {
		return "", nil
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})), nil
}
