// A replica's own report of the cluster it serves. It is this replica's word
// alone, so an operator reads every replica and compares them.

package cdsha

import (
	"log/slog"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

type Status struct {
	ClusterID string `json:"cluster_id"`
	// ID is the member id this process minted at its start, which a decree names.
	ID string `json:"id"`
	// Joined reports a replica holding the cluster's mesh CA, and Serving one
	// that may answer a read under a lease.
	Joined  bool `json:"joined"`
	Serving bool `json:"serving"`
	// Version counts the operator commands the cluster has applied.
	Version       uint64   `json:"version"`
	State         string   `json:"state,omitempty"`
	Term          uint64   `json:"term,omitempty"`
	Leader        string   `json:"leader,omitempty"`
	AppliedIndex  uint64   `json:"applied_index"`
	Voters        []string `json:"voters,omitempty"`
	NonVoters     []string `json:"non_voters,omitempty"`
	CAFingerprint string   `json:"ca_fingerprint,omitempty"`
	// GenesisCA is the mesh CA a Genesis decree for this replica carries.
	GenesisCA string `json:"genesis_ca,omitempty"`
	// Stuck is why this replica stopped applying the log.
	Stuck string `json:"stuck,omitempty"`
}

// Status reports this replica, with no place in Raft until it starts.
func (n *Node) Status() Status {
	core := n.fsm.ClusterState()
	status := Status{
		ClusterID:    core.ClusterID,
		ID:           string(n.member),
		Joined:       core.Joined(),
		Version:      core.Version,
		AppliedIndex: n.fsm.AppliedIndex(),
		Stuck:        n.fsm.Stuck(),
	}
	if core.Joined() {
		status.CAFingerprint = certutil.CertFingerprint(core.MeshCACert)
	}
	genesisCA, err := n.GenesisCA()
	if err != nil {
		slog.Error("cds-ha: this replica could not mint the mesh CA a Genesis decree would name", "error", err)
	}
	status.GenesisCA = genesisCA
	if n.raft == nil {
		return status
	}
	return n.inRaft(status)
}

func (n *Node) inRaft(status Status) Status {
	status.Serving = n.Serving()
	status.State = n.raft.State().String()
	followed := n.following()
	status.Term = followed.term
	status.Leader = string(followed.member)
	for _, server := range n.configuration() {
		if server.Suffrage == raft.Voter {
			status.Voters = append(status.Voters, string(server.ID))
			continue
		}
		status.NonVoters = append(status.NonVoters, string(server.ID))
	}
	return status
}

// CA is none while this replica does not serve its cluster: a cached CA must
// not stand in for the one it would issue under.
func (n *Node) CA() (*issuer.CA, bool) {
	if !n.Serving() {
		return nil, false
	}
	ca := n.fsm.CA()
	return ca, ca != nil
}

func (n *Node) ClusterState() ClusterState {
	return n.fsm.ClusterState()
}

// Decrees lists the decrees the cluster applied, oldest first.
func (n *Node) Decrees() []DecreeRecord {
	return n.fsm.Decrees()
}
