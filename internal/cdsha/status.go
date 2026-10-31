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
	// that may answer a read under a lease. Only the leader answers RollSafe.
	Joined   bool        `json:"joined"`
	Serving  Serving     `json:"serving"`
	RollSafe *RollSafety `json:"roll_safe,omitempty"`
	// Version counts the operator commands the cluster has applied, and
	// NodeImagesVersion names the one that last replaced the node image set.
	Version           uint64   `json:"version"`
	NodeImagesVersion uint64   `json:"node_images_version"`
	State             string   `json:"state,omitempty"`
	Term              uint64   `json:"term,omitempty"`
	Leader            string   `json:"leader,omitempty"`
	AppliedIndex      uint64   `json:"applied_index"`
	Voters            []string `json:"voters,omitempty"`
	NonVoters         []string `json:"non_voters,omitempty"`
	CAFingerprint     string   `json:"ca_fingerprint,omitempty"`
	// GenesisCA is the mesh CA a Genesis decree for this replica carries.
	GenesisCA string `json:"genesis_ca,omitempty"`
	// Stuck is why this replica stopped applying the log, and Fenced why it
	// serves nothing while it follows the log (fence.go).
	Stuck  string `json:"stuck,omitempty"`
	Fenced *Fence `json:"fenced,omitempty"`
	// Checkpoint is the newest state digest this replica recorded, and
	// Divergence what this leader made of its members' reports
	// (divergence.go).
	Checkpoint Point  `json:"checkpoint,omitzero"`
	Divergence string `json:"divergence,omitempty"`
	// LastBackup is the backup the cluster's leader appended to its board,
	// and BackupError why its backups are failing. The leader backs the
	// cluster up, and no other replica answers for the backups
	// (backupduty.go).
	LastBackup  *StoredBackup `json:"last_backup,omitempty"`
	BackupError string        `json:"backup_error,omitempty"`
}

// Status reports this replica, with no place in Raft until it starts.
func (n *Node) Status() Status {
	core := n.fsm.ClusterState()
	status := Status{
		ClusterID:         core.ClusterID,
		ID:                string(n.member),
		Joined:            core.Joined(),
		Version:           core.Version,
		NodeImagesVersion: core.NodeImagesVersion,
		AppliedIndex:      n.fsm.AppliedIndex(),
		Stuck:             n.fsm.Stuck(),
	}
	if core.Joined() {
		status.CAFingerprint = certutil.CertFingerprint(core.MeshCACert)
	}
	genesisCA, err := n.GenesisCA()
	if err != nil {
		slog.Error("cds-ha: this replica could not mint the mesh CA a Genesis decree would name", "error", err)
	}
	status.GenesisCA = genesisCA
	if n.raft.Load() == nil {
		return status
	}
	return n.inRaft(status)
}

func (n *Node) inRaft(status Status) Status {
	status.Serving = n.Serving()
	status.Fenced = n.Fenced()
	if safe, leading := n.RollSafe(); leading {
		status.RollSafe = &safe
	}
	status.Checkpoint = n.fsm.dig.lastCheckpoint()
	if n.leading() {
		status.Divergence = n.div.status()
		status.LastBackup, status.BackupError = n.backups.reported()
	}
	status.State = n.raft.Load().State().String()
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
	if !n.Serving().OK {
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
