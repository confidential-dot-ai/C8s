// Genesis: the one process the operator decreed starts the cluster.
//
// A cluster begins as a one-voter group holding nothing, and everything it is
// then comes from the first entry on its log: the operator's Genesis decree,
// which names the process that may start it, the mesh CA that process minted
// and the image sets the cluster accepts. The process acts on it only while
// it can see the replicas of its cluster and none of them holds one, so a
// host that hides the others does not get a second cluster beside them.

package cdsha

import (
	"errors"
	"log/slog"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// bootstrapElections is how many election timeouts the replica that started a
// group waits to lead it. A group of one elects itself in the first; the rest
// is slack for a process whose scheduler is busy.
const bootstrapElections = 10

// GenesisCA is the fingerprint of the mesh CA this process installs if a
// Genesis decree names it. A replica that holds a cluster offers none.
func (n *Node) GenesisCA() (string, error) {
	if n.fsm.ClusterState().Joined() {
		return "", nil
	}
	ca, err := n.genesisCA()
	if err != nil {
		return "", err
	}
	return certutil.CertFingerprint(ca.Cert.Raw), nil
}

// mintMeshCA mints the mesh CA of a cluster this process may start. The
// operator signs its fingerprint into the Genesis decree, so a replica
// replaying that decree cannot install a CA of its own.
func mintMeshCA() (*issuer.CA, error) {
	mesh, err := issuer.NewMeshCA(issuer.DefaultCACommonName, issuer.DefaultCAValidity)
	if err != nil {
		return nil, err
	}
	return mesh.Current().CA, nil
}

// decreedGenesis is the Genesis decree the operator posted to this process.
func (n *Node) decreedGenesis() (cdsdecree.Signed, bool) {
	for _, signed := range n.posted.all() {
		if signed.Decree.Kind == cdsdecree.Genesis {
			return signed, true
		}
	}
	return cdsdecree.Signed{}, false
}

// startable refuses a Genesis this replica must not act on: one where it
// could not resolve every replica of its cluster, and one where no other
// replica answered. Neither establishes that no cluster exists, and the host
// produces both at will. The operator signs an alone decree for the cluster
// whose replica set holds no other replica to answer.
func (n *Node) startable(alone bool, found discovered, answers peerAnswers) error {
	switch {
	case alone:
		return nil
	case !found.complete:
		return errors.New("discovery did not resolve every replica of this cluster")
	case !answers.answered:
		return errors.New("no other replica of this cluster answered")
	}
	return nil
}

// startCluster makes this replica the one voter of a group with no log and
// commits the Genesis decree on it. A decree that did not commit is committed
// by the next tick, on the group this replica already started.
func (n *Node) startCluster(signed cdsdecree.Signed) {
	if n.ClockError() != nil {
		return
	}
	entry, err := n.genesisEntry(signed)
	if err != nil {
		slog.Error("cds-ha: this replica could not write the entry that starts its cluster", "error", err)
		return
	}
	slog.Info("cds-ha: this replica starts its cluster", "member", n.member, "intent", signed.Decree.IntentID)
	if err := n.bootstrapSolo(); err != nil {
		slog.Warn("cds-ha: this replica could not start the one-voter group its cluster begins as", "error", err)
		return
	}
	if !await(bootstrapElections*n.cfg.Timing.Election, n.leading) {
		slog.Warn("cds-ha: this replica started a group of its own and does not lead it")
		return
	}
	genesis := Entry{
		Kind:   KindDecree,
		Decree: entry,
	}
	switch res, err := n.propose(genesis); {
	case err != nil:
		slog.Error("cds-ha: the Genesis decree did not commit", "error", err)
	case res.Decree != nil && res.Decree.Refused != "":
		slog.Error("cds-ha: the Genesis decree was refused", "refused", res.Decree.Refused)
	}
}

// bootstrapSolo makes this replica the one voter of a group with no log,
// unless it is in one already.
func (n *Node) bootstrapSolo() error {
	if n.inConfiguration() {
		return nil
	}
	return n.enqueueMutation(func() raft.Future { return n.raft.BootstrapCluster(n.solo()) })
}

// solo is the group a cluster begins as: this replica as its only voter.
func (n *Node) solo() raft.Configuration {
	return raft.Configuration{Servers: []raft.Server{{
		Suffrage: raft.Voter,
		ID:       raft.ServerID(n.member),
		Address:  n.mux.advert.serverAddress(),
	}}}
}

// genesisEntry is the entry that starts the cluster.
func (n *Node) genesisEntry(signed cdsdecree.Signed) (*DecreeEntry, error) {
	ca, err := n.genesisCA()
	if err != nil {
		return nil, err
	}
	cert, key, err := caEntryBytes(ca)
	if err != nil {
		return nil, err
	}
	return &DecreeEntry{
		Decree:     signed,
		AtMS:       time.Now().UnixMilli(),
		Policy:     n.fsm.LocalPolicy(),
		MeshCACert: cert,
		MeshCAKey:  key,
	}, nil
}
