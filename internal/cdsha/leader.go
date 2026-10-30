// The duties of the cluster's leader: it applies the operator's decrees, renews
// the mesh CA certificate under the cluster's key, and bounds the allowlist
// history. Each of them appends to the log, which only the leader does. Its
// duty over the voter seats runs on a loop of its own (seats.go).

package cdsha

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// keepCluster runs the leader's duties until ctx ends. Each duty answers for
// itself whether this replica leads, since leadership can change between two
// of them.
func (n *Node) keepCluster(ctx context.Context) {
	tick := time.NewTicker(n.cfg.Timing.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		n.renewMeshCA()
		n.pruneHistory()
	}
}

// applyThroughTheLeader puts a decree the operator posted on the cluster's
// log: this replica where it leads, and the leader it follows otherwise.
func (n *Node) applyThroughTheLeader(signed cdsdecree.Signed) (Delivered, error) {
	if !n.leading() {
		return n.forwardDecree(signed)
	}
	return n.applyDecree(signed)
}

func (n *Node) applyDecree(signed cdsdecree.Signed) (Delivered, error) {
	intent := signed.Decree.IntentID
	if err := n.refuses(signed.Decree); err != nil {
		slog.Info("cds-ha: this leader refused a decree of its operator", "intent", intent, "error", err)
		return Delivered{Intent: intent, Refused: err.Error()}, nil
	}
	entry, err := n.decreeEntry(signed)
	if err != nil {
		return Delivered{}, fmt.Errorf("cds-ha: this leader could not write the entry a decree applies through: %w", err)
	}
	res, err := n.propose(Entry{Kind: KindDecree, Decree: entry})
	switch {
	case err != nil:
		return Delivered{}, fmt.Errorf("cds-ha: a decree of this cluster's operator did not commit: %w", err)
	case res.Decree == nil:
		return Delivered{}, errors.New("cds-ha: the state machine answered a decree with no result of one")
	case res.Decree.Refused != "":
		slog.Info("cds-ha: this cluster refused a decree of its operator", "intent", intent, "refused", res.Decree.Refused)
		return Delivered{Intent: intent, Refused: res.Decree.Refused}, nil
	}
	slog.Info("cds-ha: this cluster applied a decree of its operator", "audit", true,
		"intent", intent, "kind", signed.Decree.Kind, "version", res.Decree.Version)
	return Delivered{Intent: intent, Version: res.Decree.Version}, nil
}

// refuses is why this leader does not put a decree on the log: a pin set that
// would leave the cluster without a majority of voters to lead it. Everything
// else a decree must satisfy is the state machine's to judge.
func (n *Node) refuses(d cdsdecree.Decree) error {
	if d.Kind != cdsdecree.UpdateMeasurements {
		return nil
	}
	images, err := d.CDSPins.WithLaunchFile(n.cfg.LaunchFile)
	if err != nil {
		return err
	}
	return n.keepsVoterMajority(images.Images)
}

// keepsVoterMajority refuses an image set a majority of the cluster's voters
// are not known to run: peers admit each other by that set, so it would leave
// the cluster without a leader, and with no leader no later decree can take it
// back.
func (n *Node) keepsVoterMajority(images []remote.ImagePin) error {
	voters := 0
	running := 0
	for _, server := range n.configuration() {
		if server.Suffrage != raft.Voter {
			continue
		}
		voters++
		if n.voterKnownToRun(string(server.ID), images) {
			running++
		}
	}
	if !moreThanHalf(running, voters) {
		return fmt.Errorf("%d of %d voters are known to run an image the set pins; pin the new image beside the running one first", running, voters)
	}
	return nil
}

func moreThanHalf(some, all int) bool {
	return some*2 > all
}

// voterKnownToRun judges a voter on the verdict its evidence earned: one whose
// verdict this replica does not hold runs no image any set pins.
func (n *Node) voterKnownToRun(member string, images []remote.ImagePin) bool {
	attested, known := n.attestedVoter(member)
	return known && attested.runs(images)
}

// attestedVoter is this replica's own verdict where member names it, and the
// verdict the voter's connection was admitted on otherwise.
func (n *Node) attestedVoter(member string) (verdict, bool) {
	if member == string(n.member) {
		return n.identity.Load().attested, true
	}
	held, reached := n.peers.knownAt(member)
	if !reached {
		return verdict{}, false
	}
	return held.control.attested(), true
}

// decreeEntry stamps the decree with the cluster's clock, and mints a mesh CA
// for the kind that forks the mesh.
func (n *Node) decreeEntry(signed cdsdecree.Signed) (*DecreeEntry, error) {
	entry := &DecreeEntry{Decree: signed, AtMS: time.Now().UnixMilli()}
	if signed.Decree.Kind != cdsdecree.RotateKey {
		return entry, nil
	}
	ca, err := mintMeshCA()
	if err != nil {
		return nil, err
	}
	cert, key, err := caEntryBytes(ca)
	if err != nil {
		return nil, err
	}
	entry.MeshCACert = cert
	entry.MeshCAKey = key
	return entry, nil
}

// renewMeshCA renews the cluster's mesh CA certificate through the log, under
// the key the cluster holds, so the leaves issued under it keep their anchor.
func (n *Node) renewMeshCA() {
	if !n.leading() {
		return
	}
	ca := n.fsm.CA()
	if ca == nil || !pastHalfLife(ca.Cert, time.Now()) {
		return
	}
	renewed, err := renewedMeshCert(ca)
	if err != nil {
		slog.Error("cds-ha: this leader could not sign the cluster's mesh CA certificate again", "error", err)
		return
	}
	if _, err := n.propose(Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{MeshCACert: renewed}}); err != nil {
		slog.Warn("cds-ha: the renewed mesh CA certificate did not commit", "error", err)
	}
}

// pastHalfLife leaves the cluster the other half of a life to renew it in.
func pastHalfLife(cert *x509.Certificate, now time.Time) bool {
	return now.After(cert.NotBefore.Add(lifetimeOf(cert) / 2))
}

// renewedMeshCert signs the cluster's mesh CA key again, for the lifetime of
// the certificate it replaces and under the subject its leaves name.
func renewedMeshCert(ca *issuer.CA) ([]byte, error) {
	serial, err := certutil.GenerateSerial()
	if err != nil {
		return nil, err
	}
	template := certutil.NewCATemplate(serial, ca.Cert.Subject.CommonName, time.Now().Add(lifetimeOf(ca.Cert)))
	return x509.CreateCertificate(rand.Reader, template, template, ca.Key.Public(), ca.Key)
}

func lifetimeOf(cert *x509.Certificate) time.Duration {
	return cert.NotAfter.Sub(cert.NotBefore)
}

// What the allowlist history may take of the replicated state.
const (
	historyDocuments = 1000
	historyBytes     = 64 << 20
)

// pruneHistory bounds the allowlist history through the log, so every replica
// drops the same documents. Every write journals a whole document, so the
// bound is judged every tick, and a history inside it writes nothing.
func (n *Node) pruneHistory() {
	if !n.leading() {
		return
	}
	over, keep, err := n.historyOverItsBound()
	if err != nil {
		slog.Warn("cds-ha: this leader cannot read the allowlist history to bound it", "error", err)
		return
	}
	if !over {
		return
	}
	prune := &allowlist.Command{Op: allowlist.OpPruneHistory, Keep: keep, AtMS: time.Now().UnixMilli()}
	if _, err := n.propose(Entry{Kind: KindAllowlist, Allowlist: prune}); err != nil {
		slog.Warn("cds-ha: the allowlist history did not prune", "error", err)
		return
	}
	slog.Info("cds-ha: the allowlist history is pruned", "kept", keep)
}

// historyOverItsBound reports a history holding more than the cluster keeps,
// and how many of its newest documents it then keeps, never fewer than the one
// the store serves. The leader turns the byte budget into a count, so every
// replica drops the same documents.
func (n *Node) historyOverItsBound() (over bool, keep int, err error) {
	documents, stored, err := n.historySize()
	if err != nil {
		return false, 0, err
	}
	if documents <= historyDocuments && stored <= historyBytes {
		return false, 0, nil
	}
	withinBytes, err := n.cfg.Allowlist.HistoryKeepForBytes(historyBytes)
	if err != nil {
		return false, 0, err
	}
	keep = max(1, min(historyDocuments, withinBytes))
	return documents > keep, keep, nil
}

func (n *Node) historySize() (documents int, stored int64, err error) {
	documents, err = n.cfg.Allowlist.HistoryLen()
	if err != nil {
		return 0, 0, err
	}
	stored, err = n.cfg.Allowlist.LiveBytes()
	if err != nil {
		return 0, 0, err
	}
	return documents, stored, nil
}
