package cdsha

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/hashicorp/raft"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Leader tasks: operator decrees, restore and recover, backups, history
// prune and mesh CA renewal.

// recover makes this replica the only voter of the cluster, with the state
// it holds, for a verified Recover decree naming it.
func (n *Node) recover(ctx context.Context, p PendingDecree) {
	n.log.Warn("RECOVER: forcing a one-voter configuration with this replica's state", "decree", p.Name, "id", n.id)
	if err := n.r().Shutdown().Error(); err != nil {
		n.log.Error("recover: shut down raft", "err", err)
	}
	_ = n.mux.Load().Close()
	// RecoverCluster replays the log into the FSM it is given; use a
	// scratch one, and let NewRaft restore the real one from the snapshot.
	al, err := allowlist.OpenInMemory()
	if err != nil {
		n.log.Error("recover: scratch store", "err", err)
		return
	}
	defer al.Close()
	scratch := NewFSM(PreGenesis(n.cfg.ClusterID, n.cfg.OperatorPubKey), &al, secrets.NewMemoryStore(1<<20, 1<<19, 1<<20), sandboxledger.New(time.Hour, 1<<20))
	// snapStore ignores the transport RecoverCluster passes it.
	if err := raft.RecoverCluster(n.rcfg, scratch, n.logs, n.stable, n.snaps, nil, n.solo()); err != nil {
		n.log.Error("recover: RecoverCluster", "err", err)
	}
	if err := n.startRaft(); err != nil {
		n.log.Error("recover: restart raft", "err", err)
		return
	}
	n.waitFor(20*n.cfg.Timing.Election, n.leading)
	// Record the decree in the log, so it can never apply again.
	n.applyDecree(ctx, p)
}

// pendingDecree is a valid pending decree of kind naming this replica.
func (n *Node) pendingDecree(ctx context.Context, kind DecreeKind) (PendingDecree, bool) {
	if n.cfg.Decrees == nil {
		return PendingDecree{}, false
	}
	ds, err := n.cfg.Decrees.PendingDecrees(ctx)
	if err != nil {
		return PendingDecree{}, false
	}
	for _, d := range ds {
		if d.Err != nil || d.Decree.Decree.Kind != kind || d.Decree.Decree.BootstrapNode != n.cfg.NodeName {
			continue
		}
		if err := CheckDecree(d.Decree, n.fsm.Core(), time.Now()); err != nil {
			n.log.Info("decree not usable", "decree", d.Name, "kind", kind, "why", err)
			continue
		}
		return d, true
	}
	return PendingDecree{}, false
}

// bootstrap starts a one-voter group with this replica and applies Genesis.
func (n *Node) bootstrap(ctx context.Context, g PendingDecree) {
	n.log.Info("bootstrapping the CDS cluster", "decree", g.Name, "id", n.id)
	if err := n.r().BootstrapCluster(n.solo()).Error(); err != nil {
		n.log.Warn("bootstrap", "err", err)
		return
	}
	n.waitFor(10*n.cfg.Timing.Election, n.leading)
	n.applyDecree(ctx, g)
}

// maybeBackup seals and stores the state when it changed since the last
// stored backup, at most every Timing.Backup (leader only).
func (n *Node) maybeBackup(ctx context.Context) {
	if n.recovery == nil || n.cfg.Backups == nil || time.Since(n.backupAt) < n.cfg.Timing.Backup {
		return
	}
	core := n.fsm.Core()
	// Read the index before the snapshot: a write applied while it is taken
	// then still counts as not backed up, and the next round covers it.
	applied := n.fsm.AppliedIndex()
	if !core.Joined() || applied == n.backupIndex {
		return
	}
	n.backupAt = time.Now()
	f := n.r().Snapshot()
	if err := f.Error(); err != nil {
		n.log.Warn("backup: snapshot", "err", err)
		return
	}
	meta, rc, err := f.Open()
	if err != nil {
		n.log.Warn("backup: open snapshot", "err", err)
		return
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		n.log.Warn("backup: read snapshot", "err", err)
		return
	}
	sn, err := decodeSnapshot(bytes.NewReader(body), n.fsm.readable, true)
	if err != nil {
		n.log.Warn("backup: decode snapshot", "err", err)
		return
	}
	b, err := SealBackup(n.recovery, BackupMeta{ClusterID: sn.Core.ClusterID, Epoch: sn.Core.Epoch, Index: meta.Index,
		AppliedDecrees: sn.Core.AppliedDecrees, TakenAtMS: time.Now().UnixMilli(), CAFingerprint: certutil.CertFingerprint(sn.Core.RootCert)}, body)
	if err != nil {
		n.log.Warn("backup: seal", "err", err)
		return
	}
	if err := n.cfg.Backups.PutBackup(ctx, b); err != nil {
		if errors.Is(err, ErrBackupNotNewer) {
			// Another leader stored later state (this one is deposed or was
			// cut off): leave it.
			n.log.Warn("backup: not stored, a newer one exists", "err", err)
			n.backupIndex = applied
			return
		}
		n.log.Warn("backup: store", "err", err)
		return
	}
	n.backupIndex = applied
	n.log.Info("backup stored", "epoch", b.Meta.Epoch, "index", b.Meta.Index, "bytes", len(b.Ciphertext))
}

// pruneSlack lets the history grow this far past HistoryVersions before the
// leader prunes, so pruning is one entry per batch of writes, not per write.
var pruneSlack = 64 // a var so tests can prune small histories

// maybePruneHistory (leader) bounds the allowlist history through the log,
// so every replica drops the same entries.
func (n *Node) maybePruneHistory() {
	keep := n.cfg.HistoryVersions
	if (keep <= 0 && n.cfg.HistoryBytes <= 0) || n.cfg.Allowlist == nil || time.Since(n.pruneAt) < n.cfg.Timing.Backup {
		return
	}
	n.pruneAt = time.Now()
	have, err := n.cfg.Allowlist.HistoryLen()
	if err != nil {
		return
	}
	slack := pruneSlack
	if n.cfg.HistoryBytes > 0 {
		// The leader turns the byte budget into a count, so every replica
		// prunes the same entries.
		fit, err := n.cfg.Allowlist.HistoryKeepForBytes(n.cfg.HistoryBytes)
		if err != nil {
			return
		}
		if keep <= 0 || fit < keep {
			keep, slack = fit, 0
		}
	}
	if have <= keep+slack {
		return
	}
	if _, err := n.applyEntry(Entry{Kind: KindAllowlist,
		Allowlist: &allowlist.Command{Op: allowlist.OpPruneHistory, Keep: keep}}); err != nil {
		n.log.Warn("prune allowlist history", "err", err)
		return
	}
	n.log.Info("allowlist history pruned", "kept", keep, "had", have)
}

// maybeRenewCA (leader) renews the mesh CA certificate under the cluster's
// key once it is past half its lifetime, through the log, so every replica
// serves the same certificate and running workloads keep their trust anchor.
func (n *Node) maybeRenewCA() {
	ca := n.fsm.CA()
	if ca == nil || time.Since(n.renewAt) < n.cfg.Timing.Backup {
		return
	}
	cert := ca.Cert
	if !issuer.PastHalfLife(cert, time.Now()) {
		return
	}
	n.renewAt = time.Now()
	renewed, err := issuer.SelfSignCA(ca.Key, cert.Subject.CommonName, n.cfg.CAValidity)
	if err != nil {
		n.log.Error("renew mesh CA certificate", "err", err)
		return
	}
	if _, err := n.applyEntry(Entry{Kind: KindRenewCA, RenewCA: &RenewCAEntry{RootCert: renewed.Raw}}); err != nil {
		n.log.Warn("renew mesh CA certificate", "err", err)
		return
	}
	n.log.Info("renewed mesh CA certificate", "audit", true,
		"key_id", certutil.CertFingerprint(renewed.RawSubjectPublicKeyInfo), "not_after", renewed.NotAfter.Format(time.RFC3339))
}

// AwaitingRestore reports a replica that holds no cluster and has not seen
// one for dead_after: every replica was lost, and only an operator Restore
// (or Genesis) can start one. It is how the pre-join server tells the Service
// it may take the operator's restore; a replica on its way into a live
// cluster is not ready.
//
// Not hearing from a member is not enough: a replica on a node whose pod
// network is still coming up hears from nobody, and taking client traffic
// then would answer it from the pre-join server. It needs a peer that
// answered and holds no cluster either, or, for a lone survivor of a total
// loss, no member for lonerAfter.
func (n *Node) AwaitingRestore() bool {
	if n.member() || n.fsm.Core().Joined() {
		return false
	}
	sinceMember := time.Since(time.UnixMilli(n.lastMember.Load()))
	if sinceMember <= n.cfg.Timing.DeadAfter {
		return false
	}
	return n.lastLoner.Load() > n.lastMember.Load() || sinceMember > lonerAfter
}

// lonerAfter is how long a replica that reaches no peer at all waits before
// it offers to take a restore on its own.
const lonerAfter = 5 * time.Minute

// ErrNotForThisNode refuses a Restore decree that names another node.
var ErrNotForThisNode = errors.New("cds-ha: the Restore decree names another node")

// Restore starts a cluster from an operator backup on this replica, which
// must hold no cluster and be the node the decree names. No replica it can
// reach may belong to a cluster: a restore never forks a live one.
func (n *Node) Restore(ctx context.Context, sd SignedDecree, snapshot []byte) (DecreeResult, error) {
	d := sd.Decree
	switch {
	case n.r() == nil:
		return DecreeResult{}, errors.New("cds-ha: replica not started")
	case d.Kind != Restore:
		return DecreeResult{}, errors.New("cds-ha: not a Restore decree")
	case d.BootstrapNode != n.cfg.NodeName:
		return DecreeResult{}, ErrNotForThisNode
	case n.member() || n.fsm.Core().Joined():
		return DecreeResult{}, errors.New("cds-ha: this replica already belongs to a cluster")
	}
	if err := CheckDecree(sd, n.fsm.Core(), time.Now()); err != nil {
		return DecreeResult{}, err
	}
	if SnapshotSHA256(snapshot) != d.SnapshotSHA256 {
		return DecreeResult{}, errors.New("cds-ha: snapshot differs from the one the decree names")
	}
	peers, _ := n.cfg.Peers(ctx)
	for _, p := range peers {
		if resp, err := n.call(p, 3*time.Second, controlRequest{Op: ctlStatus}); err == nil && resp.Member {
			return DecreeResult{}, fmt.Errorf("cds-ha: replica %s belongs to a cluster; join it instead of restoring", p)
		}
	}
	n.log.Warn("RESTORE: starting the cluster from an operator backup", "decree", d.IntentID, "snapshot", d.SnapshotSHA256)
	if err := n.r().BootstrapCluster(n.solo()).Error(); err != nil {
		return DecreeResult{}, err
	}
	if !n.waitFor(20*n.cfg.Timing.Election, n.leading) {
		return DecreeResult{}, errors.New("cds-ha: did not become leader after bootstrap")
	}
	resp, err := n.applyEntry(Entry{Kind: KindRestore, Restore: &RestoreEntry{Decree: sd, AtMS: time.Now().UnixMilli(), Snapshot: snapshot}})
	if err != nil {
		return DecreeResult{}, err
	}
	res, _ := resp.(DecreeResult)
	if res.Err != "" {
		return res, errors.New("cds-ha: restore refused: " + res.Err)
	}
	return res, nil
}

// applyDecrees applies pending operator decrees (leader only).
func (n *Node) applyDecrees(ctx context.Context) {
	if n.cfg.Decrees == nil {
		return
	}
	ds, err := n.cfg.Decrees.PendingDecrees(ctx)
	if err != nil {
		n.log.Debug("list decrees", "err", err)
		return
	}
	applied := n.fsm.Core().AppliedDecrees
	for _, d := range ds {
		if d.Err == nil && d.Decree.Decree.Kind == Recover && !slices.Contains(applied, d.Decree.Decree.IntentID) {
			// A leader holds a majority: nothing was lost for good. Applied
			// here, the decree would only bump the epoch, and the replica it
			// names, if merely cut off, would come back to an epoch it did
			// not see.
			n.log.Warn("Recover decree refused: the cluster has a leader with a majority", "decree", d.Name)
			n.setStatus(ctx, d.Name, DecreeStatus{RejectedReason: ErrRecoverWithQuorum.Error()})
			continue
		}
		n.applyDecree(ctx, d)
	}
}

// checkPinsKeepMajority refuses a pin set that would unpin a majority of the
// voters. Peers check each other's pins on every connection, so such a set
// leaves no leader, and with no leader no later decree can undo it. A rolling
// upgrade adds the new image's pin first and drops the old one once a
// majority of voters run the new image.
func (n *Node) checkPinsKeepMajority(pins []string) error {
	voters, pinned := 0, 0 // no configuration: 0 of 0, refused
	for _, s := range n.servers() {
		if s.Suffrage != raft.Voter {
			continue
		}
		voters++
		m := n.measurement
		if s.ID != n.id {
			st, err := n.peerStatus(s.Address, 2*time.Second)
			if err != nil {
				continue // unknown counts as unpinned
			}
			m = st.Measurement
		}
		if slices.Contains(pins, m) {
			pinned++
		}
	}
	if pinned*2 <= voters {
		return fmt.Errorf("%w: %d of %d voters run a pinned image", ErrPinsLoseMajority, pinned, voters)
	}
	return nil
}

// ErrPinsLoseMajority refuses a pin set that a majority of voters fail.
var ErrPinsLoseMajority = errors.New("refused: the new pin set leaves fewer than a majority of voters pinned, which would stop the cluster for good; pin the new image beside the running one first")

// ErrRecoverWithQuorum refuses a Recover decree on a cluster that has a
// leader, and so a majority of its voters.
var ErrRecoverWithQuorum = errors.New("refused: the cluster has a leader with a majority of its voters; Recover is break-glass after losing the majority for good")

func (n *Node) applyDecree(ctx context.Context, p PendingDecree) {
	core := n.fsm.Core()
	if p.Err == nil {
		if i := slices.Index(core.AppliedDecrees, p.Decree.Decree.IntentID); i >= 0 {
			epoch := uint64(i + 1)
			n.setStatus(ctx, p.Name, DecreeStatus{AppliedEpoch: &epoch})
			return
		}
	}
	err := p.Err
	if err == nil {
		err = CheckDecree(p.Decree, core, time.Now())
	}
	d := p.Decree.Decree
	if err == nil && d.Kind == RotateKey && len(d.Measurements) > 0 && !slices.Contains(d.Measurements, n.measurement) {
		err = errors.New("bundled pin set excludes the leader; apply UpdateMeasurements first")
	}
	if err == nil && (d.Kind == UpdateMeasurements || d.Kind == RotateKey) && len(d.Measurements) > 0 {
		err = n.checkPinsKeepMajority(d.Measurements)
	}
	if err != nil {
		n.log.Info("decree rejected", "decree", p.Name, "why", err)
		n.setStatus(ctx, p.Name, DecreeStatus{RejectedReason: err.Error()})
		return
	}
	de := DecreeEntry{Decree: p.Decree, AtMS: time.Now().UnixMilli()}
	if d.Kind == Genesis {
		de.Pins = n.cfg.BakedPins
	}
	if d.Kind == Genesis || d.Kind == RotateKey {
		minted, err := issuer.NewMeshCA(n.cfg.CACommonName, n.cfg.CAValidity)
		if err != nil {
			n.log.Error("mint mesh CA", "err", err)
			return
		}
		ca := minted.Current().CA
		key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
		if err != nil {
			n.log.Error("encode mesh CA key", "err", err)
			return
		}
		de.RootCert, de.Key = ca.Cert.Raw, key
	}
	resp, err := n.applyEntry(Entry{Kind: KindDecree, Decree: &de})
	if err != nil {
		n.log.Warn("apply decree", "decree", p.Name, "err", err)
		return
	}
	res, _ := resp.(DecreeResult)
	if res.Err != "" {
		n.setStatus(ctx, p.Name, DecreeStatus{RejectedReason: res.Err})
		return
	}
	n.log.Info("decree applied", "decree", p.Name, "kind", d.Kind, "epoch", res.Epoch)
	n.setStatus(ctx, p.Name, DecreeStatus{AppliedEpoch: &res.Epoch})
}

func (n *Node) setStatus(ctx context.Context, name string, st DecreeStatus) {
	if err := n.cfg.Decrees.SetDecreeStatus(ctx, name, st); err != nil {
		n.log.Warn("write decree status", "decree", name, "err", err)
	}
}
