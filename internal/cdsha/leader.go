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
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// Leader tasks: operator decrees, restore and recover, backups, history
// prune and mesh CA renewal.

// recover makes this replica the only voter of the cluster, with the state
// it holds, for a verified Recover decree naming it.
func (n *Node) recover(ctx context.Context, p PendingDecree) {
	r := n.r()
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	if r == nil || r != n.r() {
		n.log.Warn("recover: generation changed while waiting for membership", "decree", p.Name)
		return
	}
	if err := n.fsm.ValidatePolicy(n.fsm.Core().Policy); err != nil {
		n.log.Error("recover: application policy", "err", err)
		return
	}
	n.log.Warn("RECOVER: forcing a one-voter configuration with this replica's state", "decree", p.Name, "id", n.id)
	n.readCert.Store(nil) // recovery stops read admission before shutting Raft down
	if err := n.stopRaft(r); err != nil {
		if errors.Is(err, errShutdownTimeout) {
			// Its goroutines may still run over the stores and the log:
			// no new generation over them. Stuck, the replica exits (Run)
			// and its restart rejoins; the decree stays pending.
			_ = n.fsm.stopLocal(fmt.Errorf("recover: %w", err))
			return
		}
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
	scratch := n.recoveryFSM(&al)
	// snapStore ignores the transport RecoverCluster passes it.
	if err := raft.RecoverCluster(n.rcfg, scratch, recoveryLogStore{LogStore: n.logs, scratch: scratch}, n.stable, n.snaps, nil, n.solo()); err != nil {
		n.log.Error("recover: RecoverCluster", "err", err)
		return
	}
	// RecoverCluster ignores application results. A rejected policy or
	// unreadable command must not turn a partial replay into serving state.
	if reason := scratch.Stuck(); reason != "" {
		n.log.Error("recover: replay stopped", "reason", reason)
		return
	}
	if err := n.startRaft(); err != nil {
		n.log.Error("recover: restart raft", "err", err)
		return
	}
	n.waitFor(20*n.cfg.Timing.Election, n.leading)
	// Record the decree in the log, so it can never apply again.
	n.applyDecree(ctx, p)
}

// recoveryFSM keeps replay policy identical to this replica's live FSM.
// Operators must still configure identical policies on all replicas.
func (n *Node) recoveryFSM(al *allowlist.Store) *FSM {
	f := NewFSM(PreGenesis(n.cfg.ClusterID, n.cfg.OperatorPubKey), al,
		n.cfg.Secrets.EmptyClone(), n.cfg.Ledger.EmptyClone())
	f.readable = n.fsm.readable
	return f
}

// pendingDecree is a valid pending decree of kind naming this replica.
func (n *Node) pendingDecree(ctx context.Context, kind DecreeKind) (PendingDecree, bool) {
	if n.cfg.Decrees == nil {
		return PendingDecree{}, false
	}
	ds, err := n.cfg.Decrees.ListDecrees(ctx)
	if err != nil {
		return PendingDecree{}, false
	}
	for _, d := range ds {
		if d.Status != nil || d.Err != nil || d.Decree.Decree.Kind != kind || d.Decree.Decree.BootstrapNode != n.cfg.NodeName {
			continue
		}
		err := CheckDecree(d.Decree, n.fsm.Core(), time.Now())
		if err == nil {
			err = n.checkTarget(d.Decree)
		}
		if err != nil {
			n.log.Info("decree not usable", "decree", d.Name, "kind", kind, "why", err)
			continue
		}
		return d, true
	}
	return PendingDecree{}, false
}

// checkTarget refuses a one-shot decree meant for another process: its
// target_member is the member ID this process minted at its start, never
// one a restarted replica on the same node could hold. Only the replica
// that acts on the decree checks it; the others apply the logged decree
// under their own IDs.
func (n *Node) checkTarget(sd SignedDecree) error {
	if t := sd.Decree.TargetMember; t != string(n.id) {
		return fmt.Errorf("%w: the decree names member %q, this replica is %q", ErrNotForThisNode, t, n.id)
	}
	return nil
}

// bootstrap starts a one-voter group with this replica and applies Genesis.
func (n *Node) bootstrap(ctx context.Context, g PendingDecree) {
	r := n.r()
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	if r == nil || r != n.r() || n.stoppingReads.Load() == r {
		n.log.Warn("bootstrap: generation changed or stopping", "decree", g.Name)
		return
	}
	n.log.Info("bootstrapping the CDS cluster", "decree", g.Name, "id", n.id)
	if err := r.BootstrapCluster(n.solo()).Error(); err != nil {
		n.log.Warn("bootstrap", "err", err)
		return
	}
	n.waitFor(10*n.cfg.Timing.Election, n.leading)
	n.applyDecree(ctx, g)
}

// maybeBackup seals and stores the state when it changed since the last
// stored backup, at most every Timing.Backup (leader only). Every failure is
// kept in Status.BackupError; a streak of them is logged as an error
// (backupFailed). A state over a snapshot size bound fails every attempt,
// and each attempt dumps and encodes the whole state: after such a failure
// the next attempt backs off (backupDelay).
func (n *Node) maybeBackup(ctx context.Context) {
	wait := n.cfg.Timing.Backup
	if n.backupTooLarge {
		wait = backupDelay(wait, n.backupFails)
	}
	if n.recovery == nil || n.cfg.Backups == nil || time.Since(n.backupAt) < wait {
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
		n.backupFailed("snapshot", err)
		return
	}
	_, rc, err := f.Open()
	if err != nil {
		n.backupFailed("open snapshot", err)
		return
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		n.backupFailed("read snapshot", err)
		return
	}
	sn, err := decodeSnapshot(bytes.NewReader(body), n.fsm.readable, true)
	if err != nil {
		n.backupFailed("decode snapshot", err)
		return
	}
	// Export the application state watermark, not Raft's barrier-only suffix.
	b, err := SealAuthenticatedBackup(n.recovery, BackupMeta{ClusterID: sn.Core.ClusterID, Epoch: sn.Core.Epoch, Index: sn.Index,
		AppliedDecrees: sn.Core.AppliedDecrees, EpochFrom: sn.Core.EpochFrom, TakenAtMS: time.Now().UnixMilli(), CAFingerprint: certutil.CertFingerprint(sn.Core.RootCert)}, body, sn.Core.RootCert, sn.Key)
	if err != nil {
		n.backupFailed("seal", err)
		return
	}
	if err := n.cfg.Backups.PutBackup(ctx, b); err != nil {
		if errors.Is(err, ErrBackupNotNewer) {
			// Another leader stored later state (this one is deposed or was
			// cut off), or the stored backup is of another history: leave
			// it, and wait for the next write. Still a failure, shown in
			// Status as "backup refused" until a backup is stored again: a
			// stored manifest is the host's word, and one that keeps
			// claiming newer state blocks every backup.
			n.backupIndex = applied
			n.backupFailed("backup refused", err)
			return
		}
		n.backupFailed("store", err)
		return
	}
	n.backupIndex = applied
	if n.backupFails > 0 {
		n.log.Info("backups resumed", "after_failures", n.backupFails)
	}
	n.backupFails, n.backupTooLarge = 0, false
	n.backupErr.Store(nil)
	n.lastBackup.Store(&storedBackup{BackupStatus: BackupStatus{Index: b.Meta.Index, Epoch: b.Meta.Epoch, AtMS: b.Meta.TakenAtMS}, at: time.Now()})
	n.log.Info("backup stored", "epoch", b.Meta.Epoch, "index", b.Meta.Index, "bytes", len(b.Ciphertext))
}

// A streak of backup failures is an error once it reaches
// backupAlarmFailures attempts or lasts backupAlarmPeriods x Timing.Backup:
// a total loss would now restore older state than the cluster holds.
const (
	backupAlarmFailures = 3
	backupAlarmPeriods  = 3
)

// backupFailed reports a backup that failed at stage: in Status.BackupError
// always, as a warning until the streak reaches the alarm, then as an
// error. A failure on a size bound will repeat until the state shrinks: it
// is an error at once, and the next attempt backs off.
func (n *Node) backupFailed(stage string, err error) {
	if n.backupFails == 0 {
		n.backupSince = time.Now()
	}
	n.backupFails++
	n.backupTooLarge = tooLarge(err)
	since := n.backupSince.UTC().Format(time.RFC3339)
	if n.backupTooLarge {
		retry := backupDelay(n.cfg.Timing.Backup, n.backupFails)
		msg := fmt.Sprintf("backup failing since %s (%d attempts): the replicated state exceeds the snapshot size limit (%s: %v); no backup is stored until it shrinks",
			since, n.backupFails, stage, err)
		n.backupErr.Store(&msg)
		n.log.Error("backup failed: the replicated state exceeds the snapshot size limit; no backup is stored until it shrinks (delete allowlist entries or lower --allowlist-history-bytes/--allowlist-history-versions)",
			"stage", stage, "err", err, "consecutive_failures", n.backupFails, "next_attempt_in", retry)
		return
	}
	msg := fmt.Sprintf("backup failing since %s (%d attempts): %s: %v", since, n.backupFails, stage, err)
	n.backupErr.Store(&msg)
	if n.backupFails >= backupAlarmFailures || time.Since(n.backupSince) >= backupAlarmPeriods*n.cfg.Timing.Backup {
		n.log.Error("backups failing: no new backup is stored, so a total loss would restore older state", "stage", stage, "err", err,
			"consecutive_failures", n.backupFails, "failing_for", time.Since(n.backupSince).Round(time.Second))
		return
	}
	n.log.Warn("backup: "+stage, "err", err, "consecutive_failures", n.backupFails)
}

// pruneSlack lets the history grow this far past HistoryVersions before the
// leader prunes, so pruning is one entry per batch of writes, not per write.
var pruneSlack = 64 // a var so tests can prune small histories

// maybePruneHistory (leader) bounds the allowlist history through the log,
// so every replica drops the same entries. It checks every Tick and prunes
// only a history over its bound, so an idle cluster writes nothing. Once
// per Timing.Backup was too slow: every write journals a whole document,
// so with documents of a MiB or more the history overshot its byte bound
// by over 100 MiB within the interval and the admission cap refused most
// writes until the next prune.
func (n *Node) maybePruneHistory() {
	keep := n.cfg.HistoryVersions
	if (keep <= 0 && n.cfg.HistoryBytes <= 0) || n.cfg.Allowlist == nil || time.Since(n.pruneAt) < n.cfg.Timing.Tick {
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
	n.prunes.Add(1)
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

// ErrNotForThisNode refuses a one-shot decree that names another node, or
// another process (an earlier or later start) on this node.
var ErrNotForThisNode = errors.New("cds-ha: the decree names another node or replica process")

// Restore starts a cluster from an operator backup on this replica, which
// must hold no cluster and be the node the decree names. No replica it can
// reach may belong to a cluster: a restore never forks a live one.
// CheckRestore checks authorization and local eligibility without reading snapshot bytes.
// Restore repeats this check because state may change during an upload.
func (n *Node) CheckRestore(sd SignedDecree) error {
	d := sd.Decree
	switch {
	case n.r() == nil:
		return errors.New("cds-ha: replica not started")
	case d.Kind != Restore:
		return errors.New("cds-ha: not a Restore decree")
	case d.BootstrapNode != n.cfg.NodeName:
		return ErrNotForThisNode
	case n.member() || n.fsm.Core().Joined():
		return errors.New("cds-ha: this replica already belongs to a cluster")
	}
	if err := CheckDecree(sd, n.fsm.Core(), time.Now()); err != nil {
		return err
	}
	return n.checkTarget(sd)
}

func (n *Node) Restore(ctx context.Context, sd SignedDecree, snapshot []byte) (DecreeResult, error) {
	n.eligibilityMu.Lock()
	defer n.eligibilityMu.Unlock()
	if err := n.CheckRestore(sd); err != nil {
		return DecreeResult{}, err
	}
	d := sd.Decree
	if SnapshotSHA256(snapshot) != d.SnapshotSHA256 {
		return DecreeResult{}, errors.New("cds-ha: snapshot differs from the one the decree names")
	}
	// Reuse the complete application path on disposable stores. Authorization and
	// hash checks precede bounded decoding; no live store or Raft state changes.
	al, err := allowlist.OpenInMemory()
	if err != nil {
		return DecreeResult{}, err
	}
	scratch := n.recoveryFSM(&al)
	result := scratch.applyRestore(RestoreEntry{Decree: sd, AtMS: time.Now().UnixMilli(), Snapshot: snapshot})
	al.Close()
	if result.Err != "" {
		return result, fmt.Errorf("cds-ha: restore preflight: %s", result.Err)
	}
	peers, _ := n.cfg.Peers(ctx)
	for _, p := range peers {
		if resp, err := n.call(p, 3*time.Second, controlRequest{Op: ctlStatus}); err == nil && resp.Member {
			return DecreeResult{}, fmt.Errorf("cds-ha: replica %s belongs to a cluster; join it instead of restoring", p)
		}
	}
	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()
	if err := n.CheckRestore(sd); err != nil {
		return DecreeResult{}, err
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
	r := n.r()
	if r == nil {
		return
	}
	term, start := r.CurrentTerm(), time.Now()
	ds, err := n.cfg.Decrees.ListDecrees(ctx)
	if err != nil {
		n.log.Debug("list decrees", "err", err)
		return
	}
	// Recover decrees first: the decree view is fresh once they are judged
	// (fence.go).
	core := n.fsm.Core()
	v := n.decreeView.Load()
	fresh := v != nil && v.term == term && start.Sub(v.at) < n.cfg.Timing.decreeLease()
	doubts, ok := n.judgeRecovers(ctx, ds, core, fresh)
	n.doubts.Store(&doubts)
	if ok && time.Since(start) < n.cfg.Timing.Apply {
		n.decreeView.Store(&decreeView{term: term, at: start})
		n.mu.Lock()
		clear(n.blindRemoved)
		n.mu.Unlock()
	}
	for _, d := range ds {
		if d.Status != nil || d.Err == nil && d.Decree.Decree.Kind == Recover && !slices.Contains(core.AppliedDecrees, d.Decree.Decree.IntentID) {
			continue
		}
		r := n.r()
		n.membershipMu.Lock()
		// A decree can change what reconcile decides from (seats, pins, the
		// key): never apply one in the middle of a membership pass, nor
		// after this replica stopped leading.
		var st DecreeStatus
		ok := false
		if r == n.r() && n.stoppingReads.Load() != r && r.State() == raft.Leader {
			st, ok = n.commitDecree(d)
		}
		n.membershipMu.Unlock()
		if ok {
			n.setStatus(ctx, d.Name, st) // the API server's wait holds no lock
		}
	}
}

// runDecrees applies operator decrees and stores backups while this
// replica leads. Both wait on the API server, so they run here rather than
// in Run's loop: a server that accepts and never answers must not hold up
// seat repair, history pruning, CA renewal or a stuck leader's exit. One
// goroutine keeps decrees in order and backups one at a time.
func (n *Node) runDecrees(ctx context.Context) {
	t := time.NewTicker(n.cfg.Timing.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if r := n.r(); r == nil || r.State() != raft.Leader {
			continue
		}
		n.applyDecrees(ctx)
		n.maybeBackup(ctx)
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

// applyDecree applies one decree and records the outcome on its object.
// Callers hold membershipMu.
func (n *Node) applyDecree(ctx context.Context, p PendingDecree) {
	if st, ok := n.commitDecree(p); ok {
		n.setStatus(ctx, p.Name, st)
	}
}

// commitDecree checks a decree and commits it through the log. It returns
// the status to record on the decree object, if any: a failure to commit
// leaves the decree pending. Callers hold membershipMu.
func (n *Node) commitDecree(p PendingDecree) (DecreeStatus, bool) {
	core := n.fsm.Core()
	if p.Err == nil {
		if i := slices.Index(core.AppliedDecrees, p.Decree.Decree.IntentID); i >= 0 {
			epoch := uint64(i + 1)
			return DecreeStatus{AppliedEpoch: &epoch}, true
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
		return DecreeStatus{RejectedReason: err.Error()}, true
	}
	de := DecreeEntry{Decree: p.Decree, AtMS: time.Now().UnixMilli()}
	if d.Kind == Genesis {
		de.Pins = n.cfg.BakedPins
		de.Policy = n.fsm.LocalPolicy()
	}
	if d.Kind == Genesis || d.Kind == RotateKey {
		minted, err := issuer.NewMeshCA(n.cfg.CACommonName, n.cfg.CAValidity)
		if err != nil {
			n.log.Error("mint mesh CA", "err", err)
			return DecreeStatus{}, false
		}
		ca := minted.Current().CA
		key, err := x509.MarshalPKCS8PrivateKey(ca.Key)
		if err != nil {
			n.log.Error("encode mesh CA key", "err", err)
			return DecreeStatus{}, false
		}
		de.RootCert, de.Key = ca.Cert.Raw, key
	}
	resp, err := n.applyEntry(Entry{Kind: KindDecree, Decree: &de})
	if err != nil {
		n.log.Warn("apply decree", "decree", p.Name, "err", err)
		return DecreeStatus{}, false
	}
	res, _ := resp.(DecreeResult)
	if res.Err != "" {
		return DecreeStatus{RejectedReason: res.Err}, true
	}
	n.log.Info("decree applied", "decree", p.Name, "kind", d.Kind, "epoch", res.Epoch)
	return DecreeStatus{AppliedEpoch: &res.Epoch}, true
}

func (n *Node) setStatus(ctx context.Context, name string, st DecreeStatus) bool {
	if err := n.cfg.Decrees.SetDecreeStatus(ctx, name, st); err != nil {
		n.log.Warn("write decree status", "decree", name, "err", err)
		return false
	}
	return true
}
