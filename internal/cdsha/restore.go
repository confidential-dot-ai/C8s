// Restore: the cluster every replica of which is gone, started again from a
// sealed backup.
//
// The log lives in the replicas' TEE memory, so a cluster that lost every
// replica is gone with them. What is left is a backup on its board, sealed to
// the recovery key whose private half stays offline with the operator
// (backup.go). The operator opens one, signs a Restore decree naming the
// state it holds, and hands both to a replica that holds no cluster over the
// attested channel. That replica starts a one-voter group and the restore is
// its first log entry, as a Genesis is of a new cluster, so every replica
// that joins applies the same state.
//
// A Restore is the one decree that crosses configurations: the operator may
// have written the launch file again under the same cluster id, so the decree
// carries the CDS pins and node images of the configuration the replicas boot
// now, and they replace the restored state's. The state brings the mesh CA,
// the allowlist, the secrets and the sandbox bindings. This adds no power: the
// recovery key already opens every secret and the mesh CA key.
//
// It fails closed: a replica takes a restore only while it holds no cluster,
// its discovery resolved every replica of that cluster, and none of the ones
// that answered holds one. An empty discovery answer, which the host gives at
// will, needs a decree that says alone. See docs/cds-ha-backups.md.

package cdsha

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsboard"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

// ErrRestoreRequest is a restore request this replica could not read: the
// caller is told to post another, where every other refusal is about the
// cluster or the state.
var ErrRestoreRequest = errors.New("cds-ha: this replica could not read the restore request")

// RestoreEntry is the first entry of a restored cluster: the operator's
// Restore decree, the clock of the replica that took the restore, and the
// state the decree names.
type RestoreEntry struct {
	Decree cdsdecree.Signed `json:"decree"`
	AtMS   int64            `json:"at_ms"`
	State  []byte           `json:"state"`
}

// StateSHA256 names the state a Restore decree starts a cluster again from:
// the hex SHA-256 of the stream the operator opened from a sealed backup.
func StateSHA256(state []byte) string {
	sum := sha256.Sum256(state)
	return hex.EncodeToString(sum[:])
}

// Restore starts this replica's cluster again from the state in request: the
// Restore decree on its first line, and the state after it. It answers once
// the cluster holds that state, or with why this replica restored nothing.
func (n *Node) Restore(request io.Reader) (DecreeResult, error) {
	// One restore at a time: each starts a group of its own, and the second
	// would find a cluster the first is still writing.
	n.restores.Lock()
	defer n.restores.Unlock()
	signed, state, err := restoreRequest(request)
	if err != nil {
		return DecreeResult{}, err
	}
	// The decree is authorized before the state is read, so an unsigned
	// request costs this replica no state at all.
	if err := n.takesRestore(signed); err != nil {
		return DecreeResult{}, err
	}
	opened, err := readutil.ReadAll(state, stateBounds().stream)
	if err != nil {
		return DecreeResult{}, fmt.Errorf("cds-ha: the state the restore carries: %w", err)
	}
	return n.restoreFrom(signed, opened)
}

// restoreRequest reads the decree of a restore request and answers with the
// reader of the state behind it. The buffer holds one decree, so a first line
// longer than that is refused without reading the rest, and what the read of
// the line took from the body is still the reader's to hand on.
func restoreRequest(request io.Reader) (cdsdecree.Signed, io.Reader, error) {
	buffered := bufio.NewReaderSize(request, cdsboard.MaxDecreeBytes)
	line, err := buffered.ReadSlice('\n')
	if err != nil {
		return cdsdecree.Signed{}, nil, fmt.Errorf("%w: its first line is no decree of up to %d bytes: %w", ErrRestoreRequest, cdsboard.MaxDecreeBytes, err)
	}
	signed, err := cdsdecree.Parse(line)
	if err != nil {
		return cdsdecree.Signed{}, nil, fmt.Errorf("%w: %w", ErrRestoreRequest, err)
	}
	return signed, buffered, nil
}

// takesRestore is why this replica restores nothing: a decree that is not an
// operator Restore for this process, or a cluster that may still be there.
// The core it judges both against is one read of the state, and the clock is
// this replica's own; the state machine judges the decree again under the
// leader's clock when the entry applies.
func (n *Node) takesRestore(signed cdsdecree.Signed) error {
	d := signed.Decree
	if d.Kind != cdsdecree.Restore {
		return fmt.Errorf("cds-ha: a %s decree starts no cluster from a backup", d.Kind)
	}
	if d.TargetMember != string(n.member) {
		return errors.New("cds-ha: the Restore decree names another replica process than this one")
	}
	core := n.fsm.ClusterState()
	if err := checkDecree(n.cfg.Launch, core, signed, time.Now().UnixMilli()); err != nil {
		return err
	}
	return n.lostCluster(core, d.Alone)
}

// lostCluster is why this replica's cluster may still be there, and nothing
// where every replica of it is gone: this replica holds none, its discovery
// resolved every replica of the cluster, and the ones that answered hold none
// either. Only what discovery found is the operator's to take on themselves
// with alone, as they do for a Genesis.
func (n *Node) lostCluster(core ClusterState, alone bool) error {
	if core.Joined() {
		return errors.New("cds-ha: this replica holds a cluster already; a restore starts a lost one again")
	}
	searched := n.searched.Load()
	if err := checkSearch(searched, n.cfg.Timing.DeadAfter); err != nil {
		return err
	}
	return n.startable(alone, searched.found, searched.answers)
}

// checkSearch is why a pass of discovery settles nothing about this replica's
// cluster: there was none inside the time a member counts live in, or a
// member answered that it holds the cluster. Neither is a decree's to
// override.
func checkSearch(searched *clusterSearch, deadAfter time.Duration) error {
	switch {
	case searched == nil || time.Since(searched.at) > deadAfter:
		return errors.New("cds-ha: this replica has not looked for the replicas of its cluster within the last dead_after")
	case searched.answers.cluster:
		return errors.New("cds-ha: a replica of this cluster holds it; this replica joins it instead of restoring")
	}
	return nil
}

// clusterSearch is what the last pass of a replica outside its cluster found
// of it: the addresses discovery resolved and what the members it reached
// answered (members.go).
type clusterSearch struct {
	found   discovered
	answers peerAnswers
	at      time.Time
}

// searchedForItsCluster records the pass a restore and the operator's advice
// go by.
func (n *Node) searchedForItsCluster(found discovered, answers peerAnswers) {
	n.searched.Store(&clusterSearch{found: found, answers: answers, at: time.Now()})
}

// awaitingRestore is what this replica says about its cluster being lost: it
// holds none, and no replica of its cluster answered that it holds one. It is
// empty for every other replica, and it is advice rather than a verdict: only
// the operator can tell a cluster that is gone from a host that hides it.
func (n *Node) awaitingRestore(core ClusterState) string {
	if n.lostCluster(core, false) != nil {
		return ""
	}
	return "this replica holds no cluster and reached no replica that holds one: the cluster may be lost"
}

// restoreFrom makes this replica the one voter of a group with no log and
// commits the restore on it, as a Genesis starts a new cluster (genesis.go).
func (n *Node) restoreFrom(signed cdsdecree.Signed, state []byte) (DecreeResult, error) {
	intent := signed.Decree.IntentID
	slog.Warn("cds-ha: this replica starts its cluster again from a state its operator restored", "audit", true,
		"intent", intent, "member", n.member, "state", signed.Decree.StateSHA256)
	if err := n.bootstrapSolo(); err != nil {
		return DecreeResult{}, fmt.Errorf("cds-ha: start the one-voter group a restored cluster begins as: %w", err)
	}
	if !await(bootstrapElections*n.cfg.Timing.Election, n.leading) {
		return DecreeResult{}, errors.New("cds-ha: this replica started a group of its own and does not lead it")
	}
	entry := &RestoreEntry{Decree: signed, AtMS: time.Now().UnixMilli(), State: state}
	res, err := n.propose(Entry{Kind: KindRestore, Restore: entry})
	switch {
	case err != nil:
		return DecreeResult{}, fmt.Errorf("cds-ha: the restore did not commit: %w", err)
	case res.Decree == nil:
		return DecreeResult{}, errors.New("cds-ha: the state machine answered the restore with no result of one")
	case res.Decree.Refused != "":
		return *res.Decree, errors.New("cds-ha: the cluster refused the restore: " + res.Decree.Refused)
	}
	slog.Warn("cds-ha: this cluster is restored and this replica carries it alone until the others join", "audit", true,
		"intent", intent, "version", res.Decree.Version)
	return *res.Decree, nil
}

// applyRestore starts a lost cluster again from the state a Restore decree
// names: the mesh CA, the allowlist, the secrets and the bindings of the
// cluster that was, under the pins, node images and launch file of the
// configuration this replica boots.
func (f *FSM) applyRestore(re RestoreEntry) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	if re.Decree.Decree.Kind != cdsdecree.Restore {
		return f.refused(fmt.Errorf("a %s decree starts no cluster from a backup", re.Decree.Decree.Kind))
	}
	if err := checkDecree(f.launch, f.core, re.Decree, re.AtMS); err != nil {
		return f.refused(err)
	}
	sn, err := f.checkedRestoreState(re)
	if err != nil {
		return f.refused(err)
	}
	ca, err := meshCA(sn.ClusterState.MeshCACert, sn.MeshCAKey)
	if err != nil {
		return f.refused(fmt.Errorf("the restored state's mesh CA: %w", err))
	}
	lost := sn.ClusterState
	restored := f.restoredCore(sn.ClusterState, re)
	sn.ClusterState = restored
	if err := f.takeState(sn, ca); err != nil {
		return f.refused(err)
	}
	if err := f.raiseAllowlistVersion(restored.StartedAtMS); err != nil {
		return f.refused(err)
	}
	f.record(re.Decree, re.AtMS, restored.Version)
	slog.Warn("cds-ha: this cluster is restored from an operator backup; the writes the lost cluster took after that backup are gone", "audit", true,
		"intent", re.Decree.Decree.IntentID, "version", restored.Version, "restored_from_version", lost.Version, "restored_from_index", sn.Index)
	return Result{Decree: &DecreeResult{Version: restored.Version}}
}

// checkedRestoreState is the state a restore entry carries, as the lost
// cluster held it. Nothing of it is signed, so every part is checked: the
// digest the operator signed into the decree, the cluster it names, the
// limits this replica's stores hold, and the digests the state carries of
// itself.
func (f *FSM) checkedRestoreState(re RestoreEntry) (snapshot, error) {
	d := re.Decree.Decree
	if digest := StateSHA256(re.State); digest != d.StateSHA256 {
		return snapshot{}, fmt.Errorf("the state is %s, and the decree names %s", digest, d.StateSHA256)
	}
	sn, err := decodeSnapshot(bytes.NewReader(re.State), f.readable, stateBounds())
	if err != nil {
		return snapshot{}, err
	}
	if err := f.checkPolicy(sn.ClusterState.Policy); err != nil {
		return snapshot{}, err
	}
	switch {
	case !sn.ClusterState.Joined():
		return snapshot{}, errors.New("the state holds no mesh CA, so it is of no cluster that ever served")
	case sn.ClusterState.ClusterID != f.launch.ClusterID:
		return snapshot{}, fmt.Errorf("the state is of cluster %q, and this replica boots %q", sn.ClusterState.ClusterID, f.launch.ClusterID)
	}
	if err := checkSnapshotDigests(sn); err != nil {
		return snapshot{}, err
	}
	return sn, withinPolicy(sn, sn.ClusterState.Policy)
}

// restoredCore is the core of the restored cluster: the lost cluster's own,
// with the launch file this replica boots, the decree as the pin decree the
// cluster applied, the node images the decree carries, and the version and
// start time the decree counts (countDecree).
func (f *FSM) restoredCore(core ClusterState, re RestoreEntry) ClusterState {
	d := re.Decree.Decree
	restored := core.clone()
	restored.ConfigSHA256 = f.launch.ConfigSHA256
	restored.PinsDecree = &re.Decree
	restored.NodeImages = d.NodePins
	restored.StartedAtMS = startMS(d, re.AtMS)
	restored.countDecree(d)
	return restored
}
