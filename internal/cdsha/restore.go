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
// carries the CDS pins of the configuration the replicas boot now, and they
// replace the restored state's. The state brings the allowlist, the secrets,
// the sandbox bindings and the node images the lost cluster certified. This
// adds no power: the recovery key already opens every secret and the mesh CA
// key.
//
// The mesh CA is the one thing the restored cluster does not inherit. Its
// target mints a key inside the TEE and the decree names that certificate, as
// a Genesis does, so the key a restored cluster issues under has never been
// outside a TEE and the key in the backup stops being the cluster's. Every
// workload must be issued again under it, and the pods of the lost cluster
// authenticate nobody there.
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
	"slices"
	"time"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsboard"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// ErrRestoreRequest is a restore request this replica could not read: the
// caller is told to post another, where every other refusal is about the
// cluster or the state.
var ErrRestoreRequest = errors.New("cds-ha: this replica could not read the restore request")

// RestoreEntry is the first entry of a restored cluster: the operator's
// Restore decree, the clock of the replica that took the restore, the state
// the decree names, and the mesh CA that replica minted for the cluster.
type RestoreEntry struct {
	Decree cdsdecree.Signed `json:"decree"`
	AtMS   int64            `json:"at_ms"`
	State  []byte           `json:"state"`
	// MeshCACert and MeshCAKey are the minted mesh CA: DER and PKCS#8. The
	// decree names the certificate (genesis_ca).
	MeshCACert []byte `json:"mesh_ca_cert"`
	MeshCAKey  []byte `json:"mesh_ca_key"`
}

// NodeImagesIn are the node images the state of a backup certifies, which is
// the set a Restore of it carries: the restore sets that set from scratch, so
// a set the operator names instead would certify a node image the cluster
// retired.
func NodeImagesIn(state []byte) (*cdsdecree.NodeImages, error) {
	sn, err := decodeSnapshot(bytes.NewReader(state), Format, stateBounds())
	if err != nil {
		return nil, err
	}
	if sn.ClusterState.NodeImages == nil {
		return nil, errors.New("cds-ha: the state certifies no node images, so it is of no cluster that ever served")
	}
	return sn.ClusterState.NodeImages, nil
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
	entry, err := n.restoreEntry(signed, state)
	if err != nil {
		return DecreeResult{}, err
	}
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

// restoreEntry is the entry that starts the cluster again: the decree, the
// state it names, and the mesh CA this process minted, which the operator
// signed the fingerprint of into the decree.
func (n *Node) restoreEntry(signed cdsdecree.Signed, state []byte) (*RestoreEntry, error) {
	ca, err := n.genesisCA()
	if err != nil {
		return nil, fmt.Errorf("cds-ha: mint the mesh CA the restored cluster issues under: %w", err)
	}
	cert, key, err := caEntryBytes(ca)
	if err != nil {
		return nil, err
	}
	return &RestoreEntry{
		Decree:     signed,
		AtMS:       time.Now().UnixMilli(),
		State:      state,
		MeshCACert: cert,
		MeshCAKey:  key,
	}, nil
}

// applyRestore starts a lost cluster again from the state a Restore decree
// names: the allowlist, the secrets, the bindings and the node images of the
// cluster that was, under the CDS pins and launch file of the configuration
// this replica boots, and under a mesh CA this replica minted.
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
	ca, err := f.restoredMeshCA(re)
	if err != nil {
		return f.refused(err)
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

// restoredMeshCA is the mesh CA the restored cluster issues under: the one
// the replica taking the restore minted, which the operator signed the
// fingerprint of into the decree. The key in the state is the lost cluster's
// and has been outside a TEE; this one never has.
func (f *FSM) restoredMeshCA(re RestoreEntry) (*issuer.CA, error) {
	if certutil.CertFingerprint(re.MeshCACert) != re.Decree.Decree.GenesisCA {
		return nil, errors.New("the restore entry carries another mesh CA than the decree names")
	}
	ca, err := meshCA(re.MeshCACert, re.MeshCAKey)
	if err != nil {
		return nil, fmt.Errorf("the mesh CA the restore mints: %w", err)
	}
	return ca, nil
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
	if err := certifiesTheSameNodeImages(d.NodePins, sn.ClusterState.NodeImages); err != nil {
		return snapshot{}, err
	}
	if err := checkSnapshotDigests(sn); err != nil {
		return snapshot{}, err
	}
	return sn, withinPolicy(sn, sn.ClusterState.Policy)
}

// certifiesTheSameNodeImages requires a Restore to carry the node images the
// state it opens certifies: the set is the lost cluster's, and nodes never
// take a lower version of it, so a set naming another image would certify one
// the cluster retired, cluster-wide and for good. Entry names are the
// operator's, so the two are compared by what decides admission.
func certifiesTheSameNodeImages(decreed, held *cdsdecree.NodeImages) error {
	if held == nil {
		return errors.New("the state certifies no node images, so it is of no cluster that ever served")
	}
	certified, err := held.Images()
	if err != nil {
		return fmt.Errorf("the node images the state certifies: %w", err)
	}
	carried, err := decreed.Images()
	if err != nil {
		return fmt.Errorf("the node images the decree carries: %w", err)
	}
	missing, extra := refvalues.Diff(certified, carried)
	if carried.Family != certified.Family || len(missing) > 0 || len(extra) > 0 {
		return fmt.Errorf("the decree certifies %d node images, and the state it opens certifies %d of them, beside %d of its own",
			len(carried.Images), len(carried.Images)-len(extra), len(missing))
	}
	return nil
}

// restoredCore is the core of the restored cluster: the lost cluster's own,
// with the launch file this replica boots, the decree as the pin decree the
// cluster applied, the mesh CA this replica minted, the node images at the
// version the restore counts, and the start time the decree moves the
// cluster to.
func (f *FSM) restoredCore(core ClusterState, re RestoreEntry) ClusterState {
	d := re.Decree.Decree
	restored := core.clone()
	restored.ConfigSHA256 = f.launch.ConfigSHA256
	restored.PinsDecree = &re.Decree
	restored.MeshCACert = slices.Clone(re.MeshCACert)
	restored.StartedAtMS = startMS(d, re.AtMS)
	version := restored.countDecree(d)
	restored.certifyNodeImages(d.NodePins, version)
	return restored
}
