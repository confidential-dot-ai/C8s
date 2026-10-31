package cdsha

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsboard"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// A cluster that lost every replica is started again from a sealed backup:
// the operator opens one, signs a Restore decree naming the state it holds,
// and hands both to a replica that holds no cluster. The state brings the
// mesh CA, the allowlist and the secrets; the decree brings the image sets of
// the configuration the replicas boot now.

// relaunched is this cluster as its replicas boot it after the operator wrote
// the configuration again under the same cluster id: another launch file, the
// same cluster, operator keys and recovery key.
func (c cluster) relaunched(file []byte) cluster {
	digest := sha256.Sum256(file)
	c.launch.ConfigSHA256 = hex.EncodeToString(digest[:])
	return c
}

// freshReplica is a replica of c that holds no cluster, over stores holding
// the limits every replica of the test cluster holds.
func (c cluster) freshReplica(t *testing.T) *replica {
	t.Helper()
	return c.replica(t, inMemoryAllowlist(t), secrets.NewMemoryStore(8, 4, 64), sandboxledger.New(time.Hour, 8))
}

// pinsBoundTo pins one CDS image to the launch file a cluster boots, as the
// Restore decree for a cluster launched on that file carries.
func pinsBoundTo(t *testing.T, file []byte, digest byte) *cdsdecree.PinDocument {
	t.Helper()
	document, err := refvalues.Format(refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: []remote.ImagePin{{
			Name:       fmt.Sprintf("cds-%02x", digest),
			Digest:     bytes.Repeat([]byte{digest}, refvalues.DigestSize),
			LaunchFile: file,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pins, err := cdsdecree.NewPinDocument(document)
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

// restoreDecree is the decree the operator signs for the member that takes
// the restore: the state they opened from a backup, and the image sets of the
// configuration its replicas boot.
func restoreDecree(t *testing.T, member string, pins *cdsdecree.PinDocument, state []byte, resume uint64) cdsdecree.Decree {
	t.Helper()
	return cdsdecree.Decree{
		ClusterID:     testCluster,
		IntentID:      cdsdecree.NewIntentID(),
		Kind:          cdsdecree.Restore,
		ExpiresAt:     time.Now().Add(time.Hour),
		CDSPins:       pins,
		NodePins:      testNodeImages(t, 0x33),
		TargetMember:  member,
		TargetAddress: "10.0.0.5:8444",
		IssuedAtMS:    time.Now().UnixMilli(),
		ResumeVersion: resume,
		StateSHA256:   StateSHA256(state),
	}
}

// restoreEntry is the entry the replica that took the restore puts on the log
// it starts.
func (r *replica) restoreEntry(d cdsdecree.Decree, state []byte) RestoreEntry {
	r.t.Helper()
	return RestoreEntry{Decree: r.sign(d), AtMS: time.Now().UnixMilli(), State: state}
}

// restores applies a restore entry and answers what it produced.
func (r *replica) restores(entry RestoreEntry) DecreeResult {
	r.t.Helper()
	res := r.apply(Entry{Kind: KindRestore, Restore: &entry})
	if res.Decree == nil {
		r.t.Fatalf("a restore entry answered no decree result: %+v", res)
	}
	return *res.Decree
}

// lostClusterState is the state of a cluster that served, as the stream a
// backup seals: a workload in its allowlist and a secret in its store.
func lostClusterState(t *testing.T) (*replica, []byte) {
	t.Helper()
	r := newReplica(t)
	r.genesis()
	workloads := map[string]pkgallowlist.Workload{"web": {Containers: []pkgallowlist.Container{{Digest: testDigest(t)}}}}
	if res := r.apply(Entry{
		Kind:      KindAllowlist,
		Allowlist: &allowlist.Command{Op: allowlist.OpSeed, AtMS: time.Now().UnixMilli(), Workloads: workloads},
	}); res.Allowlist == nil || res.Allowlist.Kind != "" {
		t.Fatalf("seed the allowlist: %+v", res)
	}
	if res := r.apply(Entry{
		Kind:   KindSecret,
		Secret: &secrets.Command{Op: secrets.OpPut, Path: "/db/password", Value: []byte("hunter2")},
	}); res.Secret == nil || res.Secret.Kind != "" {
		t.Fatalf("write a secret: %+v", res)
	}
	captured, err := r.Snapshot()
	if err != nil {
		t.Fatalf("capture the state: %v", err)
	}
	var body bytes.Buffer
	if err := captured.Encode(&body); err != nil {
		t.Fatalf("encode the state: %v", err)
	}
	return r, body.Bytes()
}

// A Restore crosses configurations: the state comes from the cluster that
// was, and the launch file, CDS pins and node images from the configuration
// its replicas boot now. The version resumes above the one the operator knows
// the lost cluster reached.
func TestARestoreStartsTheClusterUnderTheConfigurationItsReplicasBootNow(t *testing.T) {
	lost, state := lostClusterState(t)
	before := lost.ClusterState()
	fresh := lost.cluster.relaunched(otherLaunchFile).freshReplica(t)

	decree := restoreDecree(t, testMember, pinsBoundTo(t, otherLaunchFile, testCDSDigest), state, before.Version+5)
	entry := fresh.restoreEntry(decree, state)
	if res := fresh.restores(entry); res.Refused != "" || res.Version != before.Version+6 {
		t.Fatalf("the restore answered %+v, want version %d", res, before.Version+6)
	}

	core := fresh.ClusterState()
	switch {
	case certutil.CertFingerprint(core.MeshCACert) != lost.keptCA():
		t.Fatalf("the restored cluster issues under mesh CA %s, and the lost one under %s", certutil.CertFingerprint(core.MeshCACert), lost.keptCA())
	case core.ConfigSHA256 != fresh.cluster.launch.ConfigSHA256:
		t.Fatalf("the restored cluster is of launch file %s, and its replicas boot %s", core.ConfigSHA256, fresh.cluster.launch.ConfigSHA256)
	case core.PinsDecree == nil || core.PinsDecree.Decree.IntentID != decree.IntentID:
		t.Fatalf("the restored cluster pins its CDS by %+v, want the Restore decree %s", core.PinsDecree, decree.IntentID)
	case core.StartedAtMS < decree.IssuedAtMS:
		t.Fatalf("the restored cluster started at %d, and the decree was issued at %d", core.StartedAtMS, decree.IssuedAtMS)
	case !slices.Contains(core.AppliedDecrees, decree.IntentID):
		t.Fatalf("the restored cluster accounted for %v, want the Restore decree %s", core.AppliedDecrees, decree.IntentID)
	}
	if pins, err := core.PinsDecree.Decree.CDSPins.WithLaunchFile(otherLaunchFile); err != nil || len(pins.Images) != 1 {
		t.Fatalf("the restored cluster pins %+v of its own launch file: %v", pins, err)
	}
	nodes, err := core.NodeImages.Images()
	if err != nil || len(nodes.Images) != 1 {
		t.Fatalf("the restored cluster certifies %+v: %v", nodes, err)
	}
	if held, err := fresh.al.Contains(testDigest(t)); err != nil || !held {
		t.Fatalf("the restored allowlist does not hold the lost cluster's workload: %v", err)
	}
	value, err := fresh.secrets.Get(context.Background(), "/db/password")
	if err != nil || string(value) != "hunter2" {
		t.Fatalf("the restored secret store answered %q: %v", value, err)
	}
	if !slices.ContainsFunc(fresh.Decrees(), func(record DecreeRecord) bool {
		return record.Decree.Decree.IntentID == decree.IntentID
	}) {
		t.Fatal("the restore is not in the record of applied decrees")
	}
}

// The allowlist version never goes back: node enforcers ignore a version
// below the one they hold, so a restored document must look newer than every
// write of the cluster that was.
func TestARestoreRaisesTheAllowlistVersionToTheClustersStart(t *testing.T) {
	lost, state := lostClusterState(t)
	served := servedVersion(t, lost)
	fresh := lost.freshReplica(t)

	decree := restoreDecree(t, testMember, pinsBoundTo(t, testLaunchFile, testCDSDigest), state, lost.ClusterState().Version)
	if res := fresh.restores(fresh.restoreEntry(decree, state)); res.Refused != "" {
		t.Fatal(res.Refused)
	}

	restored := servedVersion(t, fresh)
	if restored <= served || restored < fresh.ClusterState().StartedAtMS {
		t.Fatalf("the restored allowlist serves version %d, the lost cluster served %d, and the cluster started at %d",
			restored, served, fresh.ClusterState().StartedAtMS)
	}
}

// servedVersion is the allowlist version a replica serves, which never goes
// back across a restart of the cluster.
func servedVersion(t *testing.T, r *replica) int64 {
	t.Helper()
	_, version, err := r.al.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	served, err := strconv.ParseInt(version, 10, 64)
	if err != nil {
		t.Fatalf("the allowlist serves version %q: %v", version, err)
	}
	return served
}

// Nothing of a restore is the cluster's own word: the decree is the
// operator's signature over which state it is, and the state must be of this
// cluster, this replica's limits and the digests it carries of itself.
func TestARestoreIsRefusedUnlessItIsTheOperatorsOwnState(t *testing.T) {
	lost, state := lostClusterState(t)
	version := lost.ClusterState().Version
	for name, tc := range map[string]struct {
		state  []byte
		decree func(*cdsdecree.Decree)
	}{
		"another state than the decree names": {append(slices.Clone(state), 0), nil},
		"no state at all":                     {nil, func(d *cdsdecree.Decree) { d.StateSHA256 = StateSHA256(nil) }},
		"bytes that are no state": {[]byte("not a snapshot"), func(d *cdsdecree.Decree) {
			d.StateSHA256 = StateSHA256([]byte("not a snapshot"))
		}},
		"pins of another launch file": {state, func(d *cdsdecree.Decree) {
			d.CDSPins = pinsBoundTo(t, otherLaunchFile, testCDSDigest)
		}},
		"an expired decree":  {state, func(d *cdsdecree.Decree) { d.ExpiresAt = time.Now().Add(-time.Minute) }},
		"no resume version":  {state, func(d *cdsdecree.Decree) { d.ResumeVersion = 0 }},
		"another kind":       {state, func(d *cdsdecree.Decree) { d.Kind = cdsdecree.Genesis }},
		"no state digest":    {state, func(d *cdsdecree.Decree) { d.StateSHA256 = "" }},
		"another cluster id": {state, func(d *cdsdecree.Decree) { d.ClusterID = "another" }},
	} {
		t.Run(name, func(t *testing.T) {
			fresh := lost.freshReplica(t)
			decree := restoreDecree(t, testMember, pinsBoundTo(t, testLaunchFile, testCDSDigest), state, version)
			if tc.decree != nil {
				tc.decree(&decree)
			}
			if res := fresh.restores(fresh.restoreEntry(decree, tc.state)); res.Refused == "" {
				t.Fatalf("a restore with %s applied", name)
			}
			if fresh.ClusterState().Joined() {
				t.Fatalf("a restore with %s left the replica holding a cluster", name)
			}
		})
	}
}

// A restore starts a cluster that is gone: a replica holding one takes none,
// and the entry that carries a restore is the only one that applies it.
func TestARestoreOnlyStartsAClusterTheReplicaDoesNotHold(t *testing.T) {
	lost, state := lostClusterState(t)
	decree := restoreDecree(t, testMember, pinsBoundTo(t, testLaunchFile, testCDSDigest), state, lost.ClusterState().Version)

	if res := lost.restores(lost.restoreEntry(decree, state)); res.Refused == "" {
		t.Fatal("a replica holding a cluster took a restore")
	}
	if res := lost.applyDecreeEntry(lost.entryFor(decree)); res.Refused == "" {
		t.Fatal("a Restore decree applied as a decree entry, without the state it names")
	}
	another := lost.freshReplica(t)
	recover := another.decree(cdsdecree.Recover)
	if res := another.restores(another.restoreEntry(recover, state)); res.Refused == "" {
		t.Fatal("a restore entry carrying no Restore decree applied")
	}
}

// A replica takes a restore only while every replica of its cluster is
// accounted for as gone: the host answers every lookup and routes every
// packet, so an empty answer is no evidence, and a member that answers with a
// cluster refuses the restore whatever the decree says.
func TestARestoreFailsClosedWhileTheClusterMayStillBeThere(t *testing.T) {
	c := newLiveCluster(t)
	node, err := NewNode(c.replicaConfig(c.attestationAPI()))
	if err != nil {
		t.Fatalf("new replica: %v", err)
	}
	found := discovered{complete: true}
	for name, tc := range map[string]struct {
		searched *clusterSearch
		alone    bool
		restores bool
	}{
		"no pass of discovery yet": {nil, false, false},
		"a pass older than dead_after": {&clusterSearch{
			found:   found,
			answers: peerAnswers{answered: true},
			at:      time.Now().Add(-2 * releaseTiming.DeadAfter),
		}, false, false},
		"discovery that did not resolve every replica": {&clusterSearch{
			found:   discovered{},
			answers: peerAnswers{answered: true},
			at:      time.Now(),
		}, false, false},
		"no replica that answered": {&clusterSearch{
			found:   found,
			answers: peerAnswers{},
			at:      time.Now(),
		}, false, false},
		"no replica that answered, and the operator says alone": {&clusterSearch{
			found:   found,
			answers: peerAnswers{},
			at:      time.Now(),
		}, true, true},
		"a replica that holds the cluster": {&clusterSearch{
			found:   found,
			answers: peerAnswers{answered: true, cluster: true},
			at:      time.Now(),
		}, false, false},
		"a replica that holds the cluster, and the operator says alone": {&clusterSearch{
			found:   found,
			answers: peerAnswers{answered: true, cluster: true},
			at:      time.Now(),
		}, true, false},
		"every replica answering that it holds none": {&clusterSearch{
			found:   found,
			answers: peerAnswers{answered: true},
			at:      time.Now(),
		}, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			node.searched.Store(tc.searched)
			core := node.ClusterState()
			err := node.lostCluster(core, tc.alone)
			if restores := err == nil; restores != tc.restores {
				t.Fatalf("a replica that found %+v answered %v", tc.searched, err)
			}
			if awaiting := node.awaitingRestore(core) != ""; awaiting != (tc.restores && !tc.alone) {
				t.Fatalf("a replica that found %+v says %q about its cluster being lost", tc.searched, node.awaitingRestore(core))
			}
		})
	}
}

// The decree is read and authorized before the state behind it, so a request
// no operator signed costs the replica no state at all.
func TestARestoreRequestIsAuthorizedBeforeItsState(t *testing.T) {
	c := newLiveCluster(t)
	node, err := NewNode(c.replicaConfig(c.attestationAPI()))
	if err != nil {
		t.Fatalf("new replica: %v", err)
	}
	node.searched.Store(&clusterSearch{found: discovered{complete: true}, answers: peerAnswers{answered: true}, at: time.Now()})
	lost, state := lostClusterState(t)
	version := lost.ClusterState().Version

	for name, tc := range map[string]struct {
		request io.Reader
	}{
		"a request with no decree line":      {bytes.NewReader(state)},
		"a decree line longer than a decree": {strings.NewReader(strings.Repeat("{", cdsboard.MaxDecreeBytes+1))},
		"a line that is no decree object":    {strings.NewReader("[1]\n")},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := node.Restore(tc.request)
			if err == nil {
				t.Fatal("a replica took the request")
			}
			if !errors.Is(err, ErrRestoreRequest) {
				t.Fatalf("a request the replica could not read answered %v, which is no %v", err, ErrRestoreRequest)
			}
		})
	}
	for name, decree := range map[string]cdsdecree.Decree{
		"a decree for another process": restoreDecree(t, testMember, pinsBoundTo(t, testLaunchFile, testCDSDigest), state, version),
		"a decree of another kind":     {ClusterID: testCluster, IntentID: cdsdecree.NewIntentID(), Kind: cdsdecree.RotateKey, ExpiresAt: time.Now().Add(time.Hour), BaseVersion: 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := node.Restore(requestOf(t, c.signDecree(decree), state)); err == nil {
				t.Fatal("a replica took the decree")
			}
		})
	}
}

// requestOf is what the operator posts: the decree on one line, and the state
// behind it.
func requestOf(t *testing.T, signed cdsdecree.Signed, state []byte) io.Reader {
	t.Helper()
	line, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(append(append(line, '\n'), state...))
}

// backupHolding waits for a backup of the cluster's state at or above index,
// and answers with the state it seals.
func (c *liveCluster) backupHolding(index uint64) (Backup, []byte) {
	c.t.Helper()
	var held Backup
	eventually(c.t, 30*time.Second, fmt.Sprintf("a backup of the state at log index %d", index), func() bool {
		for _, backup := range c.backupsOnTheBoard(1) {
			if backup.Meta.Index >= index {
				held = backup
				return true
			}
		}
		return false
	})
	state, err := OpenBackup(c.recovery, held)
	if err != nil {
		c.t.Fatalf("the backup does not open with the cluster's recovery key: %v", err)
	}
	return held, state
}

// The whole of it: a cluster writes, its board holds a backup, every replica
// of it is lost, and the replicas that replace them serve the state the
// backup held, under the mesh CA the cluster issued under.
func TestALostClusterIsRestoredAndTheReplicasThatReplaceItJoin(t *testing.T) {
	c := newLiveCluster(t)
	c.genesis(3)
	leader := c.leader()
	if err := write(leader, "web", pkgallowlist.Workload{}); err != nil {
		t.Fatalf("write the allowlist: %v", err)
	}
	if err := writeASecret(leader, "/db/password"); err != nil {
		t.Fatalf("write a secret: %v", err)
	}
	keptCA := meshCAOf(leader)
	backup, state := c.backupHolding(leader.node.fsm.AppliedIndex())

	for _, r := range slices.Clone(c.replicas) {
		c.stop(r)
	}
	fresh := []*liveReplica{c.start(), c.start(), c.start()}
	eventually(t, 20*time.Second, "a fresh replica reporting that its cluster may be lost", func() bool {
		return fresh[0].node.Status().AwaitingRestore != ""
	})

	resume := backup.Meta.Version + 5
	decree := restoreDecree(t, string(fresh[0].node.member), pinsBoundTo(t, testLaunchFile, testCDSDigest), state, resume)
	result, err := fresh[0].node.Restore(requestOf(t, c.signDecree(decree), state))
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if result.Version != resume+1 {
		t.Fatalf("the restored cluster is at version %d, and it resumes above %d", result.Version, resume)
	}

	core := fresh[0].node.ClusterState()
	if certutil.CertFingerprint(core.MeshCACert) != keptCA {
		t.Fatalf("the restored cluster issues under mesh CA %s, and the lost one under %s", certutil.CertFingerprint(core.MeshCACert), keptCA)
	}
	if !holds(t, fresh[0], "web") {
		t.Fatal("the restored cluster does not serve the allowlist the backup held")
	}
	c.joined(3)
	c.settled(20 * time.Second)
	for _, joiner := range fresh[1:] {
		c.caughtUp(joiner, fresh[0], 20*time.Second)
		if !holds(t, joiner, "web") {
			t.Fatalf("replica %s joined the restored cluster without the state it holds", joiner.node.member)
		}
		if fingerprint := certutil.CertFingerprint(joiner.node.ClusterState().MeshCACert); fingerprint != keptCA {
			t.Fatalf("replica %s issues under mesh CA %s, and the restored cluster under %s", joiner.node.member, fingerprint, keptCA)
		}
	}
	if status := fresh[0].node.Status(); status.AwaitingRestore != "" {
		t.Fatalf("a replica holding the restored cluster says %q about its cluster being lost", status.AwaitingRestore)
	}
}
