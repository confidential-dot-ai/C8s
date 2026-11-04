package cdsha

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	_ "modernc.org/sqlite"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A replica that joins takes the whole state from a peer: the cluster's
// agreement, its mesh CA and every store a CDS serves from.
func TestAReplicaInstallsTheWholeStateOfItsCluster(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	source.write(t)

	joining := joiningReplica(t, source)
	install(t, joining, snapshotOf(t, source))

	if !bytes.Equal(rawOf(t, joining.ClusterState()), rawOf(t, source.ClusterState())) {
		t.Fatalf("the cluster state is %+v, and the peer's is %+v", joining.ClusterState(), source.ClusterState())
	}
	if !joining.CA().Cert.Equal(source.CA().Cert) {
		t.Fatal("the mesh CA is not the cluster's")
	}
	if joining.AppliedIndex() != source.AppliedIndex() {
		t.Fatalf("the applied index is %d, and the peer is at %d", joining.AppliedIndex(), source.AppliedIndex())
	}
	if len(joining.Decrees()) != len(source.Decrees()) {
		t.Fatalf("the decree record holds %d decrees, and the peer's holds %d", len(joining.Decrees()), len(source.Decrees()))
	}
	if held, err := joining.al.Contains(testDigest(t)); err != nil || !held {
		t.Fatalf("the allowlist does not hold the cluster's workload: %v", err)
	}
	if value, err := joining.secrets.Get(context.Background(), "/db/password"); err != nil || string(value) != "hunter2" {
		t.Fatalf("the secret store holds %q: %v", value, err)
	}
	if host, ok := joining.ledger.Local().Lookup("sandbox"); !ok || host != "10.0.0.7:9000" {
		t.Fatalf("the sandbox ledger holds %q, %v", host, ok)
	}
}

// Nothing in a snapshot is signed, so a replica installs one only of its own
// cluster, taken under the launch file it boots, carrying the mesh CA whose
// certificate it names.
func TestASnapshotOfAnotherClusterIsRefused(t *testing.T) {
	for name, tamper := range map[string]func(*testing.T, *snapshot){
		"another cluster":     func(_ *testing.T, sn *snapshot) { sn.ClusterState.ClusterID = "someone-else" },
		"another launch file": func(_ *testing.T, sn *snapshot) { sn.ClusterState.ConfigSHA256 = strings.Repeat("ab", 32) },
		"another mesh CA key": func(t *testing.T, sn *snapshot) { _, sn.MeshCAKey = caBytes(t, mintCA(t)) },
	} {
		t.Run(name, func(t *testing.T) {
			source := newReplica(t)
			source.genesis()
			snapshot := snapshotOf(t, source)
			tamper(t, &snapshot.sn)

			joining := newReplica(t)
			if err := joining.Install(bytes.NewReader(encode(t, snapshot))); err == nil {
				t.Fatal("installed")
			}
			if joining.ClusterState().Joined() {
				t.Fatal("the refused snapshot left state behind")
			}
		})
	}
}

// A replica whose stores hold other limits than the cluster's could not
// apply the log it would take over, so it installs no snapshot of it.
func TestASnapshotTakenUnderOtherLimitsIsRefused(t *testing.T) {
	source := newReplica(t)
	source.genesis()

	joining := source.replica(
		t,
		inMemoryAllowlist(t),
		secrets.NewMemoryStore(8, 4, 128),
		sandboxledger.New(time.Hour, 8),
	)
	err := joining.Install(bytes.NewReader(encode(t, snapshotOf(t, source))))
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("installing a snapshot of other limits = %v, want ErrPolicy", err)
	}
	if joining.ClusterState().Joined() {
		t.Fatal("the refused snapshot left state behind")
	}
}

// The state a replica installs is the state its peer sent: the header names
// the digest of the database image, and the image reaches no store until it
// matches.
func TestASnapshotWhoseImageIsNotItsDigestIsRefused(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	source.write(t)
	snapshot := snapshotOf(t, source)
	snapshot.sn.Image = append(snapshot.sn.Image, 0)

	joining := newReplica(t)
	err := joining.Install(bytes.NewReader(encode(t, snapshot)))
	if !errors.Is(err, ErrSnapshotDigest) {
		t.Fatalf("installing an image the header does not name = %v, want ErrSnapshotDigest", err)
	}
	if held, err := joining.al.Contains(testDigest(t)); err != nil || held {
		t.Fatalf("the refused image reached the store: %v", err)
	}
}

// A snapshot from a replication stream that outlived a member's removal would
// roll a serving replica back, so a replica keeps the newer state it holds.
func TestASnapshotOlderThanTheAppliedStateIsRefused(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	snapshot := snapshotOf(t, source)
	source.write(t)

	joining := joiningReplica(t, source)
	install(t, joining, snapshotOf(t, source))
	err := joining.Install(bytes.NewReader(encode(t, snapshot)))
	if !errors.Is(err, ErrStaleSnapshot) {
		t.Fatalf("installing an overtaken snapshot = %v, want ErrStaleSnapshot", err)
	}
	if held, err := joining.al.Contains(testDigest(t)); err != nil || !held {
		t.Fatalf("the refused snapshot rolled the state back: %v", err)
	}
	// The state it holds is already the snapshot's, so installing it again
	// would replace the state with itself.
	caught := joining.Install(bytes.NewReader(encode(t, snapshotOf(t, source))))
	if !errors.Is(caught, ErrStaleSnapshot) {
		t.Fatalf("installing the state this replica holds = %v, want ErrStaleSnapshot", caught)
	}
}

// The state a snapshot carries is of one log index: the header is read
// before the database image, so a capture the log moved under is refused.
func TestACaptureTheLogMovedUnderIsRefused(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	if err := r.stillAt(r.AppliedIndex()); err != nil {
		t.Fatalf("a capture between two entries: %v", err)
	}
	if err := r.stillAt(r.AppliedIndex() - 1); err == nil {
		t.Fatal("a capture of an index the log has left was taken")
	}
}

// A replica holds no more than a replica of its cluster may, so a snapshot
// carrying more than the cluster's limits allow reaches no store.
func TestASnapshotPastTheClustersLimitsIsRefused(t *testing.T) {
	for name, carry := range map[string][]secrets.SnapshotEntry{
		"more paths than the cluster allows": manySecrets(9),
		"a secret larger than the cluster allows": {{
			Path:  "/big",
			Value: bytes.Repeat([]byte("v"), 65),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			source := newReplica(t)
			source.genesis()
			snapshot := snapshotOf(t, source)
			snapshot.sn.Secrets = carry

			joining := joiningReplica(t, source)
			if err := joining.Install(bytes.NewReader(encode(t, snapshot))); err == nil {
				t.Fatal("installed")
			}
			if joining.secrets.Len() != 0 {
				t.Fatal("the refused snapshot reached a store")
			}
		})
	}
}

// manySecrets is n paths of a snapshot's secrets.
func manySecrets(n int) []secrets.SnapshotEntry {
	out := make([]secrets.SnapshotEntry, 0, n)
	for i := range n {
		out = append(out, secrets.SnapshotEntry{
			Path:  fmt.Sprintf("/path/%d", i),
			Value: []byte("v"),
		})
	}
	return out
}

// A replica that cannot read a snapshot's encoding refuses it instead of
// installing state it would read differently than the rest of the group.
func TestASnapshotThisReplicaCannotReadIsRefused(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	snapshot := snapshotOf(t, source)
	snapshot.sn.ClusterState.Format = Format + 1

	joining := newReplica(t)
	if err := joining.Install(bytes.NewReader(encode(t, snapshot))); !errors.Is(err, ErrNewerFormat) {
		t.Fatalf("installing a snapshot of a newer format = %v, want ErrNewerFormat", err)
	}
}

// A header field this replica does not know would leave it holding something
// else than the replicas that know the field.
func TestASnapshotHeaderWithAFieldThisReplicaDoesNotKnowIsRefused(t *testing.T) {
	joining := newReplica(t)
	stream := encodeRaw(t, []byte(`{"index":1,"core":{"cluster_id":"lane"},"from_a_later_release":1}`), nil)
	if err := joining.Install(bytes.NewReader(stream)); err == nil {
		t.Fatal("installed")
	}
}

// Both ends hold to the same bounds: a replica refuses to write a state no
// replica could read back, and refuses to read one past them.
func TestAStatePastItsBoundsIsRefusedOnBothEnds(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	source.write(t)
	snapshot := snapshotOf(t, source)
	whole := stateBounds()

	for name, b := range map[string]bounds{
		"a header over its bound": {
			header: 64,
			image:  whole.image,
			stream: whole.stream,
		},
		"an image over its bound": {
			header: whole.header,
			image:  64,
			stream: whole.stream,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := encodeSnapshot(&bytes.Buffer{}, snapshot.sn, b); !errors.Is(err, ErrStateTooLarge) {
				t.Fatalf("encoding %s = %v, want ErrStateTooLarge", name, err)
			}
			if _, err := decodeSnapshot(bytes.NewReader(encode(t, snapshot)), Format, b); !errors.Is(err, ErrStateTooLarge) {
				t.Fatalf("decoding %s = %v, want ErrStateTooLarge", name, err)
			}
		})
	}
	// The stream bound is the reader's: a state inside the two decoded
	// bounds compresses inside it.
	t.Run("a stream over its bound", func(t *testing.T) {
		b := bounds{
			header: whole.header,
			image:  whole.image,
			stream: 64,
		}
		if _, err := decodeSnapshot(bytes.NewReader(encode(t, snapshot)), Format, b); !errors.Is(err, ErrStateTooLarge) {
			t.Fatalf("decoding a stream over its bound = %v, want ErrStateTooLarge", err)
		}
	})
}

// A replica that stopped applying the log holds a state the cluster never
// agreed on, so it is no state to hand anyone.
func TestAStoppedReplicaMakesNoSnapshot(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	if res := r.applyRaw([]byte(`{"kind":"from-a-later-release"}`)); res.Stop == nil {
		t.Fatal("the entry applied")
	}
	if _, err := r.Snapshot(); err == nil {
		t.Fatal("a stopped replica made a snapshot")
	}
}

// A snapshot this replica's own database cannot take leaves it behind for
// good: the sender keeps retrying while the replica, a voter with healthy
// heartbeats, serves nothing. It stops as it does on an entry its store
// refused, and exits to rejoin.
func TestASnapshotThisReplicasOwnStoreCannotTakeStopsItLocally(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	source.write(t)

	path := filepath.Join(t.TempDir(), "allowlist.db")
	al, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	joining := source.replica(
		t,
		al,
		secrets.NewMemoryStore(8, 4, 64),
		sandboxledger.New(time.Hour, 8),
	)

	holder, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { holder.Close() })
	holder.SetMaxOpenConns(1)
	if _, err := holder.Exec("BEGIN EXCLUSIVE"); err != nil {
		t.Fatal(err)
	}
	if err := joining.Install(bytes.NewReader(encode(t, snapshotOf(t, source)))); err == nil {
		t.Fatal("installed")
	}
	if !joining.StuckLocal() {
		t.Fatalf("stuck %q, want a fault of this replica's own", joining.Stuck())
	}
}

// write applies one command to each store the log writes.
func (r *replica) write(t *testing.T) {
	t.Helper()
	workloads := map[string]pkgallowlist.Workload{
		"web": {Containers: []pkgallowlist.Container{{Digest: testDigest(t)}}},
	}
	r.apply(Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:        allowlist.OpSeed,
			AtMS:      time.Now().UnixMilli(),
			Workloads: workloads,
		},
	})
	r.apply(Entry{
		Kind: KindSecret,
		Secret: &secrets.Command{
			Op:    secrets.OpPut,
			Path:  "/db/password",
			Value: []byte("hunter2"),
		},
	})
	r.apply(Entry{
		Kind: KindBinding,
		Binding: &sandboxledger.Command{
			SandboxID: "sandbox",
			Host:      "10.0.0.7:9000",
			AtMS:      time.Now().UnixMilli(),
		},
	})
}

// joiningReplica is another replica of the cluster, over empty stores.
func joiningReplica(t *testing.T, of *replica) *replica {
	t.Helper()
	return of.replica(
		t,
		inMemoryAllowlist(t),
		secrets.NewMemoryStore(8, 4, 64),
		sandboxledger.New(time.Hour, 8),
	)
}

// snapshotOf captures the replica's state.
func snapshotOf(t *testing.T, r *replica) *Snapshot {
	t.Helper()
	snapshot, err := r.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

// encode is the stream a snapshot travels as.
func encode(t *testing.T, snapshot *Snapshot) []byte {
	t.Helper()
	var stream bytes.Buffer
	if err := snapshot.Encode(&stream); err != nil {
		t.Fatal(err)
	}
	return stream.Bytes()
}

// encodeRaw is the stream of a header and an image chosen by the test.
func encodeRaw(t *testing.T, header, image []byte) []byte {
	t.Helper()
	var stream bytes.Buffer
	zw, err := zstd.NewWriter(&stream)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(append(header, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(image); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return stream.Bytes()
}

// install takes the snapshot as the joining replica does.
func install(t *testing.T, r *replica, snapshot *Snapshot) {
	t.Helper()
	if err := r.Install(bytes.NewReader(encode(t, snapshot))); err != nil {
		t.Fatal(err)
	}
}
