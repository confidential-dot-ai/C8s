package cdsha

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func TestReplicasThatAppliedTheSameLogRecordOneStateDigest(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	applyAll(source, writesOfOneLog(t, 1))

	joining := joiningReplica(t, source)
	install(t, joining, snapshotOf(t, source))
	joining.index = source.index

	replicas := []*replica{source, joining}
	for _, r := range replicas {
		applyAll(r, writesOfOneLog(t, 2))
		r.apply(Entry{Kind: KindCheckpoint})
	}

	held := checkpointOf(t, joining)
	was := checkpointOf(t, source)
	if held != was {
		t.Fatalf("the replicas hold %+v and %+v at the same checkpoint", held, was)
	}
	if held.State == (digest{}) || held.Chain == (digest{}) {
		t.Fatalf("the checkpoint carries no digests: %+v", held)
	}

	// An entry one replica alone applied is seen at the next checkpoint.
	joining.apply(Entry{
		Kind: KindSecret,
		Secret: &secrets.Command{
			Op:    secrets.OpPut,
			Path:  "/alone",
			Value: []byte("v"),
		},
	})
	for _, r := range replicas {
		r.index = joining.index
		r.apply(Entry{Kind: KindCheckpoint})
	}
	alone := checkpointOf(t, joining)
	together := checkpointOf(t, source)
	if alone.Chain == together.Chain || alone.State == together.State {
		t.Fatalf("an entry one replica alone applied left the checkpoints equal: %+v %+v", alone, together)
	}
}

// One write to each store, and a token spend refused the second time.
func writesOfOneLog(t *testing.T, tag int) []Entry {
	t.Helper()
	at := int64(1_800_000_000_000 + tag)
	token := fmt.Sprintf("header.payload-%d.signature", tag)
	spend := Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:    allowlist.OpConsumeToken,
			AtMS:  at,
			Token: token,
		},
	}
	return []Entry{
		{
			Kind: KindAllowlist,
			Allowlist: &allowlist.Command{
				Op:   allowlist.OpSeed,
				AtMS: at,
				Workloads: map[string]pkgallowlist.Workload{
					fmt.Sprintf("workload-%d", tag): testWorkload(t, tag),
				},
			},
		},
		{
			Kind: KindSecret,
			Secret: &secrets.Command{
				Op:    secrets.OpPut,
				Path:  fmt.Sprintf("/secret/%d", tag),
				Value: []byte{byte(tag)},
			},
		},
		{
			Kind: KindBinding,
			Binding: &sandboxledger.Command{
				SandboxID: fmt.Sprintf("sandbox-%d", tag),
				Host:      "10.0.0.7:9000",
				AtMS:      at,
			},
		},
		spend,
		spend,
	}
}

func applyAll(r *replica, entries []Entry) {
	for _, entry := range entries {
		r.apply(entry)
	}
}

func TestAReplicaThatStoppedRecordsNoStateDigest(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	r.apply(Entry{Kind: KindCheckpoint})
	before := checkpointOf(t, r)

	if res := r.applyRaw([]byte(`{"kind":"from-a-later-release"}`)); res.Stop == nil {
		t.Fatal("the entry applied")
	}
	r.apply(Entry{Kind: KindCheckpoint})

	after := checkpointOf(t, r)
	if after != before {
		t.Fatalf("a stopped replica recorded %+v at a checkpoint", after)
	}
	// Its chain still moves: the leader compares it with its own.
	if r.dig.latest().Index != r.index {
		t.Fatalf("the chain stands at index %d, and the log at %d", r.dig.latest().Index, r.index)
	}
}

func checkpointOf(t *testing.T, r *replica) Point {
	t.Helper()
	recorded := r.dig.lastCheckpoint()
	if recorded.State == (digest{}) {
		t.Fatal("the replica recorded no checkpoint")
	}
	return recorded
}

func TestAnInstalledSnapshotCarriesTheChainAndTheStateItHolds(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	source.write(t)
	captured := snapshotOf(t, source)

	joining := joiningReplica(t, source)
	install(t, joining, captured)

	if joining.dig.latest() != source.dig.latest() {
		t.Fatalf("the installed chain stands at %+v, and the peer's at %+v", joining.dig.latest(), source.dig.latest())
	}
	held, err := joining.digestsNow()
	if err != nil {
		t.Fatal(err)
	}
	if held != captured.sn.Digests {
		t.Fatalf("the installed state is %+v, and the snapshot carries %+v", held, captured.sn.Digests)
	}
}

func TestASnapshotWhoseContentIsNotItsDigestsIsRefused(t *testing.T) {
	source := newReplica(t)
	source.genesis()
	source.write(t)
	otherImage := imageOfAnotherAllowlist(t, source)

	for name, change := range map[string]func(*testing.T, *snapshot){
		"a secret":            func(_ *testing.T, sn *snapshot) { sn.Secrets[0].Value = []byte("another value") },
		"a sandbox binding":   func(_ *testing.T, sn *snapshot) { sn.Bindings[0].Host = "10.9.9.9:9000" },
		"the cluster state":   func(_ *testing.T, sn *snapshot) { sn.ClusterState.Voters = 7 },
		"the decree record":   func(_ *testing.T, sn *snapshot) { sn.Decrees = nil },
		"the database image":  func(_ *testing.T, sn *snapshot) { sn.Image, sn.ImageSHA256 = otherImage, imageDigest(otherImage) },
		"the state digest":    func(_ *testing.T, sn *snapshot) { sn.Digests.State = digest{} },
		"no digests at all":   func(_ *testing.T, sn *snapshot) { sn.Digests = Digests{} },
		"no chain of its own": func(_ *testing.T, sn *snapshot) { sn.Chain = Point{} },
	} {
		t.Run(name, func(t *testing.T) {
			captured := snapshotOf(t, source)
			change(t, &captured.sn)

			joining := joiningReplica(t, source)
			err := joining.Install(bytes.NewReader(encode(t, captured)))
			if !errors.Is(err, ErrSnapshotDigest) && !errors.Is(err, allowlist.ErrImageContent) {
				t.Fatalf("installing a snapshot with %s changed = %v, want its digests refused", name, err)
			}
			if joining.ClusterState().Joined() || joining.secrets.Len() != 0 {
				t.Fatalf("the refused snapshot reached a store of this replica")
			}
		})
	}
}

// As sound a database as the replica's own, holding another document.
func imageOfAnotherAllowlist(t *testing.T, of *replica) []byte {
	t.Helper()
	other := joiningReplica(t, of)
	other.index = of.index
	other.apply(Entry{Kind: KindAllowlist, Allowlist: &allowlist.Command{
		Op:        allowlist.OpSeed,
		AtMS:      time.Now().UnixMilli(),
		Workloads: map[string]pkgallowlist.Workload{"another": testWorkload(t, 9)},
	}})
	image, err := other.al.Dump()
	if err != nil {
		t.Fatal(err)
	}
	return image
}

func TestAStateThatChangedUnderTheReplicaIsNotCaptured(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.db")
	store, err := allowlist.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	r := newCluster(t).replica(
		t,
		store,
		secrets.NewMemoryStore(8, 4, 64),
		sandboxledger.New(time.Hour, 8),
	)
	r.genesis()
	r.write(t)
	if _, err := r.Snapshot(); err != nil {
		t.Fatalf("a capture of the state this replica applied: %v", err)
	}

	changeUnderTheStore(t, path)

	if _, err := r.Snapshot(); err == nil {
		t.Fatal("a capture of state that changed under the replica was taken")
	}
	if !r.StuckLocal() {
		t.Fatalf("stuck %q, want a fault of this replica's own", r.Stuck())
	}
}

// A connection of its own, which the store's digest hooks never see.
func changeUnderTheStore(t *testing.T, path string) {
	t.Helper()
	outside, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { outside.Close() })
	changed, err := outside.Exec(`UPDATE workload_entry SET name = 'changed-under-the-store'`)
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := changed.RowsAffected(); err != nil || rows == 0 {
		t.Fatalf("the test changed %d rows under the store: %v", rows, err)
	}
}

func TestADigestTravelsAsHex(t *testing.T) {
	point := Point{
		Index: 7,
		Chain: digest{0xab},
	}
	line, err := point.Chain.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if want := "ab" + strings.Repeat("00", 31); string(line) != want {
		t.Fatalf("the chain reads %q, want %q", line, want)
	}
	var read digest
	for _, text := range []string{"", "ab", "zz" + strings.Repeat("00", 31)} {
		if err := read.UnmarshalText([]byte(text)); err == nil {
			t.Errorf("%q read as a digest", text)
		}
	}
}
