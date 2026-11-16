package cdsha

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The three stores a CDS keeps are written through the log and nowhere else,
// so a replica that applied the same entries holds the same answers.
func TestTheLogWritesEveryStore(t *testing.T) {
	r := newReplica(t)
	r.genesis()

	workloads := map[string]pkgallowlist.Workload{
		"web": {Containers: []pkgallowlist.Container{{Digest: testDigest(t)}}},
	}
	seed := r.apply(Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:        allowlist.OpSeed,
			AtMS:      time.Now().UnixMilli(),
			Workloads: workloads,
		},
	})
	if seed.Allowlist == nil || seed.Allowlist.Kind != "" || seed.Allowlist.Added != 1 {
		t.Fatalf("seeding the allowlist answered %+v", seed)
	}
	if held, err := r.al.Contains(testDigest(t)); err != nil || !held {
		t.Fatalf("the allowlist does not hold the seeded workload: %v", err)
	}

	secret := r.apply(Entry{
		Kind: KindSecret,
		Secret: &secrets.Command{
			Op:    secrets.OpPut,
			Path:  "/db/password",
			Value: []byte("hunter2"),
		},
	})
	if secret.Secret == nil || secret.Secret.Kind != "" {
		t.Fatalf("writing a secret answered %+v", secret)
	}
	if value, err := r.secrets.Get(context.Background(), "/db/password"); err != nil || string(value) != "hunter2" {
		t.Fatalf("the store holds %q: %v", value, err)
	}

	binding := r.apply(Entry{
		Kind: KindBinding,
		Binding: &sandboxledger.Command{
			SandboxID: "sandbox",
			Host:      "10.0.0.7:9000",
			AtMS:      time.Now().UnixMilli(),
		},
	})
	if binding.Binding == nil || !bool(*binding.Binding) {
		t.Fatalf("recording a sandbox binding answered %+v", binding)
	}
}

// A replica that cannot read an entry stops serving instead of skipping it:
// Raft moves on either way, and a replica that skipped one would answer from
// state the rest of the group does not have.
func TestAnEntryThisReplicaCannotReadStopsIt(t *testing.T) {
	for name, entry := range map[string]any{
		"a newer format": Entry{
			Kind:   KindSecret,
			Format: Format + 1,
			Secret: &secrets.Command{
				Op:    secrets.OpPut,
				Path:  "/p",
				Value: []byte("v"),
			},
		},
		"an unknown kind": Entry{Kind: "from-a-later-release"},
		"a newer agreed": Entry{
			Kind:      KindFormat,
			SetFormat: Format + 1,
		},
		"a kind with no body": Entry{Kind: KindSecret},
		"two JSON values":     json.RawMessage(`{"kind":"format","set_format":1}{}`),
		"an unknown field":    json.RawMessage(`{"kind":"secret","dropped":1}`),
		"not an entry":        json.RawMessage(`[1]`),
	} {
		t.Run(name, func(t *testing.T) {
			r := newReplica(t)
			r.genesis()
			if res := r.applyRaw(rawOf(t, entry)); res.Stop == nil {
				t.Fatalf("applied: %+v", res)
			}
			if r.Stuck() == "" || r.StuckLocal() {
				t.Fatalf("stuck %q, this replica's own fault %v", r.Stuck(), r.StuckLocal())
			}
			if r.AppliedIndex() != r.index {
				t.Fatal("the applied index stopped moving: Raft has moved on regardless")
			}
		})
	}
}

// An entry a replica understands and refuses is an answer, not a stop: the
// group holds the same state afterwards.
func TestARefusedCommandIsNotAStop(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	res := r.apply(Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:   "no-such-op",
			AtMS: time.Now().UnixMilli(),
		},
	})
	if res.Allowlist == nil || res.Allowlist.Kind == "" {
		t.Fatalf("an unknown allowlist command answered %+v", res)
	}
	if res.Allowlist.LocalStoreFault() {
		t.Fatal("a command the store refused was taken for a fault of this replica's disk")
	}
	if res.Stop != nil || r.Stuck() != "" {
		t.Fatalf("a refused command stopped the replica: %s", r.Stuck())
	}
}

// Every applied decree stays in the record an operator reads over the
// attested channel, and the record is bounded.
func TestTheDecreeRecordKeepsTheNewestDecrees(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	for range maxDecreeRecord + 2 {
		if res := r.applyDecreeEntry(r.entryFor(r.decree(cdsdecree.RotateKey))); res.Refused != "" {
			t.Fatal(res.Refused)
		}
	}
	record := r.Decrees()
	if len(record) != maxDecreeRecord {
		t.Fatalf("the record holds %d decrees, want %d", len(record), maxDecreeRecord)
	}
	if !slices.IsSortedFunc(record, func(a, b DecreeRecord) int { return cmp.Compare(a.Version, b.Version) }) {
		t.Fatal("the record is not oldest first")
	}
	last := record[len(record)-1]
	applied := r.ClusterState().AppliedDecrees
	if last.Version != r.ClusterState().Version || last.Decree.Decree.IntentID != applied[len(applied)-1] {
		t.Fatalf("the newest record entry is %+v, and the cluster is at version %d", last, r.ClusterState().Version)
	}
}

// A replica serves the cluster its measured configuration names, so there is
// no state machine without one.
func TestAReplicaLaunchesWithItsClusterAndKeys(t *testing.T) {
	c := newCluster(t)
	for name, launch := range map[string]Launch{
		"no cluster": {
			OperatorKeys: c.launch.OperatorKeys,
			ConfigSHA256: c.launch.ConfigSHA256,
			Voters:       3,
		},
		"no operator key": {
			ClusterID:    testCluster,
			ConfigSHA256: c.launch.ConfigSHA256,
			Voters:       3,
		},
		"no launch file": {
			ClusterID:    testCluster,
			OperatorKeys: c.launch.OperatorKeys,
			Voters:       3,
		},
		"no voter seats": {
			ClusterID:    testCluster,
			OperatorKeys: c.launch.OperatorKeys,
			ConfigSHA256: c.launch.ConfigSHA256,
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered == nil {
					t.Fatal("a state machine was built")
				}
			}()
			NewFSM(
				launch,
				inMemoryAllowlist(t),
				secrets.NewMemoryStore(8, 4, 64),
				sandboxledger.New(time.Hour, 8),
			)
		})
	}
}

func testDigest(t *testing.T) types.Digest {
	t.Helper()
	digest, err := types.ParseDigest("sha256:" + strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

// rawOf is an entry as it travels: a value the test marshals, or bytes it
// wrote by hand.
func rawOf(t *testing.T, entry any) []byte {
	t.Helper()
	if raw, ok := entry.(json.RawMessage); ok {
		return raw
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
