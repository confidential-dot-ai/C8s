package cdsha

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	"github.com/confidential-dot-ai/c8s/internal/cdsdecree"
	"github.com/confidential-dot-ai/c8s/internal/sandboxledger"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// A Genesis fixes the limits the cluster applies commands under. A replica
// whose own stores hold other limits would answer differently from its peers,
// so it stops before it changes any state.
func TestGenesisFixesTheClusterPolicy(t *testing.T) {
	c := newCluster(t)
	r := c.replica(
		t,
		inMemoryAllowlist(t),
		secrets.NewMemoryStore(8, 4, 64),
		sandboxledger.New(time.Hour, 8),
	)
	entry := r.entryFor(r.decree(cdsdecree.Genesis))
	if res := r.applyDecreeEntry(entry); res.Refused != "" {
		t.Fatal(res.Refused)
	}
	if got := r.ClusterState().Policy; got != r.LocalPolicy() {
		t.Fatalf("the cluster's policy is %+v", got)
	}

	other := c.replica(
		t,
		inMemoryAllowlist(t),
		secrets.NewMemoryStore(8, 4, 1024),
		sandboxledger.New(time.Hour, 8),
	)
	res := other.apply(Entry{
		Kind:   KindDecree,
		Decree: &entry,
	})
	if !errors.Is(res.Stop, ErrPolicy) {
		t.Fatalf("a replica whose stores hold other limits answered %+v", res)
	}
	if other.ClusterState().Joined() {
		t.Fatal("a refused policy left the cluster started")
	}
}

// The policy is checked against this replica's stores at every entry, so a
// replica that took the cluster's state from elsewhere stops at the first
// command rather than applying it under other limits.
func TestAClusterPolicyThisReplicaDoesNotHoldStopsIt(t *testing.T) {
	r := newReplica(t)
	r.genesis()
	r.mu.Lock()
	r.core.Policy.SecretsMaxValue++
	r.mu.Unlock()
	res := r.apply(Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:   allowlist.OpStartJournal,
			AtMS: time.Now().UnixMilli(),
		},
	})
	if !errors.Is(res.Stop, ErrPolicy) {
		t.Fatalf("applying a command under other limits answered %+v", res)
	}
	if r.Stuck() == "" {
		t.Fatal("the replica follows the log under limits it does not hold")
	}
}

// A replica that holds no cluster has nothing to apply an entry against.
func TestACommandBeforeGenesisStopsTheReplica(t *testing.T) {
	r := newReplica(t)
	res := r.apply(Entry{
		Kind: KindAllowlist,
		Allowlist: &allowlist.Command{
			Op:   allowlist.OpStartJournal,
			AtMS: time.Now().UnixMilli(),
		},
	})
	if res.Stop == nil || !strings.Contains(res.Stop.Error(), "holds no cluster") {
		t.Fatalf("a command before Genesis answered %+v", res)
	}
}
