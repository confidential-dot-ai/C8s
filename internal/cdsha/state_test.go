package cdsha

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// A replica whose CDS cannot serve the held state (say, the allowlist store
// refused the chain's policy) refuses instead of serving what the CDS still
// holds, and serves again once a later store read retries it with success.
func TestReplicaRefusesWhileTheCDSCannotServeItsState(t *testing.T) {
	s := newSet(t, 1)
	n := s.node(0)
	var failing atomic.Bool
	failing.Store(true)
	n.mu.Lock()
	n.cfg.OnState = func(*cdschain.State) error {
		if failing.Load() {
			return errors.New("database or disk is full")
		}
		return nil
	}
	n.mu.Unlock()
	s.start()
	s.waitFor("the replica to refuse on the failed state", func() bool {
		_, err := n.Current(context.Background())
		return errors.Is(err, ErrUnavailable) && strings.Contains(err.Error(), "disk is full")
	})
	if st := n.Status(); !strings.Contains(st.Serving, "disk is full") {
		t.Fatalf("status serving %q does not name the failed state", st.Serving)
	}
	failing.Store(false)
	s.waitServing(0)
}

// policyEntry is a policy entry after head whose allowlist admits name.
func (s *set) policyEntry(after cdschain.Head, name string) (cdschain.Entry, []byte) {
	s.t.Helper()
	doc, err := pkgallowlist.ParseJSON([]byte(`{"schema":"c8s.allowlist/v1","workloads":{"` + name + `":{"label":"ghcr.io/x/` + name + `:v1","containers":[{"digest":"sha256:` + strings.Repeat("ab", 32) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`))
	if err != nil {
		s.t.Fatal(err)
	}
	raw, err := doc.Canonical()
	if err != nil {
		s.t.Fatal(err)
	}
	payload, _ := json.Marshal(cdschain.Policy{Allowlist: raw})
	return s.sign(cdschain.Body{Cluster: "lane", Seq: after.Seq + 1, Prev: after.Hash, Type: cdschain.TypePolicy, Payload: payload}), raw
}

func digestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Policy answers for the policies of the chain the replica holds now: one a
// resolve dropped is gone, and one adopted after a lookup is found.
func TestPolicyFollowsTheHeldChain(t *testing.T) {
	s := newSet(t, 1)
	n := s.node(0)
	n.cancel()
	s.start()
	base := n.State().Head
	dropped, droppedRaw := s.policyEntry(base, "web")
	if err := n.adopt([]cdschain.Entry{dropped}, "test"); err != nil {
		t.Fatal(err)
	}
	if got, ok := n.Policy(digestOf(droppedRaw)); !ok || string(got) != string(droppedRaw) {
		t.Fatal("the held policy is not found by its digest")
	}
	n.mu.Lock()
	n.haltLocked(Fork{Seq: base.Seq + 1, Mine: dropped.Hash(), Theirs: cdschain.Hash{7}})
	n.mu.Unlock()
	if err := n.Resolve(base.Seq+1, cdschain.Hash{7}, dropped.Hash()); err != nil {
		t.Fatal(err)
	}
	if _, ok := n.Policy(digestOf(droppedRaw)); ok {
		t.Fatal("a policy the resolve dropped is still served by digest")
	}
	kept, keptRaw := s.policyEntry(base, "db")
	if err := n.adopt([]cdschain.Entry{kept}, "test"); err != nil {
		t.Fatal(err)
	}
	if got, ok := n.Policy(digestOf(keptRaw)); !ok || string(got) != string(keptRaw) {
		t.Fatal("a policy adopted after the last lookup is not found")
	}
}
