package cdsha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/secrets"
)

// putSecret seals value through slot and writes the operator's secret entry
// naming it, nil deleting the secret; it returns the sealed hash.
func (s *set) putSecret(slot int, path string, value []byte) *cdschain.Hash {
	s.t.Helper()
	n := s.node(slot)
	var sealed *cdschain.Hash
	if value != nil {
		hex, err := n.Seal(context.Background(), path, value)
		if err != nil {
			s.t.Fatal(err)
		}
		h, err := cdschain.ParseHash(hex)
		if err != nil {
			s.t.Fatal(err)
		}
		sealed = &h
	}
	payload, _ := json.Marshal(cdschain.Secret{Path: path, Sealed: sealed})
	head := n.State().Head
	e := s.sign(cdschain.Body{Cluster: "lane", Seq: head.Seq + 1, Prev: head.Hash, Type: cdschain.TypeSecret, Payload: payload})
	if _, done, err := n.Submit(context.Background(), e); err != nil || !done {
		s.t.Fatalf("secret entry through slot %d: done=%v %v", slot, done, err)
	}
	return sealed
}

// released requires every replica to release want at path.
func (s *set) released(path string, want []byte) {
	s.t.Helper()
	for slot := range s.nodes {
		if got, err := s.node(slot).Secrets().Get(context.Background(), path); err != nil || !bytes.Equal(got, want) {
			s.t.Fatalf("slot %d released %q, %v; want %q", slot, got, err, want)
		}
	}
}

// A secret the operator writes through one replica is released by every
// replica, a replacement that joined by handoff included, and the store holds
// only ciphertext. A rotation releases only the new value; a delete, none.
func TestASetReleasesTheSecretItsChainNames(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	ctx := context.Background()
	old := []byte("operator-database-password")
	first := s.putSecret(0, "/app/db", old)
	s.released("/app/db", old)
	s.boot(2, buildA)
	s.waitServing(2)
	s.released("/app/db", old)
	stored, _ := s.store.GetEntry(ctx, *first)
	if len(stored) == 0 || bytes.Contains(stored, old) {
		t.Fatalf("the store holds %q", stored)
	}

	rotated := []byte("rotated-password")
	s.putSecret(1, "/app/db", rotated)
	s.released("/app/db", rotated)
	s.putSecret(2, "/app/db", nil)
	for slot := range s.nodes {
		if got, err := s.node(slot).Secrets().Get(ctx, "/app/db"); !errors.Is(err, secrets.ErrNotFound) {
			t.Fatalf("slot %d after the delete: %q, %v", slot, got, err)
		}
	}
}

// A store that serves an older sealed value under the newest entry's hash,
// or withholds it, gets a refusal, never the older value.
func TestASetRefusesARolledBackSecret(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	ctx := context.Background()
	old := []byte("old-value")
	first := s.putSecret(0, "/app/db", old)
	second := s.putSecret(0, "/app/db", []byte("new-value"))
	s.store.mu.Lock()
	s.store.entries[*second] = s.store.entries[*first]
	s.store.mu.Unlock()
	for slot := range s.nodes {
		if got, err := s.node(slot).Secrets().Get(ctx, "/app/db"); err == nil || bytes.Equal(got, old) {
			t.Fatalf("slot %d released %q, %v after the rollback", slot, got, err)
		}
	}
	s.store.mu.Lock()
	delete(s.store.entries, *second)
	s.store.mu.Unlock()
	if got, err := s.node(1).Secrets().Get(ctx, "/app/db"); err == nil {
		t.Fatalf("released %q with the value withheld", got)
	}
}

// A set generates no secret: a workload's create finds the operator's value
// or is refused.
func TestASetGeneratesNoSecret(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	st := s.node(1).Secrets()
	ctx := context.Background()
	if _, _, err := st.PutIfAbsent(ctx, "/app/key", []byte("generated"), secrets.WorkloadHolder("app")); !errors.Is(err, secrets.ErrOperatorOnly) {
		t.Fatalf("a workload's create: %v", err)
	}
	s.putSecret(0, "/app/key", []byte("operator"))
	if _, held, err := st.PutIfAbsent(ctx, "/app/key", []byte("generated"), secrets.WorkloadHolder("app")); err != nil || !held.Exists {
		t.Fatalf("a create over the operator's value: %+v %v", held, err)
	}
	s.released("/app/key", []byte("operator"))
}

// A replica that does not serve, here cut off from a majority, releases
// nothing.
func TestAReplicaThatDoesNotServeReleasesNoSecret(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.putSecret(0, "/app/db", []byte("value"))
	s.fault(1, true, 0)
	s.fault(2, true, 0)
	s.waitFor("slot 0 to refuse", func() bool { _, err := s.serves(0); return err != nil })
	if got, err := s.node(0).Secrets().Get(context.Background(), "/app/db"); err == nil {
		t.Fatalf("released %q", got)
	}
}
