package cdsha

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// Entry 0 is written create-if-absent once the store answers.
func TestGenesisBeforeStore(t *testing.T) {
	s := newSet(t, 1)
	s.node(0).setStore(nil)
	s.start()
	_, err := s.serves(0)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("served without a store: %v", err)
	}
	s.node(0).setStore(s.store)
	s.waitServing(0)
	if s.storeHead().Seq != 0 {
		t.Fatalf("store head %+v", s.storeHead())
	}
}

// A store head on another branch, below the held head, halts.
func TestStoreOtherBranchHalts(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	genesis := s.node(0).State().Head
	s.write(0)
	s.write(0)
	other := s.entry(genesis, 3)
	data, _ := other.Encode()
	_ = s.store.PutEntry(context.Background(), other.Hash(), data)
	raw, _ := json.Marshal(cdschain.Head{V: 1, Cluster: "lane", Seq: 1, Hash: other.Hash()})
	s.setHead(raw)
	if _, err := s.serves(0); !errors.Is(err, ErrHalted) && s.node(0).halted() == nil {
		t.Fatalf("not halted on another branch: %v", err)
	}
}

// REROOT: a store holding another genesis is a fork at seq 0.
func TestForeignGenesisRefused(t *testing.T) {
	a, b := newSet(t, 1), newSet(t, 1)
	a.bootstrap()
	b.start()
	b.node(0).setStore(a.store)
	b.waitFor("the foreign chain to halt the replica", func() bool { _, _ = b.serves(0); return b.node(0).halted() != nil })
	if f := b.node(0).halted(); f.Seq != 0 {
		t.Fatalf("fork %+v", f)
	}
}

// A store head naming any seq costs a bounded walk, even over a long
// run of linked entries that do not verify.
func TestHugeStoreHeadDoesNotAllocate(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	prev := s.node(0).State().Head.Hash
	for seq := uint64(1); seq <= maxWalk+10; seq++ {
		body, _ := json.Marshal(cdschain.Body{V: 1, Cluster: "lane", Seq: seq, Prev: prev, Type: cdschain.TypeOperatorKeys, Payload: json.RawMessage(`{"keys":""}`)})
		e := cdschain.Entry{Body: body, Sig: "x"}
		data, _ := e.Encode()
		_ = s.store.PutEntry(context.Background(), e.Hash(), data)
		prev = e.Hash()
	}
	raw, _ := json.Marshal(cdschain.Head{V: 1, Cluster: "lane", Seq: maxWalk + 10, Hash: prev})
	s.setHead(raw)
	// Only the read below walks the store: no gossip tick reads it too.
	s.node(0).cancel()
	time.Sleep(T)
	counting := &countingStore{Store: s.store}
	s.node(0).setStore(counting)
	if _, err := s.serves(0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("served a store head that does not verify: %v", err)
	}
	if entries, reads := counting.entries.Load(), counting.reads.Load(); reads != 1 || entries > maxWalk {
		t.Fatalf("%d store reads walked %d entries", reads, entries)
	}
}

// A self check that gets no answer evicts nothing.
func TestUnansweringSelfCheckEvictsNothing(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	s.mu.Lock()
	s.nodes[0].selfErr = true
	s.mu.Unlock()
	if _, _, err := s.node(0).Submit(context.Background(), s.accepted(s.node(0).State().Head, buildA, buildB)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * T)
	s.waitServing(0)
}

// A replica refuses a resolution dropping an entry it answered done.
func TestResolveRefusesDoneEntry(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	head := s.write(0)
	s.node(0).mu.Lock()
	s.node(0).haltLocked(Fork{Seq: head.Seq, Mine: head.Hash, Theirs: cdschain.Hash{7}})
	s.node(0).mu.Unlock()
	if err := s.node(0).Resolve(head.Seq, cdschain.Hash{7}, head.Hash); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "done") {
		t.Fatalf("dropped a done entry: %v", err)
	}
}

// A resolution past the held chain naming the zero hash as dropped is taken
// as by any replica behind the seq: nothing is cut.
func TestResolvePastTheChainCutsNothing(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	head := s.node(0).State().Head
	if err := s.node(0).Resolve(head.Seq+5, cdschain.Hash{7}, cdschain.Hash{}); err != nil {
		t.Fatal(err)
	}
	if got := s.node(0).State().Head; got != head {
		t.Fatalf("head %+v after a resolution past the chain, want %+v", got, head)
	}
}

type countingStore struct {
	Store
	reads, entries atomic.Int64
}

func (c *countingStore) GetEntry(ctx context.Context, h cdschain.Hash) ([]byte, error) {
	c.entries.Add(1)
	return c.Store.GetEntry(ctx, h)
}

func (c *countingStore) GetHead(ctx context.Context) ([]byte, error) {
	c.reads.Add(1)
	return c.Store.GetHead(ctx)
}

// The chain's size warning fires as it grows.
func TestChainSizeWarns(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	for range 3 {
		s.write(0)
	}
	if s.node(0).warned[0] == 0 {
		t.Fatal("no size warning past the threshold")
	}
}

// A store head above the held chain is walked, never taken
// as held because its hash is zero.
func TestZeroHashStoreHeadIsRefused(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	held := s.node(0).State().Head
	raw, _ := json.Marshal(cdschain.Head{V: 1, Cluster: "lane", Seq: held.Seq + 5})
	s.setHead(raw)
	if _, err := s.serves(0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("served over a store head with a zero hash: %v", err)
	}
}

// A read takes the store head first: a write another replica made is
// served at once, before any gossip round.
func TestReadTakesTheStoreHeadFirst(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	s.node(0).cancel()
	time.Sleep(T)
	head := s.node(0).State().Head
	e := s.entry(head, 1)
	data, _ := e.Encode()
	old, _ := s.store.GetHead(context.Background())
	next, _ := json.Marshal(cdschain.Head{V: 1, Cluster: "lane", Seq: head.Seq + 1, Hash: e.Hash()})
	_ = s.store.PutEntry(context.Background(), e.Hash(), data)
	if err := s.store.CASHead(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	if got, err := s.serves(0); err != nil || got.Hash != e.Hash() {
		t.Fatalf("served %+v %v, not the store's newer head", got, err)
	}
}

// Start refuses a genesis that no launch operator key signed, that does
// not name this replica at its slot, or that names another CA key; and a
// replica whose store holds a chain is no genesis. Each case breaks one rule.
func TestStartRefusals(t *testing.T) {
	s := newSet(t, 1)
	p, _ := s.node(0).Pending(false)
	stranger := newKey(t)
	other, _ := cdschain.PublicKeyPEM(&newKey(t).PublicKey)
	genesis := func(signer *ecdsa.PrivateKey, member, ca string) []cdschain.Entry {
		opPEM, _ := cdschain.PublicKeyPEM(&signer.PublicKey)
		payload, _ := json.Marshal(cdschain.Genesis{Endpoints: endpoints(1), Members: []string{member}, OperatorKeys: opPEM, CAKey: ca,
			Accepted: []cdschain.Build{{Measurements: buildA, Version: "v1.0.0"}}})
		e, err := cdschain.Sign(signer, cdschain.Body{Cluster: "lane", Type: cdschain.TypeGenesis, Payload: payload})
		if err != nil {
			t.Fatal(err)
		}
		return []cdschain.Entry{e}
	}
	for name, chain := range map[string][]cdschain.Entry{
		"another operator": genesis(stranger, p.Member, p.CAKey),
		"another member":   genesis(s.operator, other, p.CAKey),
		"another CA key":   genesis(s.operator, p.Member, other),
	} {
		if err := s.node(0).Start(Handoff{Entries: chain}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	s.mu.Lock()
	s.nodes[0].joining = true
	s.mu.Unlock()
	if err := s.node(0).Start(Handoff{Entries: genesis(s.operator, p.Member, p.CAKey)}); !errors.Is(err, ErrNotPending) {
		t.Errorf("a replica whose store holds a chain took a genesis: %v", err)
	}
	s.mu.Lock()
	s.nodes[0].joining = false
	s.mu.Unlock()
	if err := s.node(0).Start(Handoff{Entries: genesis(s.operator, p.Member, p.CAKey)}); err != nil {
		t.Fatalf("negative control: %v", err)
	}
}

// A replica still on the dropped branch, which never saw the kept entry, is
// resolved too: it drops its entry rather than refusing, so the set
// converges. One holding a third entry refuses.
func TestResolveDropsAnUnseenFork(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	head := s.write(0)
	keep := cdschain.Hash{7}
	if err := s.node(0).Resolve(head.Seq, keep, cdschain.Hash{8}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a resolution naming neither held entry: %v", err)
	}
	s.node(0).mu.Lock()
	s.node(0).done = nil
	s.node(0).mu.Unlock()
	if err := s.node(0).Resolve(head.Seq, keep, head.Hash); err != nil {
		t.Fatalf("dropping the held entry: %v", err)
	}
	if s.node(0).State().Head.Seq != head.Seq-1 {
		t.Fatal("the dropped entry is still held")
	}
}
