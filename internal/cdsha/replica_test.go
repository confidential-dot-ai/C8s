package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Genesis on one replica; the others join by handoff and every
// replica serves the done write.
func TestGenesisJoinAndWrite(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	head := s.write(0)
	for slot := range 3 {
		s.waitFor("every replica to serve the write", func() bool { h, err := s.serves(slot); return err == nil && h == head })
	}
}

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

// Two writers race for one seq: the entry whose compare-and-swap lost is
// refused with 409 and never held, served or gossiped.
func TestCASLoserNeverHeld(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	won, lost := s.entry(s.node(1).State().Head, 1), s.entry(s.node(1).State().Head, 2)
	s.node(1).setStore(losingStore{s.store, func() {
		if _, _, err := s.node(0).commit(context.Background(), fixed(won), false); err != nil {
			t.Errorf("the winning write: %v", err)
		}
	}})
	if _, _, err := s.node(1).commit(context.Background(), fixed(lost), false); !errors.Is(err, ErrConflict) {
		t.Fatalf("losing write: %v", err)
	}
	if s.node(1).State().Head.Hash == lost.Hash() {
		t.Fatal("the replica holds the entry whose swap lost")
	}
}

// losingStore lets another write win the race for its first swap.
type losingStore struct {
	Store
	win func()
}

func (l losingStore) CASHead(ctx context.Context, old, next []byte) error {
	if l.win != nil {
		l.win()
	}
	return l.Store.CASHead(ctx, old, next)
}

// A write no majority holds after its round is not done.
func TestWriteWithoutAMajorityIsNotDone(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.fault(1, true, 0)
	s.fault(2, true, 0)
	if _, done, err := s.node(0).commit(context.Background(), fixed(s.entry(s.node(0).State().Head, 1)), false); err != nil || done {
		t.Fatalf("done=%v %v with no peer answering", done, err)
	}
}

// A store rolled back is written forward; no replica
// serves below what it holds, and nobody refuses for it.
func TestStoreRollbackWrittenForward(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	old, _ := s.store.GetHead(context.Background())
	head := s.write(0)
	s.write(1)
	s.setHead(old)
	for slot := range 3 {
		if h, err := s.serves(slot); err != nil || h.Seq < head.Seq {
			t.Fatalf("slot %d served %+v %v after a rollback", slot, h, err)
		}
	}
	if s.storeHead().Seq < head.Seq+1 {
		t.Fatalf("store not written forward: %+v", s.storeHead())
	}
}

// A wiped store is re-seeded from a replica's memory.
func TestStoreWipedReseeded(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	head := s.write(0)
	fresh := NewMemory()
	for _, n := range s.nodes {
		n.setStore(fresh)
	}
	s.store = fresh
	if h, err := s.serves(1); err != nil || h != head {
		t.Fatalf("after a wipe: %+v %v", h, err)
	}
	if s.storeHead() != head {
		t.Fatalf("store not re-seeded: %+v", s.storeHead())
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

// Freshness needs pongs within T to this replica's pings.
func TestLatePongsAreNotFresh(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.fault(1, false, 2*T)
	s.fault(2, false, 2*T)
	s.waitFor("slot 0 to refuse", func() bool { _, err := s.serves(0); return errors.Is(err, ErrUnavailable) })
	s.fault(1, false, 0)
	s.waitServing(0)
}

// A replica cut off from a majority refuses reads and writes.
func TestMinorityRefuses(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.fault(1, true, 0)
	s.fault(2, true, 0)
	s.waitFor("slot 0 to refuse", func() bool { _, err := s.serves(0); return err != nil })
	if _, _, err := s.node(0).Submit(context.Background(), s.entry(s.node(0).State().Head, 1)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a cut-off replica took a write: %v", err)
	}
}

// A replica on a withholding store learns a done write from its
// peers within about T and writes its store forward; it does not halt.
func TestWithheldReplicaCatchesUp(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	stale := s.store.Clone()
	s.node(2).setStore(stale)
	head := s.write(0)
	s.waitFor("slot 2 to serve the write", func() bool { h, err := s.serves(2); return err == nil && h == head })
	if s.node(2).halted() != nil {
		t.Fatal("a withheld replica halted")
	}
	raw, _ := stale.GetHead(context.Background())
	var h cdschain.Head
	if json.Unmarshal(raw, &h) != nil || h != head {
		t.Fatalf("withheld store not written forward: %s", raw)
	}
}

// Two writes at one seq, one per store of an equivocating host, are
// never both done, in either order; the replicas then halt.
func TestTwoWritesAtOneSeqNeverBothDone(t *testing.T) {
	for _, first := range []int{0, 2} {
		s := newSet(t, 3)
		s.bootstrap()
		s.node(2).setStore(s.store.Clone())
		base := s.node(0).State().Head
		// Until both writes are in, only the first writer reaches out: a
		// pong carrying the first write, or a store written forward with
		// it, would turn the second into a 409 rather than a write at the
		// same seq.
		for slot := range 3 {
			s.mute(slot, slot != first)
		}
		done := 0
		for _, slot := range []int{first, 2 - first} {
			e := s.entry(base, slot+1)
			if _, ok, err := s.node(slot).commit(context.Background(), fixed(e), false); err == nil && ok {
				done++
			}
			if h := s.node(slot).State().Head; h.Hash != e.Hash() {
				t.Fatalf("first=%d: slot %d holds head %+v, not its write", first, slot, h)
			}
		}
		for slot := range 3 {
			s.mute(slot, false)
		}
		if done > 1 {
			t.Fatalf("first=%d: both writes at seq %d answered done", first, base.Seq+1)
		}
		s.waitFor("a fork halt", func() bool { return s.node(1).halted() != nil || s.node(0).halted() != nil })
	}
}

// A new instance at a slot displaces the member, which goes idle.
func TestDisplacedMemberGoesIdle(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	old := s.node(1)
	s.boot(1, buildA)
	s.waitServing(1)
	s.node(0).mu.Lock()
	chain, state := slices.Clone(s.node(0).chain), s.node(0).state
	s.node(0).mu.Unlock()
	old.mu.Lock()
	old.chain, old.state = chain, state
	old.mu.Unlock()
	if _, err := old.Current(context.Background()); err == nil || !strings.Contains(err.Error(), "not the member") {
		t.Fatalf("a displaced member: %v", err)
	}
}

// A joiner whose build is not accepted gets no keys and no slot.
func TestUnacceptedJoinerStaysPending(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.boot(2, buildB)
	time.Sleep(5 * T)
	if s.node(2).State() != nil || s.node(0).State().Members[2] == s.node(2).memberPEM {
		t.Fatal("an unaccepted build joined")
	}
}

// The keys leave only to a joiner accepted at the store's head when
// they leave, even when the accepted set changes between the check and the
// keys: here the genesis already names the joiner, so no member entry orders
// the two, and the eviction reaches only the store, so the giver learns it
// only by reading the store.
func TestHandoffRechecksAtNewHead(t *testing.T) {
	s := newSet(t, 3, buildA, buildA, buildB)
	var once sync.Once
	s.mu.Lock()
	s.onAttested = func(req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Host == "r2:8443" {
			once.Do(func() { s.storeWrite(s.accepted(s.storeHead(), buildA)) })
		}
	}
	s.mu.Unlock()
	s.start(buildA, buildB)
	time.Sleep(10 * T)
	if s.node(2).State() != nil {
		t.Fatal("a joiner evicted while it was admitted got the keys")
	}
}

// A halted replica hands nothing over, even to a replica the genesis
// already names.
func TestHaltedGiverRefuses(t *testing.T) {
	s := newSet(t, 3)
	s.start()
	s.node(0).mu.Lock()
	s.node(0).haltLocked(Fork{Seq: 0})
	s.node(0).mu.Unlock()
	time.Sleep(5 * T)
	if s.node(1).State() != nil || s.node(2).State() != nil {
		t.Fatal("a halted replica handed the keys over")
	}
}

// Raise-floor: a build no longer accepted stops serving; U1: it still
// hands the keys to a joiner of an accepted build.
func TestEvictedBuildStillHandsOff(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.write(0)
	if _, _, err := s.node(0).Submit(context.Background(), s.accepted(s.node(0).State().Head, buildC)); err != nil {
		t.Fatal(err)
	}
	s.waitFor("the evicted build to stop", func() bool { _, err := s.serves(1); return err != nil })
	s.boot(0, buildC)
	s.waitServing(0)
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

// Resolve: the replica holding the dropped entry drops it and catches up;
// reads racing the cut do not panic.
func TestResolveSettlesFork(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.node(2).setStore(s.store.Clone())
	base := s.node(0).State().Head
	keep, drop := s.entry(base, 1), s.entry(base, 2)
	// As in TestACutReplicaServesOnlyOnceItHoldsTheKeptEntry: slot 2 takes
	// the dropped entry, unreachable, before the kept one exists.
	s.fault(2, true, 0)
	_, _, _ = s.node(2).commit(context.Background(), fixed(drop), false)
	if h := s.node(2).State().Head; h.Hash != drop.Hash() {
		t.Fatalf("slot 2 holds head %+v, not the dropped entry", h)
	}
	_, _, _ = s.node(0).commit(context.Background(), fixed(keep), false)
	s.waitFor("the dropped side to halt", func() bool { return s.node(2).halted() != nil })
	s.fault(2, false, 0)
	s.node(2).setStore(s.store)
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 50 {
			_, _ = s.node(2).Current(context.Background())
		}
	})
	for slot := range 3 {
		if err := s.node(slot).Resolve(base.Seq+1, keep.Hash(), drop.Hash()); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	for slot := range 3 {
		s.waitFor("every replica on the kept entry", func() bool {
			h, err := s.serves(slot)
			return err == nil && h.Seq == base.Seq+1 && h.Hash == keep.Hash()
		})
	}
}

// A replica that a resolve cut back serves nothing until it holds the kept
// entry: that entry may be a done write, and its store may still show the
// dropped branch, which it then writes over with the shorter chain.
func TestACutReplicaServesOnlyOnceItHoldsTheKeptEntry(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.node(2).setStore(s.store.Clone())
	base := s.node(0).State().Head
	keep, drop := s.entry(base, 1), s.entry(base, 2)
	// Slot 2 takes the dropped entry before the kept one exists: a pong
	// carrying the kept entry first would leave it nothing to drop. No peer
	// reaches it, so none hears of the dropped entry before the kept one is done.
	s.fault(2, true, 0)
	_, _, _ = s.node(2).commit(context.Background(), fixed(drop), false)
	if h := s.node(2).State().Head; h.Hash != drop.Hash() {
		t.Fatalf("slot 2 holds head %+v, not the dropped entry", h)
	}
	if _, done, err := s.node(0).commit(context.Background(), fixed(keep), false); err != nil || !done {
		t.Fatalf("the kept entry is not done: %v %v", done, err)
	}
	s.waitFor("the dropped side to halt", func() bool { return s.node(2).halted() != nil })
	s.fault(2, false, 0)
	if err := s.node(2).Resolve(base.Seq+1, keep.Hash(), drop.Hash()); err != nil {
		t.Fatal(err)
	}
	if state, err := s.node(2).Current(context.Background()); err == nil && state.Head.Seq <= base.Seq {
		t.Fatalf("served head %d below the done entry at %d", state.Head.Seq, base.Seq+1)
	}
	s.waitFor("the cut replica to serve the kept entry", func() bool {
		h, err := s.serves(2)
		return err == nil && h.Hash == keep.Hash()
	})
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

// After a resolve at S, a store walk and a pong start where the reader's
// chain ends, not at S: else once the chain grows past the walk and pong
// bounds above S, a replica behind never catches up.
func TestAfterAResolveReadsStartAtTheHead(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	n := s.node(0)
	resolved := n.State().Head.Seq + 1
	if err := n.Resolve(resolved, cdschain.Hash{7}, cdschain.Hash{8}); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		s.write(0)
	}
	n.cancel()
	time.Sleep(T)
	head := n.State().Head
	ping, err := n.sign(Note{Cluster: "lane", Slot: 0, Nonce: "n", Head: head, From: resolved})
	if err != nil {
		t.Fatal(err)
	}
	if pong, err := n.HandleGossip(context.Background(), ping); err != nil || len(pong.Entries) != 0 {
		t.Fatalf("a pong to a pinger at this head carried %d entries: %v", len(pong.Entries), err)
	}
	e := s.entry(head, 1)
	data, _ := e.Encode()
	old, _ := s.store.GetHead(context.Background())
	next, _ := json.Marshal(cdschain.Head{V: 1, Cluster: "lane", Seq: head.Seq + 1, Hash: e.Hash()})
	_ = s.store.PutEntry(context.Background(), e.Hash(), data)
	if err := s.store.CASHead(context.Background(), old, next); err != nil {
		t.Fatal(err)
	}
	counting := &countingStore{Store: s.store}
	n.setStore(counting)
	if got, err := s.serves(0); err != nil || got.Hash != e.Hash() || counting.entries.Load() != 1 {
		t.Fatalf("served %+v %v after reading %d store entries, want the new head after 1", got, err, counting.entries.Load())
	}
}

// A ping not signed by a member costs no store read.
func TestUnsignedPingCausesNoWork(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	k := newKey(t)
	note, _ := json.Marshal(Note{Cluster: "lane", Slot: 0, Head: cdschain.Head{Seq: 99}})
	e, _ := cdschain.Sign(k, cdschain.Body{Cluster: "lane", Type: "gossip", Payload: note})
	counting := &countingStore{Store: s.store}
	s.node(0).setStore(counting)
	if _, err := s.node(0).HandleGossip(context.Background(), Gossip{Note: e}); !errors.Is(err, ErrInvalid) || counting.reads.Load() > 0 {
		t.Fatalf("unsigned ping: %v, %d store reads", err, counting.reads.Load())
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

// Operator requests are checked under the held chain's operator keys,
// not the launch file's.
func TestOperatorRequestsUseTheChainsKeys(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	rotated := newKey(t)
	pem, _ := cdschain.PublicKeyPEM(&rotated.PublicKey)
	payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: pem})
	head := s.node(0).State().Head
	if _, _, err := s.node(0).Submit(context.Background(), s.sign(cdschain.Body{Cluster: "lane", Seq: head.Seq + 1, Prev: head.Hash, Type: cdschain.TypeOperatorKeys, Payload: payload})); err != nil {
		t.Fatal(err)
	}
	var got []*ecdsa.PublicKey
	h := s.node(0).Handler(func(_ *http.Request, _ []byte, keys []*ecdsa.PublicKey) error { got = keys; return errors.New("no") })
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, ResolvePath, strings.NewReader("{}")))
	if len(got) != 1 || !got[0].Equal(&rotated.PublicKey) {
		t.Fatalf("the request was checked under %d keys, not the rotated one", len(got))
	}
	// A token minted right after the replica started is refused for now
	// (503, retry), any other refusal for good (401).
	for err, want := range map[error]int{fmt.Errorf("%w: now", operatorauth.ErrTokenBeforeStart): http.StatusServiceUnavailable, errors.New("no"): http.StatusUnauthorized} {
		rec := httptest.NewRecorder()
		s.node(0).Handler(func(*http.Request, []byte, []*ecdsa.PublicKey) error { return err }).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, StoreCredentialPath, strings.NewReader("x")))
		if rec.Code != want {
			t.Errorf("refused with %v: %d, want %d", err, rec.Code, want)
		}
	}
}

// Peers that answer but hold only an older head do not confirm a write.
func TestStalePeersDoNotConfirm(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	stale := s.store.Clone()
	s.node(1).setStore(stale)
	s.node(2).setStore(stale)
	s.fault(0, true, 0) // the peers' own pings cannot fetch it from the writer
	if _, done, err := s.node(0).commit(context.Background(), fixed(s.entry(s.node(0).State().Head, 1)), false); err != nil || done {
		t.Fatalf("done=%v %v while no peer could hold the entry", done, err)
	}
}

// Model fix 1: a replayed pong (another round's nonce) does not renew
// freshness.
func TestReplayedPongIsNotFresh(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.mu.Lock()
	s.replay = map[int][]byte{1: nil}
	s.mu.Unlock()
	s.fault(2, true, 0)
	s.waitFor("slot 0 to refuse on replayed pongs", func() bool { _, err := s.serves(0); return errors.Is(err, ErrUnavailable) })
}

// A pong not signed by the slot's member key does not count.
func TestForeignSignedPongIsNotFresh(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	stranger := newKey(t)
	s.mu.Lock()
	s.forge = func(slot int, _ *Note) *ecdsa.PrivateKey {
		if slot == 1 {
			return stranger
		}
		return nil
	}
	s.mu.Unlock()
	s.fault(2, true, 0)
	s.waitFor("slot 0 to refuse on foreign pongs", func() bool { _, err := s.serves(0); return errors.Is(err, ErrUnavailable) })
}

// A write a majority holds is still not done when its round halts the
// writer on another entry at its seq.
func TestWriteHaltedInItsRoundIsNotDone(t *testing.T) {
	s := newSet(t, 5)
	s.bootstrap()
	next := s.node(0).State().Head.Seq + 1
	s.mu.Lock()
	s.forge = func(slot int, n *Note) *ecdsa.PrivateKey {
		if slot >= 3 && n.Head.Seq >= next {
			n.Head = cdschain.Head{V: 1, Cluster: "lane", Seq: next, Hash: cdschain.Hash{7}}
			return s.nodes[slot].member
		}
		return nil
	}
	s.mu.Unlock()
	if _, done, err := s.node(0).commit(context.Background(), fixed(s.entry(s.node(0).State().Head, 1)), false); err != nil || done {
		t.Fatalf("done=%v %v though the round showed another entry at seq %d", done, err, next)
	}
	if s.node(0).halted() == nil {
		t.Fatal("the writer did not halt")
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

// A member's pong head above the held chain with a zero hash is not in the
// chain: it counts neither as fresh nor as a holder.
func TestZeroHashPongHeadIsNotHeld(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	held := s.node(0).State().Head
	if err := s.node(0).learn(cdschain.Head{V: 1, Cluster: "lane", Seq: held.Seq + 5}, nil, "a pong"); err == nil {
		t.Fatal("a zero-hash pong head above the chain was taken as held")
	}
	if err := s.node(0).learn(held, nil, "a pong"); err != nil {
		t.Fatalf("negative control: the held head: %v", err)
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

// The CA key travels sealed to the joiner's member key.
func TestHandoffSealsTheKeyToTheJoiner(t *testing.T) {
	s := newSet(t, 3)
	var leaked atomic.Bool
	s.mu.Lock()
	s.onAttested = func(req *http.Request) {
		if req.URL.Path == HandoffPath && req.Body != nil {
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			var h Handoff
			if json.Unmarshal(body, &h) == nil && bytes.Contains(h.CAKey, []byte("PRIVATE KEY")) {
				leaked.Store(true)
			}
		}
	}
	s.mu.Unlock()
	s.bootstrap()
	if leaked.Load() {
		t.Fatal("the CA key left in the clear")
	}
}

// A replica behind the head an entry follows refuses it with 503, not 409:
// a 409 says the head moved past the entry's prev.
func TestBehindReplicaDoesNotAnswerConflict(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	stale := s.store.Clone()
	s.node(2).setStore(stale)
	s.node(2).cancel() // no rounds: it learns nothing from its peers
	time.Sleep(T)
	head := s.write(0)
	_, _, err := s.node(2).commit(context.Background(), fixed(s.entry(head, 1)), false)
	if errors.Is(err, ErrConflict) {
		t.Fatalf("a replica behind answered a conflict: %v", err)
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

// A replica whose store names an older head than a member's latest pong
// refuses a write before its swap: on a withholding store the write could
// take a seq the set already took.
func TestWriteRefusedBelowAGossipedHead(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	stale := s.store.Clone()
	s.node(2).setStore(stale)
	s.node(2).cancel() // no rounds: only the pong set below
	time.Sleep(T)
	old := s.node(2).State().Head
	head := s.write(0)
	n := s.node(2)
	n.mu.Lock()
	n.heard[0] = heard{key: n.state.Members[0], at: time.Now(), seq: head.Seq}
	n.mu.Unlock()
	if _, _, err := n.commit(context.Background(), fixed(s.entry(old, 2)), false); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a write below a gossiped head: %v", err)
	}
	raw, _ := stale.GetHead(context.Background())
	var h cdschain.Head
	if json.Unmarshal(raw, &h) != nil || h != old {
		t.Fatalf("the withholding store moved to %s", raw)
	}
}

// A replica restarted at its slot (a new member key, so its giver writes a
// member entry) rejoins a chain of 1000 entries within 40 gossip intervals while
// another writer keeps the head moving.
func TestRestartedReplicaRejoinsUnderWriteLoad(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	ctx := context.Background()
	head := s.storeHead()
	old, _ := s.store.GetHead(ctx)
	for range 1000 {
		e := s.entry(head, 1)
		data, _ := e.Encode()
		_ = s.store.PutEntry(ctx, e.Hash(), data)
		head = cdschain.Head{V: 1, Cluster: "lane", Seq: head.Seq + 1, Hash: e.Hash()}
	}
	next, _ := json.Marshal(head)
	if err := s.store.CASHead(ctx, old, next); err != nil {
		t.Fatal(err)
	}
	s.waitFor("the set to hold 1000 entries", func() bool { h, err := s.serves(1); return err == nil && h.Seq >= head.Seq })
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			n := s.node(1)
			_, _, _ = n.Submit(context.Background(), s.entry(n.State().Head, 1))
		}
	}()
	// The joiner's attested calls answer slowly, as a real attestation
	// does: a head the giver read before one is stale after it.
	s.mu.Lock()
	s.onAttested = func(req *http.Request) {
		if req.URL.Host == "r2:8443" {
			time.Sleep(3 * T)
		}
	}
	s.mu.Unlock()
	time.Sleep(5 * T)
	start := time.Now()
	s.boot(2, buildA)
	var err error
	for _, err = s.serves(2); err != nil && time.Since(start) < 100*T; _, err = s.serves(2) {
		time.Sleep(T / 4)
	}
	took := time.Since(start)
	close(stop)
	wg.Wait()
	if took > 40*T {
		t.Fatalf("the restarted replica did not serve within %s under write load: %v", took, err)
	}
}

// A giver writes a joiner's member entry only at a head that accepts
// the builds the join was attested under, though it signs at the head it
// reads: here the joiner's build is evicted on the store while its join
// call runs.
func TestJoinerEvictedDuringItsJoinIsNotWritten(t *testing.T) {
	s := newSet(t, 3, buildA, buildA, buildB)
	s.bootstrap(buildA, buildB)
	var once sync.Once
	s.mu.Lock()
	s.onAttested = func(req *http.Request) {
		if req.Method == http.MethodGet && req.URL.Host == "r2:8443" {
			once.Do(func() { s.storeWrite(s.accepted(s.storeHead(), buildA)) })
		}
	}
	s.mu.Unlock()
	joiner := s.boot(2, buildB)
	time.Sleep(10 * T)
	for slot := range 2 {
		if s.node(slot).State().Members[2] == joiner.memberPEM {
			t.Fatalf("replica %d names a joiner of an evicted build as a member", slot)
		}
	}
}

// A replica not told its slot learns it from the endpoint that answers with
// its own member key, then joins and serves like any other. One that no
// endpoint answers for learns none and takes no keys.
func TestReplicaLearnsItsSlot(t *testing.T) {
	s := newSet(t, 3)
	s.unslotted = true
	for slot := range 3 {
		s.boot(slot, buildA)
	}
	stray, err := New(Config{Cluster: "lane", Endpoints: endpoints(3), Self: -1, Gossip: T, PeerTimeout: T, Peer: &http.Client{Transport: s.transport(nil, nil)}}, s.store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go stray.Run(ctx)
	s.waitFor("every replica to learn its slot", func() bool {
		return s.node(0).slot() == 0 && s.node(1).slot() == 1 && s.node(2).slot() == 2
	})
	s.bootstrap()
	if got, err := stray.slot(), stray.Start(Handoff{Entries: []cdschain.Entry{s.genesis}}); got != -1 || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a replica at no endpoint: slot %d, start %v", got, err)
	}
}
