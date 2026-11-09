// Package cdsha is a CDS replica of a fixed set in front of an untrusted
// store (docs/cds-ha.md): it verifies the chain, adopts newer verified heads
// from the store and its peers, writes the store forward, and halts on two
// entries at one seq. It persists nothing.
package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// Config is one replica's place in its set and the knobs of its rounds.
type Config struct {
	Cluster   string
	Endpoints []string
	// Self is this replica's slot; -1 learns it (Run, learnSlot).
	Self int
	// OperatorKeys are the launch file's: a genesis must be signed by one.
	OperatorKeys []*ecdsa.PublicKey
	// Gossip is T: a replica refuses without answers from a majority to
	// pings it sent within T.
	Gossip       time.Duration
	PeerTimeout  time.Duration
	StoreTimeout time.Duration
	WarnEntries  int
	WarnBytes    int64
	Mesh         *issuer.MeshCA
	// Peer reaches the other replicas for gossip, which member signatures
	// authenticate; Attested(pins) admits only a replica whose attested
	// build pins name (key handoff).
	Peer     *http.Client
	Attested func(armtls.Pins) (*http.Client, error)
	// SelfCheck reports whether this replica's own attestation passes one
	// build's pins; an error is "no answer", which evicts nothing.
	SelfCheck func(ctx context.Context, measurements string) (bool, error)
	// OnState is told every state the replica adopts.
	OnState func(*cdschain.State)
	// Validate checks an entry's payload beyond the chain's rules.
	Validate func(cdschain.Body) error
}

// Errors a write or a read maps to its HTTP status.
var (
	ErrUnavailable = errors.New("unconfirmed")
	ErrInvalid     = errors.New("invalid entry")
	// ErrMayHaveCommitted is a write after which the store may hold the entry.
	ErrMayHaveCommitted = errors.New("the write may have been applied")
)

// Fork is two entries at one seq; the replica halts until a resolve.
type Fork struct {
	Seq    uint64        `json:"seq"`
	Mine   cdschain.Hash `json:"mine"`
	Theirs cdschain.Hash `json:"theirs"`
	Source string        `json:"source"`
}

type heard struct {
	key string
	at  time.Time
	seq uint64 // the head seq the pong named
}

// Replica is one CDS replica's memory.
type Replica struct {
	cfg       Config
	member    *ecdsa.PrivateKey
	memberPEM string
	self      atomic.Int64 // the slot, -1 until learnt

	mu         sync.Mutex
	store      Store
	credential []byte
	storeErr   string
	storeSeq   uint64 // the head seq the last store read named
	chain      []cdschain.Entry
	state      *cdschain.State // nil until genesis or a handoff
	heard      map[int]heard
	fork       *Fork
	dropped    map[cdschain.Hash]uint64
	done       []cdschain.Head
	own        map[string]bool // build measurements -> this replica's attestation passes them
	warned     [2]int64
	handing    map[int]bool
	// forwardFails failed write-forwards in a row; none is tried before
	// forwardAfter.
	forwardFails int
	forwardAfter time.Time
	// joining: holds no chain, but its store does; it is no genesis.
	joining bool
	// cut is the seq a resolve cut the chain at: the kept entry there may be
	// a done write, so the replica serves again only once it holds one.
	cut uint64
}

// New starts a pending replica with a fresh member key.
func New(cfg Config, store Store) (*Replica, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	memberPEM, err := cdschain.PublicKeyPEM(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	r := &Replica{
		cfg: cfg, member: key, memberPEM: memberPEM, store: store,
		heard: map[int]heard{}, dropped: map[cdschain.Hash]uint64{}, own: map[string]bool{}, handing: map[int]bool{},
	}
	r.self.Store(int64(cfg.Self))
	return r, nil
}

func (r *Replica) slot() int { return int(r.self.Load()) }

// learnSlot asks every endpoint for its status and takes the slot whose
// answer names this replica's own member key, a fresh random key no other
// instance holds. The answer is not authenticated, and need not be: the
// host routes the endpoints, so it already decides which instance answers
// at a slot, and a giver hands a slot over only after an attested join at
// that slot's endpoint. A wrong slot costs availability, never the keys.
func (r *Replica) learnSlot(ctx context.Context) bool {
	for slot := range r.cfg.Endpoints {
		var s Status
		cctx, cancel := context.WithTimeout(ctx, r.cfg.PeerTimeout)
		err := Call(cctx, r.cfg.Peer, http.MethodGet, r.url(slot, StatusPath), nil, &s)
		cancel()
		if err == nil && s.Member == r.memberPEM {
			r.self.Store(int64(slot))
			slog.Info("CDS replica learnt its slot", "slot", slot, "endpoint", r.cfg.Endpoints[slot])
			return true
		}
	}
	return false
}

// State is the held state, nil while pending.
func (r *Replica) State() *cdschain.State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Identity is the chain identity this replica answers a client pinning pin
// with (C-ID): pin itself when its chain holds that entry ("<seq>:<hash>"),
// else its genesis hash; "" with no chain.
func (r *Replica) Identity(pin string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == nil {
		return ""
	}
	if h, err := cdschain.ParsePin(pin); err == nil && r.holdsLocked(h) {
		return pin
	}
	return r.state.Genesis.String()
}

func majority(n int) int { return n/2 + 1 }

// servingLocked is why the replica serves nothing now, nil when it serves.
func (r *Replica) servingLocked() error {
	switch {
	case r.state == nil:
		return fmt.Errorf("%w: the replica holds no chain yet", ErrUnavailable)
	case r.fork != nil && r.fork.Seq == 0:
		return fmt.Errorf("%w: halted: %s holds a different genesis; re-root under a new cluster ID", ErrUnavailable, r.fork.Source)
	case r.fork != nil:
		return fmt.Errorf("%w: halted: two entries at seq %d (%s, %s from %s); resolve the fork", ErrUnavailable, r.fork.Seq, r.fork.Mine, r.fork.Theirs, r.fork.Source)
	case r.state.Members[r.slot()] != r.memberPEM:
		return fmt.Errorf("%w: this replica is not the member of slot %d", ErrUnavailable, r.slot())
	case r.buildLocked() == "":
		return fmt.Errorf("%w: this replica's build is not accepted at head %d", ErrUnavailable, r.state.Head.Seq)
	case !r.freshLocked():
		return fmt.Errorf("%w: no gossip from enough replicas within %v", ErrUnavailable, r.cfg.Gossip)
	case r.state.Head.Seq < r.cut:
		return fmt.Errorf("%w: a resolve cut the chain at seq %d; it serves again once it holds the kept entry", ErrUnavailable, r.cut)
	}
	return nil
}

// memberAheadLocked is the highest head seq a current member's pong named
// within T, if it is above the store's last read head; else 0.
func (r *Replica) memberAheadLocked() uint64 {
	ahead := uint64(0)
	for slot, h := range r.heard {
		if h.key == r.state.Members[slot] && time.Since(h.at) < r.cfg.Gossip && h.seq > r.storeSeq {
			ahead = max(ahead, h.seq)
		}
	}
	return ahead
}

// freshLocked: a majority, counting self, answered a ping sent within T.
func (r *Replica) freshLocked() bool {
	recent := 1
	for slot, h := range r.heard {
		if h.key == r.state.Members[slot] && time.Since(h.at) < r.cfg.Gossip {
			recent++
		}
	}
	return recent >= majority(len(r.cfg.Endpoints))
}

// buildLocked is the version of an accepted build this replica's own
// attestation passes, "" when none does.
func (r *Replica) buildLocked() string {
	for _, b := range r.state.Accepted {
		if r.own[b.Measurements] {
			return b.Version
		}
	}
	return ""
}

// Current refreshes from the store and returns the state the replica
// serves: the store read comes first, every check after it.
func (r *Replica) Current(ctx context.Context) (*cdschain.State, error) {
	if _, err := r.refresh(ctx); err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.servingLocked(); err != nil {
		return nil, err
	}
	return r.state, nil
}

// refresh reads the store's head and reconciles: adopt a newer verified
// chain, write a store that is behind forward, halt on another branch. It
// returns the head bytes the store now holds.
func (r *Replica) refresh(ctx context.Context) ([]byte, error) {
	r.mu.Lock()
	st, state := r.store, r.state
	r.mu.Unlock()
	if state == nil {
		return nil, fmt.Errorf("%w: the replica holds no chain yet", ErrUnavailable)
	}
	if st == nil {
		return nil, fmt.Errorf("%w: the store is unreachable: no store credential yet", ErrUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.StoreTimeout)
	defer cancel()
	raw, err := st.GetHead(ctx)
	if err == nil {
		raw, err = r.reconcile(ctx, st, raw)
	}
	switch {
	case errors.Is(err, ErrHalted):
		r.mu.Lock()
		err = fmt.Errorf("%w: %w", ErrHalted, r.servingLocked())
		r.mu.Unlock()
	case err != nil && !errors.Is(err, ErrUnavailable):
		err = fmt.Errorf("%w: the store is unreachable: %w", ErrUnavailable, err)
	}
	r.mu.Lock()
	if was := r.storeErr; err == nil {
		r.storeErr = ""
	} else if r.storeErr = err.Error(); r.storeErr != was {
		slog.Error("CDS replica refuses: the store read failed", "error", err)
	}
	r.mu.Unlock()
	return raw, err
}

func (r *Replica) reconcile(ctx context.Context, st Store, raw []byte) ([]byte, error) {
	if raw == nil {
		// An empty store: wiped, or before entry 0 (written create-if-absent).
		r.mu.Lock()
		r.storeSeq = 0
		r.mu.Unlock()
		return r.writeForward(ctx, st, nil, 0)
	}
	var h cdschain.Head
	if err := cdschain.DecodeStrict(raw, &h); err != nil || h.V != cdschain.Version || h.Cluster != r.cfg.Cluster {
		return nil, fmt.Errorf("%w: the CDS store names a head that does not verify", ErrUnavailable)
	}
	r.mu.Lock()
	r.storeSeq = h.Seq
	held, from := r.state.Head, r.fromLocked(h.Seq)
	inChain := r.holdsLocked(h)
	r.mu.Unlock()
	switch {
	case inChain && h.Seq == held.Seq:
		return raw, nil
	case inChain:
		return r.writeForward(ctx, st, raw, h.Seq+1)
	}
	entries, err := walk(ctx, st, h, from, r.meets)
	if err != nil {
		return nil, fmt.Errorf("%w: the CDS store names a head that does not verify: %w", ErrUnavailable, err)
	}
	if err := r.adopt(entries, "the store"); errors.Is(err, errDropped) {
		// The store is on a branch a resolve dropped: write ours over it.
		return r.writeForward(ctx, st, raw, from)
	} else if err != nil {
		return nil, err
	}
	return raw, nil
}

// fromLocked is the lowest seq a fetch of a head at seq must start at to
// meet this replica's chain, or a branch a resolve dropped.
func (r *Replica) fromLocked(seq uint64) uint64 {
	from := min(seq, r.state.Head.Seq+1)
	for _, s := range r.dropped {
		from = min(from, s)
	}
	return from
}

// holdsLocked: this replica's chain holds h's entry.
func (r *Replica) holdsLocked(h cdschain.Head) bool {
	return h.Seq < uint64(len(r.chain)) && r.chain[h.Seq].Hash() == h.Hash
}

func (r *Replica) hashAtLocked(seq uint64) cdschain.Hash {
	if seq >= uint64(len(r.chain)) {
		return cdschain.Hash{}
	}
	return r.chain[seq].Hash()
}

// maxWalk bounds one walk down the store's prev links: a head that
// claims any seq costs at most this many reads and their bytes.
const (
	maxWalk      = 4096
	maxWalkBytes = 64 << 20
)

// meets: the entry at seq whose prev is prev follows this replica's chain.
func (r *Replica) meets(seq uint64, prev cdschain.Hash) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return seq > 0 && r.holdsLocked(cdschain.Head{Seq: seq - 1, Hash: prev})
}

// walk reads the entries from h down by their prev links, in chain order,
// to seq from or to the first that meets the chain, whichever comes first.
// Each one must be at the seq its successor names.
func walk(ctx context.Context, st Store, h cdschain.Head, from uint64, meets func(seq uint64, prev cdschain.Hash) bool) ([]cdschain.Entry, error) {
	var out []cdschain.Entry
	want, seq, size := h.Hash, h.Seq, 0
	for {
		if len(out) == maxWalk || size > maxWalkBytes {
			return nil, fmt.Errorf("the store head is more than %d entries or %d bytes ahead", maxWalk, maxWalkBytes)
		}
		data, err := st.GetEntry(ctx, want)
		if err != nil {
			return nil, err
		}
		if data == nil {
			return nil, fmt.Errorf("the store holds no entry %s", want)
		}
		e, err := cdschain.ParseEntry(data)
		if err != nil {
			return nil, err
		}
		b, err := e.Decode()
		if err != nil || e.Hash() != want || b.Seq != seq {
			return nil, fmt.Errorf("the store's entry %s is not the entry at seq %d", want, seq)
		}
		out, size = append(out, e), size+len(data)
		if seq == from || meets(seq, b.Prev) {
			slices.Reverse(out)
			return out, nil
		}
		want, seq = b.Prev, seq-1
	}
}

var (
	errDropped = errors.New("on a branch a resolve dropped")
	// ErrHalted is a replica halted on a fork.
	ErrHalted = errors.New("halted on a fork")
)

// adopt takes entries in chain order that meet this replica's chain. An
// entry at a seq it holds must be the one it holds, else the replica halts;
// a newer one must verify after its head.
func (r *Replica) adopt(entries []cdschain.Entry, source string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	defer func() {
		if changed {
			r.adoptedLocked()
		}
	}()
	for _, e := range entries {
		b, err := e.Decode()
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalid, source, err)
		}
		hash := e.Hash()
		if _, ok := r.dropped[hash]; ok {
			return errDropped
		}
		if b.Seq <= r.state.Head.Seq {
			if r.hashAtLocked(b.Seq) != hash {
				r.haltLocked(Fork{Seq: b.Seq, Mine: r.hashAtLocked(b.Seq), Theirs: hash, Source: source})
				return ErrHalted
			}
			continue
		}
		next, err := r.state.Apply(e)
		if errors.Is(err, cdschain.ErrNotNext) {
			r.haltLocked(Fork{Seq: r.state.Head.Seq, Mine: r.state.Head.Hash, Theirs: b.Prev, Source: source})
			return ErrHalted
		}
		if err != nil {
			return fmt.Errorf("%w: %s: %w", ErrInvalid, source, err)
		}
		r.chain, r.state, changed = append(r.chain, e), next, true
	}
	return nil
}

func (r *Replica) haltLocked(f Fork) {
	if r.fork == nil {
		r.fork = &f
		slog.Error("CDS replica HALTED; issuance and writes stop until an operator resolves the fork", "reason", r.servingLocked())
	}
}

// adoptedLocked tells the CDS the new state and warns as the chain grows
// (v1 never prunes it).
func (r *Replica) adoptedLocked() {
	s := r.state
	for i, size := range []int64{int64(s.Entries), s.Bytes} {
		limit := []int64{int64(r.cfg.WarnEntries), r.cfg.WarnBytes}[i]
		if limit > 0 && size/limit > r.warned[i] {
			r.warned[i] = size / limit
			slog.Error("CDS chain passed its size warning; v1 never prunes it", "entries", s.Entries, "bytes", s.Bytes)
		}
	}
	if r.cfg.OnState != nil {
		r.cfg.OnState(s)
	}
}

// writeForward puts this replica's entries from seq from on and moves the
// store's head from old to its own, every forwardBatch entries, so a
// re-seed cut short by the store timeout keeps what it wrote. A lost race
// is left to the next read. After a failure it backs off (forwardBackoff,
// doubling to maxForwardBackoff) instead of retrying on every read.
func (r *Replica) writeForward(ctx context.Context, st Store, old []byte, from uint64) ([]byte, error) {
	r.mu.Lock()
	if wait := time.Until(r.forwardAfter); wait > 0 {
		r.mu.Unlock()
		return nil, fmt.Errorf("%w: the CDS store is behind this replica; writing it forward again in %s", ErrUnavailable, wait.Round(time.Millisecond))
	}
	entries, head := slices.Clone(r.chain[min(from, uint64(len(r.chain))):]), r.state.Head
	r.mu.Unlock()
	raw, err := forward(ctx, st, old, entries, head)
	r.mu.Lock()
	if err != nil {
		r.forwardFails++
		r.forwardAfter = time.Now().Add(min(forwardBackoff<<min(r.forwardFails-1, 8), maxForwardBackoff))
	} else {
		r.forwardFails = 0
	}
	r.mu.Unlock()
	if err == nil && !bytes.Equal(raw, old) {
		slog.Warn("CDS store was behind this replica; wrote it forward", "store_head_from", from, "head", head.Seq)
	}
	return raw, err
}

const (
	forwardBatch      = 64
	forwardBackoff    = 250 * time.Millisecond
	maxForwardBackoff = 10 * time.Second
)

// forward puts entries, which end at head, and moves the store's head from
// old to head, and to the entry ending each full batch on the way. It
// returns the head bytes the store holds, old if another writer moved it.
func forward(ctx context.Context, st Store, old []byte, entries []cdschain.Entry, head cdschain.Head) ([]byte, error) {
	cas := func(at cdschain.Head) (bool, error) {
		next, err := json.Marshal(at)
		if err == nil {
			err = st.CASHead(ctx, old, next)
		}
		if errors.Is(err, ErrConflict) {
			return false, nil
		}
		if err == nil {
			old = next
		}
		return err == nil, err
	}
	for i, e := range entries {
		data, err := e.Encode()
		if err == nil {
			err = st.PutEntry(ctx, e.Hash(), data)
		}
		if err != nil {
			return nil, err
		}
		if (i+1)%forwardBatch == 0 && i+1 < len(entries) {
			// INVARIANT: the store's head names an entry whose whole chain
			// the store holds: every entry up to it is put before it.
			at := head
			at.Seq, at.Hash = head.Seq-uint64(len(entries)-1-i), e.Hash()
			moved, err := cas(at)
			if err != nil {
				return nil, err
			}
			if !moved {
				return old, nil
			}
		}
	}
	if _, err := cas(head); err != nil {
		return nil, err
	}
	return old, nil
}

// Submit writes an operator's entry; the replica must be serving.
func (r *Replica) Submit(ctx context.Context, e cdschain.Entry) (cdschain.Head, bool, error) {
	return r.commit(ctx, func(*cdschain.State) (cdschain.Entry, error) { return e, nil }, true)
}

// swap verifies entry(state), for the state at the store's head, after that
// head and moves the store's head to it; with serving, only while the
// replica serves, checked after the store read. A lost compare-and-swap
// is retried after a fresh read, so 409 means the verified head moved past
// the entry's prev, not that the store's bytes did. An entry built from the
// state it follows (a giver's member entry) never meets a 409.
func (r *Replica) swap(ctx context.Context, entry func(*cdschain.State) (cdschain.Entry, error), serving bool) (cdschain.Head, cdschain.Entry, error) {
	var e cdschain.Entry
	for attempt := 1; ; attempt++ {
		raw, err := r.refresh(ctx)
		if err != nil {
			return cdschain.Head{}, e, err
		}
		r.mu.Lock()
		state, halted, st, ahead := r.state, r.fork != nil, r.store, r.memberAheadLocked()
		var notServing error
		if serving && !halted {
			notServing = r.servingLocked()
		}
		r.mu.Unlock()
		if halted {
			return cdschain.Head{}, e, fmt.Errorf("%w: %w", ErrUnavailable, ErrHalted)
		}
		if notServing != nil {
			return cdschain.Head{}, e, notServing
		}
		if ahead > 0 {
			// The store may withhold from this replica: a write on it could
			// take a seq the set already took (a fork, then a halt).
			return cdschain.Head{}, e, fmt.Errorf("%w: a member gossiped head %d, above the store head this replica read", ErrUnavailable, ahead)
		}
		if e, err = entry(state); err != nil {
			return cdschain.Head{}, e, err
		}
		b, derr := e.Decode()
		next, err := state.Apply(e)
		if errors.Is(err, cdschain.ErrNotNext) && derr == nil && b.Seq > state.Head.Seq+1 {
			// The entry follows a head this replica has not reached: it is
			// behind, which says nothing about the head having moved.
			return cdschain.Head{}, e, fmt.Errorf("%w: this replica is behind head %d the entry follows", ErrUnavailable, b.Seq-1)
		}
		if errors.Is(err, cdschain.ErrNotNext) {
			return cdschain.Head{}, e, fmt.Errorf("%w: %w; re-read the head and resubmit", ErrConflict, err)
		}
		if err == nil && r.cfg.Validate != nil {
			if err = derr; err == nil {
				err = r.cfg.Validate(b)
			}
		}
		if err != nil {
			return cdschain.Head{}, e, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		data, err := e.Encode()
		if err != nil {
			return cdschain.Head{}, e, err
		}
		head, _ := json.Marshal(next.Head)
		sctx, cancel := context.WithTimeout(ctx, r.cfg.StoreTimeout)
		if err = st.PutEntry(sctx, e.Hash(), data); err == nil {
			err = st.CASHead(sctx, raw, head)
		} else {
			err = fmt.Errorf("%w: the store is unreachable: %w", ErrUnavailable, err)
		}
		cancel()
		switch {
		case errors.Is(err, ErrConflict) && attempt < 3:
			continue
		case errors.Is(err, ErrConflict):
			return cdschain.Head{}, e, fmt.Errorf("%w: the store head keeps moving", ErrUnavailable)
		case errors.Is(err, ErrUnavailable):
			return cdschain.Head{}, e, err
		case err != nil:
			return next.Head, e, fmt.Errorf("%w: %w", ErrMayHaveCommitted, err)
		}
		return next.Head, e, nil
	}
}

// commit swaps an entry in (swap) and only after that CAS succeeds holds it.
// It is done (true) only when a majority, counting self, holds it after one
// round.
func (r *Replica) commit(ctx context.Context, entry func(*cdschain.State) (cdschain.Entry, error), serving bool) (cdschain.Head, bool, error) {
	next, e, err := r.swap(ctx, entry, serving)
	if err != nil {
		return next, false, err
	}
	if err := r.adopt([]cdschain.Entry{e}, "this replica's write"); err != nil {
		return next, false, nil
	}
	holders := 1
	for _, h := range r.round(ctx) {
		if h.Seq >= next.Seq {
			holders++
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	confirmed := holders >= majority(len(r.cfg.Endpoints)) && r.fork == nil
	if confirmed {
		r.done = append(r.done, next)
	}
	return next, confirmed, nil
}

// Resolve settles a fork at seq: a replica holding drop there drops its
// entries from seq on; every replica (also one behind seq) then ignores
// drop's branch and clears its halt. The caller (the operator CLI) has
// checked that nothing dropped was answered done.
func (r *Replica) Resolve(seq uint64, keep, drop cdschain.Hash) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state == nil {
		return fmt.Errorf("%w: the replica holds no chain yet", ErrUnavailable)
	}
	if seq == 0 {
		return fmt.Errorf("%w: the genesis cannot be dropped; re-root instead", ErrInvalid)
	}
	// A replica holding the dropped entry drops it, whether or not it saw
	// the kept one; one holding a third entry at seq refuses (an operator
	// typo, or a fork this resolution does not settle).
	if held := r.hashAtLocked(seq); keep == drop || (held != drop && held != keep && held != (cdschain.Hash{})) {
		return fmt.Errorf("%w: the resolution names neither entry this replica holds at seq %d", ErrInvalid, seq)
	}
	holdsDrop := r.holdsLocked(cdschain.Head{Seq: seq, Hash: drop})
	for _, d := range r.done {
		if d.Seq >= seq && holdsDrop {
			return fmt.Errorf("%w: this replica answered a write done at seq %d on the dropped branch", ErrInvalid, d.Seq)
		}
	}
	if holdsDrop {
		for _, e := range r.chain[seq:] {
			r.dropped[e.Hash()] = seq
		}
		state, err := cdschain.Verify(r.chain[:seq])
		if err != nil {
			return err
		}
		r.chain, r.state, r.cut = r.chain[:seq], state, seq
		r.adoptedLocked()
	}
	r.dropped[drop] = seq
	r.fork = nil
	slog.Warn("CDS fork resolved by the operator", "audit", true, "seq", seq, "dropped", drop)
	return nil
}
