package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// Note is one gossip message, a ping or its pong, signed with the sender's
// member key. A ping asks for the entries from From on; a pong echoes the
// ping's nonce and carries them.
type Note struct {
	Cluster string        `json:"cluster"`
	Slot    int           `json:"slot"`
	Nonce   string        `json:"nonce"`
	Head    cdschain.Head `json:"head"`
	From    uint64        `json:"from"`
	// Pending is a replica that holds no chain: a giver hands it the keys.
	Pending bool `json:"pending,omitempty"`
}

// Gossip is a signed note and, in a pong, the entries it asked for.
type Gossip struct {
	Note    cdschain.Entry   `json:"note"`
	Entries []cdschain.Entry `json:"entries,omitempty"`
}

// maxGossipEntries bounds the entries one pong carries.
const maxGossipEntries = 4 << 20

func (r *Replica) sign(n Note) (Gossip, error) {
	body, err := json.Marshal(n)
	if err != nil {
		return Gossip{}, err
	}
	e, err := cdschain.Sign(r.member, cdschain.Body{Cluster: r.cfg.Cluster, Type: "gossip", Payload: body})
	return Gossip{Note: e}, err
}

// open decodes a note, verified under key; "" only reads a pending
// replica's claim, which the handoff then checks by attestation.
func open(g Gossip, key string) (Note, error) {
	var n Note
	if key != "" {
		pub, err := cdschain.ParseKey(key)
		if err == nil {
			err = g.Note.VerifySignature([]*ecdsa.PublicKey{pub})
		}
		if err != nil {
			return n, err
		}
	}
	b, err := g.Note.Decode()
	if err == nil {
		err = cdschain.DecodeStrict(b.Payload, &n)
	}
	return n, err
}

// round pings every other slot once and returns, by slot, the heads of the
// members whose pong came back within T and is consistent with this
// replica's chain after it adopted what the pong carried.
func (r *Replica) round(ctx context.Context) map[int]cdschain.Head {
	r.mu.Lock()
	if r.state == nil {
		r.mu.Unlock()
		return nil
	}
	ping := Note{Cluster: r.cfg.Cluster, Slot: r.slot(), Nonce: rand.Text(), Head: r.state.Head, From: r.fromLocked(r.state.Head.Seq + 1)}
	r.mu.Unlock()
	signed, err := r.sign(ping)
	if err != nil {
		return nil
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	heads := map[int]cdschain.Head{}
	for slot := range r.cfg.Endpoints {
		if slot == r.slot() {
			continue
		}
		wg.Go(func() {
			if h, ok := r.exchange(ctx, slot, signed, ping.Nonce); ok {
				mu.Lock()
				heads[slot] = h
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return heads
}

func (r *Replica) exchange(ctx context.Context, slot int, ping Gossip, nonce string) (cdschain.Head, bool) {
	sent := time.Now()
	ctx, cancel := context.WithTimeout(ctx, min(r.cfg.Gossip, r.cfg.PeerTimeout))
	defer cancel()
	var pong Gossip
	if err := Call(ctx, r.cfg.Peer, http.MethodPost, r.url(slot, GossipPath), ping, &pong); err != nil {
		slog.Debug("CDS gossip: no answer", "slot", slot, "error", err)
		return cdschain.Head{}, false
	}
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if claimed, err := open(pong, ""); err == nil && claimed.Pending {
		go r.handoff(context.WithoutCancel(ctx), slot)
		return cdschain.Head{}, false
	}
	n, err := open(pong, state.Members[slot])
	// Only an answer to this round's ping counts; the call's timeout
	// is at most T from sending it.
	if err != nil || n.Cluster != r.cfg.Cluster || n.Slot != slot || n.Nonce != nonce {
		return cdschain.Head{}, false
	}
	if err := r.learn(n.Head, pong.Entries, fmt.Sprintf("the replica of slot %d", slot)); err != nil {
		return cdschain.Head{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.heard[slot] = heard{key: state.Members[slot], at: sent, seq: n.Head.Seq}
	return n.Head, true
}

// learn takes a member's head and the entries it sent: it adopts them, and
// the head must then be in this replica's chain. A head at a seq it holds
// with another hash is a fork.
func (r *Replica) learn(h cdschain.Head, entries []cdschain.Entry, source string) error {
	if err := r.adopt(entries, source); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.holdsLocked(h):
		return nil
	case h.Seq <= r.state.Head.Seq && len(r.dropped) == 0:
		r.haltLocked(Fork{Seq: h.Seq, Mine: r.hashAtLocked(h.Seq), Theirs: h.Hash, Source: source})
		return ErrHalted
	}
	return errors.New("the head is not in this replica's chain")
}

// HandleGossip answers a member's ping: it learns from the pinger's head
// through the store, then answers its own head and the entries asked for.
func (r *Replica) HandleGossip(ctx context.Context, ping Gossip) (Gossip, error) {
	r.mu.Lock()
	state := r.state
	r.mu.Unlock()
	if state == nil {
		return r.sign(Note{Cluster: r.cfg.Cluster, Slot: r.slot(), Pending: true})
	}
	claimed, err := open(ping, "")
	if err != nil || claimed.Slot < 0 || claimed.Slot >= len(state.Members) {
		return Gossip{}, fmt.Errorf("%w: gossip from no slot", ErrInvalid)
	}
	n, err := open(ping, state.Members[claimed.Slot])
	if err != nil || n.Cluster != r.cfg.Cluster {
		return Gossip{}, fmt.Errorf("%w: gossip not signed by the member of slot %d", ErrInvalid, claimed.Slot)
	}
	if n.Head.Seq > state.Head.Seq {
		// The pinger wrote it through the store; a withheld store leaves
		// this replica behind, and the pinger then does not count it.
		_, _ = r.refresh(ctx)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pong := Gossip{}
	size := 0
	from := n.From
	if r.holdsLocked(n.Head) {
		// The pinger's chain is this one up to its head.
		from = n.Head.Seq + 1
	}
	for _, e := range r.chain[min(from, uint64(len(r.chain))):] {
		if size += len(e.Body) + len(e.Sig); size > maxGossipEntries && len(pong.Entries) > 0 {
			break
		}
		pong.Entries = append(pong.Entries, e)
	}
	signed, err := r.sign(Note{Cluster: r.cfg.Cluster, Slot: r.slot(), Nonce: n.Nonce, Head: r.state.Head})
	signed.Entries = pong.Entries
	return signed, err
}

// Run gossips every T/2, so a pong answered within the window renews
// freshness before the previous one expires; a round waiting on a slow peer
// never delays the next. It also reads the store, so an idle replica still
// writes it forward and notices another chain in it.
func (r *Replica) Run(ctx context.Context) {
	ticker := time.NewTicker(r.cfg.Gossip / 2)
	defer ticker.Stop()
	for r.slot() < 0 && !r.learnSlot(ctx) {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
	for {
		go r.round(ctx)
		_, _ = r.refresh(ctx)
		r.checkBuild(ctx)
		r.findChain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// checkBuild holds this replica's own attestation to each accepted build
// not judged yet. A check that gets no answer is retried and evicts nothing.
func (r *Replica) checkBuild(ctx context.Context) {
	r.mu.Lock()
	var todo []string
	if r.state != nil {
		for _, b := range r.state.Accepted {
			if _, judged := r.own[b.Measurements]; !judged {
				todo = append(todo, b.Measurements)
			}
		}
	}
	r.mu.Unlock()
	for _, m := range todo {
		ok, err := r.cfg.SelfCheck(ctx, m)
		if err != nil {
			slog.Warn("CDS replica cannot check its own build yet", "error", err)
			continue
		}
		r.mu.Lock()
		r.own[m] = ok
		r.mu.Unlock()
	}
}

// Pending is what a replica that holds no chain publishes: its member key
// and the CA key a genesis would name.
type Pending struct {
	Cluster   string   `json:"cluster"`
	Endpoints []string `json:"endpoints"`
	CAKey     string   `json:"caKey"`
	Member    string   `json:"member"`
}

// findChain records whether the store of a replica that holds no chain
// already holds one: it then waits for a giver and is no genesis.
func (r *Replica) findChain(ctx context.Context) {
	r.mu.Lock()
	st, pending := r.store, r.state == nil
	r.mu.Unlock()
	if !pending || st == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, r.cfg.StoreTimeout)
	defer cancel()
	if head, err := st.GetHead(ctx); err == nil && head != nil {
		r.mu.Lock()
		r.joining = true
		r.mu.Unlock()
	}
}

// Pending is nil once the replica holds a chain, or (genesis) found one in
// the store.
func (r *Replica) Pending(genesis bool) (*Pending, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != nil || (genesis && r.joining) {
		return nil, nil
	}
	ca, err := cdschain.PublicKeyPEM(r.cfg.Mesh.Current().CA.Key.Public())
	return &Pending{Cluster: r.cfg.Cluster, Endpoints: r.cfg.Endpoints, CAKey: ca, Member: r.memberPEM}, err
}

// Handoff is what a giver hands a joiner: the chain, the CA, the branches a
// resolve dropped and the store credential.
type Handoff struct {
	Entries    []cdschain.Entry         `json:"entries"`
	CACert     []byte                   `json:"caCert"`
	CAKey      []byte                   `json:"caKey"`
	Dropped    map[cdschain.Hash]uint64 `json:"dropped,omitempty"`
	Credential []byte                   `json:"credential,omitempty"`
}

// handoff gives the keys to the pending replica at slot. Its attested
// build must be accepted at the head the member entry follows and again at
// the head the keys leave at: a new client, so a new handshake, under the
// pins of that head. The giver's own build is not checked (U1).
func (r *Replica) handoff(ctx context.Context, slot int) {
	r.mu.Lock()
	busy, state := r.handing[slot], r.state
	r.handing[slot] = true
	r.mu.Unlock()
	if busy {
		return
	}
	if err := r.give(ctx, slot, state); err != nil {
		slog.Warn("CDS key handoff did not complete", "slot", slot, "error", err)
	}
	r.mu.Lock()
	delete(r.handing, slot)
	r.mu.Unlock()
}

// errMemberWritten: the joiner is already the member of its slot.
var errMemberWritten = errors.New("the joiner is already the member")

func (r *Replica) give(ctx context.Context, slot int, state *cdschain.State) error {
	var p Pending
	if err := r.attestedCall(ctx, state, http.MethodGet, r.url(slot, JoinPath), nil, &p); err != nil {
		return err
	}
	if p.Cluster != r.cfg.Cluster {
		return fmt.Errorf("the joiner is of cluster %q", p.Cluster)
	}
	if state.Members[slot] != p.Member {
		// Signed at the head the write reads, so other writers moving the
		// head while the attested join ran do not make it lose; but only
		// while the builds the join was attested under are the accepted
		// ones.
		member := func(at *cdschain.State) (cdschain.Entry, error) {
			switch {
			case at.Members[slot] == p.Member:
				return cdschain.Entry{}, errMemberWritten
			case !slices.Equal(at.Accepted, state.Accepted):
				return cdschain.Entry{}, fmt.Errorf("%w: the accepted builds changed after the join was attested", ErrConflict)
			}
			payload, _ := json.Marshal(cdschain.Member{Slot: slot, Key: p.Member})
			return cdschain.Sign(r.member, cdschain.Body{Cluster: r.cfg.Cluster, Seq: at.Head.Seq + 1, Prev: at.Head.Hash, Type: cdschain.TypeMember, Payload: payload})
		}
		if _, confirmed, err := r.commit(ctx, member, false); !errors.Is(err, errMemberWritten) && (err != nil || !confirmed) {
			return fmt.Errorf("member entry for slot %d not done: %v", slot, err)
		}
	}
	// The keys leave at the store's head, which may hold an entry gossip
	// has not brought yet.
	if _, err := r.refresh(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	h := Handoff{Entries: slices.Clone(r.chain), Dropped: maps.Clone(r.dropped), Credential: r.credential}
	state, halted := r.state, r.fork != nil
	r.mu.Unlock()
	// A halted replica hands nothing over.
	if halted || state.Members[slot] != p.Member {
		return errors.New("the joiner is not the member at the head the keys would leave at")
	}
	certPEM, keyPEM, err := r.cfg.Mesh.Current().CA.PEM()
	if err != nil {
		return err
	}
	// The key is sealed to the member key the joiner showed on the attested
	// join call: only that instance can open it, whichever instance the
	// host routes this connection to.
	h.CACert = certPEM
	sealed, err := sealToMember(p.Member, r.cfg.Cluster, keyPEM)
	clear(keyPEM)
	if err != nil {
		return err
	}
	h.CAKey = sealed
	if err := r.attestedCall(ctx, state, http.MethodPost, r.url(slot, HandoffPath), h, nil); err != nil {
		return err
	}
	slog.Info("CDS handed the keys to a joiner", "audit", true, "slot", slot, "head", state.Head.Seq)
	return nil
}

// attestedCall calls a replica over a fresh client pinned to state's builds.
func (r *Replica) attestedCall(ctx context.Context, state *cdschain.State, method, url string, in, out any) error {
	client, err := r.cfg.Attested(armtls.Pins(state.Pins().Policy()))
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	return Call(ctx, client, method, url, in, out)
}

// Start makes a pending replica a member: a genesis (no CA key: its own CA
// must be the one entry 0 names) or a handoff. The chain must start at a
// genesis signed by a launch operator key, for this cluster and endpoints,
// and name this replica's member key at its slot.
func (r *Replica) Start(h Handoff) error {
	if r.slot() < 0 {
		return fmt.Errorf("%w: this replica has not learnt its slot yet", ErrUnavailable)
	}
	state, err := cdschain.Verify(h.Entries)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	switch {
	case h.Entries[0].VerifySignature(r.cfg.OperatorKeys) != nil:
		return fmt.Errorf("%w: the genesis is not signed by a launch operator key", ErrInvalid)
	case state.Cluster != r.cfg.Cluster || !slices.Equal(state.Endpoints, r.cfg.Endpoints):
		return fmt.Errorf("%w: the chain is of another cluster or endpoint list", ErrInvalid)
	case state.Members[r.slot()] != r.memberPEM:
		return fmt.Errorf("%w: the chain does not name this replica the member of slot %d", ErrInvalid, r.slot())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != nil {
		return ErrNotPending
	}
	if h.CAKey == nil {
		if r.joining {
			return ErrNotPending
		}
		if !state.CAKey.Equal(r.cfg.Mesh.Current().CA.Key.Public()) {
			return fmt.Errorf("%w: the genesis names another CA key", ErrInvalid)
		}
	} else if err := r.adoptCA(h.CACert, h.CAKey, state.CAKey); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.chain, r.state = h.Entries, state
	for k, v := range h.Dropped {
		r.dropped[k] = v
	}
	if h.Credential != nil && r.store == nil {
		if err := r.setCredentialLocked(h.Credential); err != nil {
			slog.Warn("CDS replica refused the handed store credential", "error", err)
		}
	}
	r.adoptedLocked()
	slog.Info("CDS replica holds the chain", "audit", true, "head", state.Head.Seq, "genesis", state.Genesis)
	return nil
}

const handoffInfo = "c8s-cds-handoff/v1/"

// sealToMember encrypts plain to a member key (HPKE, DHKEM P-256).
func sealToMember(memberPEM, cluster string, plain []byte) ([]byte, error) {
	pub, err := cdschain.ParseKey(memberPEM)
	if err != nil {
		return nil, err
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, err
	}
	pk, err := hpke.NewDHKEMPublicKey(ecdhPub)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(handoffInfo+cluster), plain)
}

// adoptCA opens the CA key sealed to this replica's member key and adopts it.
func (r *Replica) adoptCA(certPEM, sealed []byte, want *ecdsa.PublicKey) error {
	priv, err := r.member.ECDH()
	if err != nil {
		return err
	}
	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return err
	}
	keyPEM, err := hpke.Open(k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(handoffInfo+r.cfg.Cluster), sealed)
	if err != nil {
		return fmt.Errorf("the CA key is not sealed to this replica's member key: %w", err)
	}
	defer clear(keyPEM)
	return r.cfg.Mesh.Adopt(certPEM, keyPEM, want)
}

// ErrNotPending is a genesis or handoff to a replica that holds a chain.
var ErrNotPending = errors.New("the replica already holds a chain")

// SetCredential installs the Kubernetes store credential.
func (r *Replica) SetCredential(data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.setCredentialLocked(data)
}

func (r *Replica) setCredentialLocked(data []byte) error {
	store, err := OpenKube(data, r.cfg.Cluster)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	r.store, r.credential = store, bytes.Clone(data)
	return nil
}

func (r *Replica) url(slot int, path string) string {
	return "https://" + r.cfg.Endpoints[slot] + path
}

// Call sends in as JSON and decodes a 2xx answer, capped, into out.
func Call(ctx context.Context, client *http.Client, method, url string, in, out any) error {
	return call(ctx, client, method, url, in, out, maxAnswer)
}

func call(ctx context.Context, client *http.Client, method, url string, in, out any, limit int64) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := readutil.ReadAll(resp.Body, limit)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return &operatorauth.StatusError{Status: resp.StatusCode, Body: string(bytes.TrimSpace(data))}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// maxAnswer caps any HA answer: a handoff carries the whole chain.
const maxAnswer = 1 << 30
