package cdsha

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// T is the gossip interval of every test set.
const T = 100 * time.Millisecond

var (
	buildA = testutil.CDSPinDocument(strings.Repeat("a1", 48), "launch")
	buildB = testutil.CDSPinDocument(strings.Repeat("b2", 48), "launch")
	buildC = testutil.CDSPinDocument(strings.Repeat("c3", 48), "launch")
)

// node is one replica instance of a test set: its build and its faults.
type node struct {
	*Replica
	build   string
	handler http.Handler
	cancel  context.CancelFunc
	// down drops every request to this node; delay holds each one.
	down  bool
	delay time.Duration
	// selfErr makes its own build check get no answer.
	selfErr bool
	// muted drops every request this node sends (mute). in and out are
	// held by each request to and from it, so fault and mute return only
	// once none that started before is in flight.
	muted   bool
	in, out sync.RWMutex
}

// set is an in-process replica set: its nodes answer at r<slot>:8443 through
// a transport that applies faults and, for attested calls, the pins.
type set struct {
	t        *testing.T
	mu       sync.Mutex
	nodes    []*node // by slot; a replaced slot points at the new instance
	store    *Memory
	operator *ecdsa.PrivateKey
	opPEM    string
	genesis  cdschain.Entry
	// onAttested runs before each attested request.
	onAttested func(*http.Request)
	// replay answers every gossip call to a slot it names with the first
	// answer that slot gave.
	replay map[int][]byte
	// forge rewrites a slot's pong note and names the key it is re-signed
	// with; nil leaves the pong alone.
	forge func(slot int, n *Note) *ecdsa.PrivateKey
	// unslotted boots replicas that are not told their slot.
	unslotted bool
}

func endpoints(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("r%d:8443", i)
	}
	return out
}

func newSet(t *testing.T, n int, builds ...string) *set {
	t.Helper()
	s := &set{t: t, store: NewMemory()}
	s.operator = newKey(t)
	s.opPEM, _ = cdschain.PublicKeyPEM(&s.operator.PublicKey)
	s.nodes = make([]*node, n)
	for slot := range n {
		b := buildA
		if slot < len(builds) {
			b = builds[slot]
		}
		s.boot(slot, b)
	}
	return s
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// boot starts a pending instance at slot with build b, replacing any.
func (s *set) boot(slot int, b string) *node {
	s.t.Helper()
	mesh, err := issuer.NewMeshCA("c8s-test", time.Hour)
	if err != nil {
		s.t.Fatal(err)
	}
	n := &node{build: b}
	self := slot
	if s.unslotted {
		self = -1
	}
	n.Replica, err = New(Config{
		Cluster: "lane", Endpoints: endpoints(len(s.nodes)), Self: self,
		OperatorKeys: []*ecdsa.PublicKey{&s.operator.PublicKey},
		Gossip:       T, PeerTimeout: T, StoreTimeout: time.Second, WarnEntries: 3,
		Mesh: mesh,
		Peer: &http.Client{Transport: s.transport(n, nil)},
		Attested: func(pins armtls.Pins) (*http.Client, error) {
			return &http.Client{Transport: s.transport(n, &pins)}, nil
		},
		SelfCheck: func(_ context.Context, m string) (bool, error) {
			s.mu.Lock()
			noAnswer := n.selfErr
			s.mu.Unlock()
			if noAnswer {
				return false, errors.New("no answer")
			}
			return m == n.build, nil
		},
	}, s.store)
	if err != nil {
		s.t.Fatal(err)
	}
	n.handler = n.Handler(func(*http.Request, []byte, []*ecdsa.PublicKey) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	s.t.Cleanup(cancel)
	s.mu.Lock()
	if old := s.nodes[slot]; old != nil {
		old.down = true
		old.cancel()
	}
	s.nodes[slot] = n
	s.mu.Unlock()
	go n.Run(ctx)
	return n
}

// transport reaches the set's nodes; with pins, only a node whose build
// they name (attested).
type transport struct {
	s    *set
	from *node
	pins *armtls.Pins
}

func (s *set) transport(from *node, pins *armtls.Pins) http.RoundTripper {
	return transport{s, from, pins}
}

func (tr transport) RoundTrip(req *http.Request) (*http.Response, error) {
	s := tr.s
	if tr.from != nil {
		tr.from.out.RLock()
		defer tr.from.out.RUnlock()
		if tr.from.muted {
			return nil, errors.New("connection refused")
		}
	}
	var target *node
	s.mu.Lock()
	for slot, e := range endpoints(len(s.nodes)) {
		if e == req.URL.Host {
			target = s.nodes[slot]
		}
	}
	s.mu.Unlock()
	if target == nil {
		return nil, errors.New("connection refused")
	}
	target.in.RLock()
	defer target.in.RUnlock()
	s.mu.Lock()
	hook, down, delay := s.onAttested, target.down, target.delay
	s.mu.Unlock()
	if down {
		return nil, errors.New("connection refused")
	}
	if tr.pins != nil {
		if hook != nil {
			hook(req)
		}
		if !slices.ContainsFunc(tr.pins.Images, func(p remote.ImagePin) bool { return hex.EncodeToString(p.Digest) == measurementOf(target.build) }) {
			return nil, errors.New("armtls: attestation policy check failed")
		}
	}
	select {
	case <-time.After(delay):
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	rec := httptest.NewRecorder()
	target.handler.ServeHTTP(rec, req)
	if req.URL.Path == GossipPath {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.forge != nil {
			var pong Gossip
			if err := json.Unmarshal(rec.Body.Bytes(), &pong); err == nil {
				if n, err := open(pong, ""); err == nil {
					if key := s.forge(target.cfg.Self, &n); key != nil {
						body, _ := json.Marshal(n)
						pong.Note, _ = cdschain.Sign(key, cdschain.Body{Cluster: "lane", Type: "gossip", Payload: body})
						data, _ := json.Marshal(pong)
						return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(data)), Header: http.Header{}}, nil
					}
				}
			}
		}
		if cached, ok := s.replay[target.cfg.Self]; ok {
			if cached == nil {
				s.replay[target.cfg.Self] = rec.Body.Bytes()
			} else {
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(cached)), Header: http.Header{}}, nil
			}
		}
	}
	return rec.Result(), nil
}

func measurementOf(build string) string {
	i := strings.Index(build, `"measurement":"`) + len(`"measurement":"`)
	return build[i : i+96]
}

// bootstrap signs a genesis accepting builds over the pending replicas and
// waits until every replica running one of them serves it.
func (s *set) bootstrap(builds ...string) {
	s.t.Helper()
	builds = s.start(builds...)
	for slot, n := range s.nodes {
		for _, b := range builds {
			if n.build == b {
				s.waitServing(slot)
			}
		}
	}
}

// start posts the genesis to slot 0 and returns the builds it accepts.
func (s *set) start(builds ...string) []string {
	s.t.Helper()
	if len(builds) == 0 {
		builds = []string{buildA}
	}
	g := cdschain.Genesis{Endpoints: endpoints(len(s.nodes)), OperatorKeys: s.opPEM}
	for _, n := range s.nodes {
		p, err := n.Pending(true)
		if err != nil || p == nil {
			s.t.Fatalf("not pending: %v", err)
		}
		g.Members = append(g.Members, p.Member)
		if g.CAKey == "" {
			g.CAKey = p.CAKey
		}
	}
	for i, b := range builds {
		g.Accepted = append(g.Accepted, cdschain.Build{Measurements: b, Version: fmt.Sprintf("v1.%d.0", i)})
	}
	payload, _ := json.Marshal(g)
	s.genesis = s.sign(cdschain.Body{Cluster: "lane", Type: cdschain.TypeGenesis, Payload: payload})
	if err := s.nodes[0].Start(Handoff{Entries: []cdschain.Entry{s.genesis}}); err != nil {
		s.t.Fatal(err)
	}
	return builds
}

func (s *set) sign(b cdschain.Body) cdschain.Entry {
	s.t.Helper()
	e, err := cdschain.Sign(s.operator, b)
	if err != nil {
		s.t.Fatal(err)
	}
	return e
}

// entry is an operator-keys entry after head; variants differ in content.
func (s *set) entry(after cdschain.Head, variant int) cdschain.Entry {
	s.t.Helper()
	extra := s.opPEM
	for range variant {
		k, _ := cdschain.PublicKeyPEM(&newKey(s.t).PublicKey)
		extra += k
	}
	payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: extra})
	return s.sign(cdschain.Body{Cluster: "lane", Seq: after.Seq + 1, Prev: after.Hash, Type: cdschain.TypeOperatorKeys, Payload: payload})
}

func (s *set) accepted(after cdschain.Head, builds ...string) cdschain.Entry {
	var p cdschain.Accepted
	for i, b := range builds {
		p.Accepted = append(p.Accepted, cdschain.Build{Measurements: b, Version: fmt.Sprintf("v2.%d.0", i)})
	}
	payload, _ := json.Marshal(p)
	return s.sign(cdschain.Body{Cluster: "lane", Seq: after.Seq + 1, Prev: after.Hash, Type: cdschain.TypeAccepted, Payload: payload})
}

func (s *set) node(slot int) *node {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nodes[slot]
}

// write submits a fresh entry through slot after its head and requires done.
func (s *set) write(slot int) cdschain.Head {
	s.t.Helper()
	n := s.node(slot)
	head, done, err := n.Submit(context.Background(), s.entry(n.State().Head, 1))
	if err != nil || !done {
		s.t.Fatalf("write through slot %d: done=%v %v", slot, done, err)
	}
	return head
}

func (s *set) waitServing(slot int) {
	s.t.Helper()
	s.waitFor(fmt.Sprintf("slot %d to serve", slot), func() bool {
		_, err := s.node(slot).Current(context.Background())
		return err == nil
	})
}

func (s *set) waitFor(what string, cond func() bool) {
	s.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(T / 4) {
		if cond() {
			return
		}
	}
	s.t.Fatalf("timed out waiting for %s", what)
}

// serves is the head slot serves, or why it refuses.
func (s *set) serves(slot int) (cdschain.Head, error) {
	state, err := s.node(slot).Current(context.Background())
	if err != nil {
		return cdschain.Head{}, err
	}
	return state.Head, nil
}

func (s *set) storeHead() cdschain.Head {
	s.t.Helper()
	raw, _ := s.store.GetHead(context.Background())
	var h cdschain.Head
	if err := json.Unmarshal(raw, &h); err != nil {
		s.t.Fatalf("store head %q: %v", raw, err)
	}
	return h
}

// fault sets slot's faults; a request to it already past the down check
// completes before fault returns.
func (s *set) fault(slot int, down bool, delay time.Duration) {
	s.mu.Lock()
	n := s.nodes[slot]
	n.down, n.delay = down, delay
	s.mu.Unlock()
	n.in.Lock()
	n.in.Unlock() //nolint:staticcheck // waits out the requests in flight
}

// mute drops (or, false, lets through again) every request slot sends: its
// gossip, the pongs it learns from, and its handoffs. A request already
// sent completes before mute returns.
func (s *set) mute(slot int, muted bool) {
	n := s.node(slot)
	n.out.Lock()
	n.muted = muted
	n.out.Unlock()
}

func (n *node) setStore(st Store) {
	n.mu.Lock()
	n.store = st
	n.mu.Unlock()
}

func (n *node) halted() *Fork {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fork
}

// Clone copies the store, as a host that shows one replica another store.
func (m *Memory) Clone() *Memory {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := NewMemory()
	c.head = bytes.Clone(m.head)
	for h, e := range m.entries {
		c.entries[h] = bytes.Clone(e)
	}
	return c
}

// storeWrite puts e on the store alone and moves its head to e, as a writer
// no replica hears from would.
func (s *set) storeWrite(e cdschain.Entry) {
	s.t.Helper()
	ctx := context.Background()
	b, _ := e.Decode()
	data, _ := e.Encode()
	old, _ := s.store.GetHead(ctx)
	next, _ := json.Marshal(cdschain.Head{V: 1, Cluster: "lane", Seq: b.Seq, Hash: e.Hash()})
	_ = s.store.PutEntry(ctx, e.Hash(), data)
	if err := s.store.CASHead(ctx, old, next); err != nil {
		s.t.Errorf("writing seq %d to the store: %v", b.Seq, err)
	}
}

// setHead overwrites the store's head, as a host rewriting the store would.
func (s *set) setHead(raw []byte) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	s.store.head = raw
}

// fixed is commit's entry argument for an entry built before the write.
func fixed(e cdschain.Entry) func(*cdschain.State) (cdschain.Entry, error) {
	return func(*cdschain.State) (cdschain.Entry, error) { return e, nil }
}
