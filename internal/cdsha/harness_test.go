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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// T is the gossip interval of every test set.
const T = 100 * time.Millisecond

var (
	buildA = testutil.CDSPinDocument(strings.Repeat("a1", 48), "launch")
	buildB = testutil.CDSPinDocument(strings.Repeat("b2", 48), "launch")
)

// node is one replica instance of a test set: its build and its faults.
type node struct {
	*Replica
	build  string
	cancel context.CancelFunc
	// selfErr makes its own build check get no answer.
	selfErr bool
}

// set is an in-process replica set over one memory store.
type set struct {
	t        *testing.T
	mu       sync.Mutex
	nodes    []*node // by slot; a replaced slot points at the new instance
	store    *Memory
	operator *ecdsa.PrivateKey
	opPEM    string
	genesis  cdschain.Entry
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
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	s.t.Cleanup(cancel)
	s.mu.Lock()
	if old := s.nodes[slot]; old != nil {
		old.cancel()
	}
	s.nodes[slot] = n
	s.mu.Unlock()
	go n.Run(ctx)
	return n
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

// setHead overwrites the store's head, as a host rewriting the store would.
func (s *set) setHead(raw []byte) {
	s.store.mu.Lock()
	defer s.store.mu.Unlock()
	s.store.head = raw
}
