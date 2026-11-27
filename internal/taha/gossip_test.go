package taha

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/issuer"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/operatorauth"
)

// An idle replica reads its store every T/2, with no client asking: that
// read writes a rolled-back store forward and notices another chain.
func TestIdleReplicaReadsTheStoreEveryHalfT(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	counting := &countingStore{Store: s.store}
	s.node(0).setStore(counting)
	time.Sleep(10 * T)
	if n := counting.reads.Load(); n < 10 {
		t.Fatalf("%d store reads in 10 T, want one every T/2", n)
	}
}

// A pending replica whose store already holds a chain waits for a giver:
// it no longer offers itself for a genesis, but still publishes its key.
func TestPendingReplicaOverAChainIsNoGenesis(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	n := s.boot(0, buildA)
	s.waitFor("the new instance to find the store's chain", func() bool {
		p, err := n.Pending(true)
		return err == nil && p == nil
	})
	if p, err := n.Pending(false); err != nil || p == nil {
		t.Fatalf("a joiner publishes nothing for a giver: %v", err)
	}
}

// A ping asks only for the entries after the pinger's head: a replica
// behind it, which holds none of them, sends none back.
func TestPongCarriesOnlyEntriesAfterThePingersHead(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	s.node(2).setStore(s.store.Clone())
	s.mute(2, true)
	s.write(0)
	ahead := s.node(0)
	ping, _ := ahead.ping()
	signed, err := ahead.sign(ping)
	if err != nil {
		t.Fatal(err)
	}
	pong, err := s.node(2).HandleGossip(context.Background(), signed)
	if got := s.node(2).State().Head.Seq; got != 0 {
		t.Fatalf("slot 2 is at seq %d, not behind", got)
	}
	if err != nil || len(pong.Entries) != 0 {
		t.Fatalf("a replica behind the pinger sent %d entries: %v", len(pong.Entries), err)
	}
}

// A pong carries as many of the entries asked for as fit in
// maxGossipEntries, counting each entry's body and signature, so no pong
// grows with the chain; the next ping, from the last entry carried, gets
// the rest. An entry ending exactly at the bound still fits.
func TestPongsAreBounded(t *testing.T) {
	size := func(e cdschain.Entry) int { return len(e.Body) + len(e.Sig) }
	for _, over := range []int{0, 1} {
		s := newSet(t, 1)
		s.bootstrap()
		n := s.node(0)
		from := n.State().Head
		var written []cdschain.Entry
		write := func(e cdschain.Entry) {
			if _, done, err := n.Submit(context.Background(), e); err != nil || !done {
				t.Fatalf("write: done=%v %v", done, err)
			}
			written = append(written, e)
		}
		total := 0
		for range 3 {
			write(s.routes(n.State().Head, 900<<10))
			total += size(written[len(written)-1])
		}
		write(s.routesOfSize(n.State().Head, maxGossipEntries+over-total))
		write(s.routes(n.State().Head, 1))
		var got []cdschain.Entry
		for len(got) < len(written) {
			ping, err := n.sign(Note{Cluster: "lane", Slot: 0, Head: from, From: from.Seq + 1})
			if err != nil {
				t.Fatal(err)
			}
			pong, err := n.HandleGossip(context.Background(), ping)
			if err != nil {
				t.Fatal(err)
			}
			carried, next := 0, len(got)+len(pong.Entries)
			for _, e := range pong.Entries {
				carried += size(e)
			}
			if len(pong.Entries) == 0 || carried > maxGossipEntries || next < len(written) && carried+size(written[next]) <= maxGossipEntries {
				t.Fatalf("pong after seq %d carries %d entries, %d bytes; at most %d fit", from.Seq, len(pong.Entries), carried, maxGossipEntries)
			}
			got = append(got, pong.Entries...)
			from = cdschain.Head{Seq: from.Seq + uint64(len(pong.Entries)), Hash: got[len(got)-1].Hash()}
		}
		for i, e := range got {
			if e.Hash() != written[i].Hash() {
				t.Fatalf("pong entry %d is not the entry at seq %d", i, i+1)
			}
		}
	}
}

// A ping claiming a slot outside the endpoints is refused.
func TestPingFromNoSlotIsRefused(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	n := s.node(0)
	for _, slot := range []int{-1, 1} {
		g, err := n.sign(Note{Cluster: "lane", Slot: slot})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.HandleGossip(context.Background(), g); !errors.Is(err, ErrInvalid) {
			t.Errorf("ping from slot %d: %v", slot, err)
		}
	}
}

// A replica level with the pinger answers without reading its store, so a
// slow store costs it no freshness with its peers.
func TestSlowStoreDelaysNoPongAtTheSameHead(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	entered, release := make(chan struct{}, 1), make(chan struct{})
	defer close(release)
	s.node(1).setStore(&hangingStore{Store: s.store, entered: entered, release: release})
	ping, _ := s.node(0).ping()
	signed, err := s.node(0).sign(ping)
	if err != nil {
		t.Fatal(err)
	}
	answered := make(chan error, 1)
	go func() {
		_, err := s.node(1).HandleGossip(context.Background(), signed)
		answered <- err
	}()
	select {
	case err := <-answered:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * T):
		t.Fatal("the pong waited for the store read")
	}
}

// A replica told its slot, slot 0 too, never asks the endpoints for it: it
// goes on to read its store even when no endpoint answers with its key.
func TestToldSlotAsksNoEndpoint(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	mesh, err := issuer.NewMeshCA("c8s-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Config{Cluster: "lane", Endpoints: endpoints(1), Self: 0, Gossip: T, PeerTimeout: T, StoreTimeout: time.Second,
		Mesh: mesh, Peer: &http.Client{Transport: s.transport(nil, nil)}}, s.store)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go r.Run(ctx)
	s.waitFor("the replica to find the store's chain", func() bool {
		p, err := r.Pending(true)
		return err == nil && p == nil
	})
}

// givingSet is a set whose slot 2 is a fresh pending instance and whose
// other replicas run no rounds, so only the test hands it the keys.
func givingSet(t *testing.T) (*set, *node) {
	s := newSet(t, 3)
	s.bootstrap()
	for slot := range 2 {
		s.node(slot).cancel()
	}
	return s, s.boot(2, buildA)
}

// One handoff writes the joiner's member entry and hands it the keys.
func TestOneHandoffWritesTheMemberAndHandsOver(t *testing.T) {
	s, joiner := givingSet(t)
	s.node(0).handoff(context.Background(), 2)
	if st := joiner.State(); st == nil || st.Members[2] != joiner.memberPEM {
		t.Fatal("the joiner holds no chain naming it after one handoff")
	}
}

// A handoff the joiner does not take is an error, not a key handoff done.
func TestHandoffTheJoinerRefusesFails(t *testing.T) {
	s, joiner := givingSet(t)
	s.mu.Lock()
	s.onAttested = func(req *http.Request) {
		if req.URL.Path == HandoffPath {
			req.Body = io.NopCloser(strings.NewReader("{"))
		}
	}
	s.mu.Unlock()
	giver := s.node(0)
	// As handoff does, so a round's pending pong starts no second one.
	giver.mu.Lock()
	giver.handing[2] = true
	giver.mu.Unlock()
	if err := giver.give(context.Background(), 2, giver.State()); err == nil || joiner.State() != nil {
		t.Fatalf("a refused handoff: %v", err)
	}
}

// Every replica of a set issues under the CA its genesis names: a joiner
// opens the handed key and adopts it.
func TestJoinersIssueUnderTheSetsCA(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	for slot := range 3 {
		n := s.node(slot)
		if !n.State().CAKey.Equal(n.cfg.Mesh.Current().CA.Key.Public()) {
			t.Errorf("slot %d issues under its own CA, not the set's", slot)
		}
	}
}

// A joiner with no store credential takes the one the handoff carries, so
// it reaches the store and can hand it on; one with a store keeps its own.
// A credential that is no store kubeconfig is refused.
func TestJoinerTakesTheHandedStoreCredential(t *testing.T) {
	cred := storeCredential(t)
	for _, own := range []bool{false, true} {
		s, joiner := givingSet(t)
		giver := s.node(0)
		giver.mu.Lock()
		giver.credential = cred
		giver.mu.Unlock()
		if !own {
			joiner.setStore(nil)
		}
		giver.handoff(context.Background(), 2)
		joiner.mu.Lock()
		store, held := joiner.store, joiner.credential
		joiner.mu.Unlock()
		switch {
		case joiner.State() == nil:
			t.Fatal("no handoff")
		case own && store != Store(s.store):
			t.Error("a joiner with its own store took the handed one")
		case !own && !bytes.Equal(held, cred):
			t.Error("a joiner with no store did not take the handed credential")
		}
	}
	s := newSet(t, 1)
	if err := s.node(0).SetCredential([]byte("not: a kubeconfig")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a credential that is no kubeconfig: %v", err)
	}
}

// Call takes every 2xx answer and refuses any other with its status.
func TestCallTakesEvery2xx(t *testing.T) {
	for status, ok := range map[int]bool{200: true, 299: true, 300: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"seq":7}`))
		}))
		var out map[string]int
		err := Call(context.Background(), srv.Client(), http.MethodGet, srv.URL, nil, &out)
		srv.Close()
		var refused *operatorauth.StatusError
		switch {
		case ok && (err != nil || out["seq"] != 7):
			t.Errorf("status %d: %v %v", status, out, err)
		case !ok && (!errors.As(err, &refused) || refused.Status != status):
			t.Errorf("status %d: %v", status, err)
		}
	}
}

// routes is a routes entry after head whose manifest is size bytes.
func (s *set) routes(after cdschain.Head, size int) cdschain.Entry {
	payload, _ := json.Marshal(cdschain.Routes{Manifest: bytes.Repeat([]byte{'r'}, size)})
	return s.sign(cdschain.Body{Cluster: "lane", Seq: after.Seq + 1, Prev: after.Hash, Type: cdschain.TypeRoutes, Payload: payload})
}

// routesOfSize is a routes entry after head whose body and signature are
// size bytes together.
func (s *set) routesOfSize(after cdschain.Head, size int) cdschain.Entry {
	s.t.Helper()
	manifest, pad := bytes.Repeat([]byte{'r'}, (size-512)*3/4), 0
	for range 100 {
		payload, _ := json.Marshal(cdschain.Routes{Manifest: manifest, Token: strings.Repeat("t", pad)})
		e := s.sign(cdschain.Body{Cluster: "lane", Seq: after.Seq + 1, Prev: after.Hash, Type: cdschain.TypeRoutes, Payload: payload})
		d := size - len(e.Body) - len(e.Sig)
		if d == 0 {
			return e
		}
		if pad += d; pad < 0 {
			break
		}
	}
	s.t.Fatalf("no routes entry of %d bytes", size)
	return cdschain.Entry{}
}

// storeCredential is a store kubeconfig naming an API server that refuses.
func storeCredential(t *testing.T) []byte {
	mesh, err := issuer.NewMeshCA("c8s-test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, _, err := mesh.Current().CA.PEM()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Appendf(nil, `apiVersion: v1
kind: Config
clusters:
- name: store
  cluster:
    server: https://127.0.0.1:1
    certificate-authority-data: %s
users:
- name: ta
  user:
    token: t
contexts:
- name: ta
  context:
    cluster: store
    user: ta
current-context: ta
`, base64.StdEncoding.EncodeToString(certPEM))
}
