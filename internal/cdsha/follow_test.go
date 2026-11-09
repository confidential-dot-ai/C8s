package cdsha

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

func (s *set) follow(pin *cdschain.Head, known *cdschain.State) (*cdschain.State, error) {
	return Follow(context.Background(), "https://r0:8443", pin, known, &http.Client{Transport: s.transport(nil, nil)},
		func(pins armtls.Pins) (*http.Client, error) {
			return &http.Client{Transport: s.transport(nil, &pins)}, nil
		})
}

// A reader follows the chain from a pinned entry and never takes one
// that does not extend what it verified before.
func TestFollow(t *testing.T) {
	a, b := newSet(t, 1), newSet(t, 1)
	a.bootstrap()
	b.bootstrap()
	pin := cdschain.Head{Seq: 0, Hash: a.genesis.Hash()}
	first, err := a.follow(&pin, nil)
	if err != nil || first.Head.Seq != 0 {
		t.Fatalf("from the genesis: %+v %v", first, err)
	}
	head := a.write(0)
	next, err := a.follow(&pin, first)
	if err != nil || next.Head != head {
		t.Fatalf("incremental: %+v %v", next, err)
	}
	if _, err := b.follow(&pin, nil); err == nil {
		t.Fatal("followed a chain without the pinned entry")
	}
	b.write(0)
	b.write(0)
	if _, err := b.follow(nil, next); !errors.Is(err, ErrNotExtending) {
		t.Fatalf("another chain past the known head: %v", err)
	}
}

// C-ID: a replica answers a pin its chain holds, else its genesis.
func TestIdentity(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	head := s.write(0)
	g := s.genesis.Hash().String()
	later := "1:" + head.Hash.String()
	for pin, want := range map[string]string{g: g, "0:" + g: "0:" + g, later: later, "2:" + head.Hash.String(): g, "": g, "1:" + g: g} {
		if got := s.node(0).Identity(pin); got != want {
			t.Errorf("pin %q: answered %q, want %q", pin, got, want)
		}
	}
}

// fakeReplica serves pages of chain and the status, counting chain reads.
func fakeReplica(t *testing.T, chain func(read int) []cdschain.Entry, status Status) string {
	t.Helper()
	reads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == StatusPath {
			_ = json.NewEncoder(w).Encode(status)
			return
		}
		from, _ := strconv.Atoi(r.URL.Query().Get("from"))
		entries := chain(reads)
		reads++
		page := Chain{}
		if from < len(entries) {
			page.Entries = entries[from:min(len(entries), from+chainPage)]
		}
		_ = json.NewEncoder(w).Encode(page)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// Follow takes no head a replica does not serve, cuts a tail the
// serving replica does not confirm, and reads on when it confirms more.
func TestFollowConfirmsTheHead(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	s.write(0)
	s.write(0)
	all := s.node(0).chain
	head := func(i int) *cdschain.Head { h, _ := cdschain.Verify(all[:i+1]); return &h.Head }
	plain := func(armtls.Pins) (*http.Client, error) { return http.DefaultClient, nil }
	follow := func(url string) (*cdschain.State, error) {
		return Follow(context.Background(), url, nil, nil, http.DefaultClient, plain)
	}
	whole := func(int) []cdschain.Entry { return all }
	if _, err := follow(fakeReplica(t, whole, Status{Held: head(2), Serving: "unconfirmed"})); err == nil {
		t.Error("followed a replica that serves nothing")
	}
	if got, err := follow(fakeReplica(t, whole, Status{Held: head(1)})); err != nil || got.Head != *head(1) {
		t.Errorf("an unconfirmed tail: %+v %v", got, err)
	}
	growing := func(read int) []cdschain.Entry { return all[:min(len(all), 2+read)] }
	if got, err := follow(fakeReplica(t, growing, Status{Held: head(2)})); err != nil || got.Head != *head(2) {
		t.Errorf("a newer confirmed head: %+v %v", got, err)
	}
}

// The chain read before verification is bounded.
func TestChainReadIsBounded(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	e := s.node(0).chain[0]
	endless := func(int) []cdschain.Entry { return slices.Repeat([]cdschain.Entry{e}, 100*chainPage) }
	url := fakeReplica(t, endless, Status{})
	defer func(old int) { maxChainRead = old }(maxChainRead)
	maxChainRead = 4 * chainPage * len(e.Body)
	if _, err := ReadChain(context.Background(), http.DefaultClient, url, 0); err == nil {
		t.Fatal("an endless chain read ended without an error")
	}
}
