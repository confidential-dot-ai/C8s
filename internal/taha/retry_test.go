package taha

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
)

type retryStore struct {
	Store
	writes atomic.Int64
}

func (s *retryStore) PutEntry(ctx context.Context, hash cdschain.Hash, raw []byte) error {
	s.writes.Add(1)
	return s.Store.PutEntry(ctx, hash, raw)
}

func (s *retryStore) CASHead(ctx context.Context, old, next []byte) error {
	s.writes.Add(1)
	return s.Store.CASHead(ctx, old, next)
}

func TestRetryAcceptedEntryPreservesState(t *testing.T) {
	for _, stage := range []string{"at-head", "historical", "rotated"} {
		t.Run(stage, func(t *testing.T) {
			s := newSet(t, 1)
			s.bootstrap()
			n := s.node(0)
			store := &retryStore{Store: s.store}
			n.setStore(store)
			var applied, validated atomic.Int64
			n.mu.Lock()
			n.cfg.OnState = func(*cdschain.State) error {
				applied.Add(1)
				return nil
			}
			n.cfg.Validate = func(cdschain.Body) error {
				validated.Add(1)
				return nil
			}
			n.mu.Unlock()

			artifact, _ := s.policyEntry(n.State().Head, "original")
			original, done, err := n.Submit(context.Background(), artifact)
			if err != nil || !done {
				t.Fatalf("initial entry: head=%+v done=%v err=%v", original, done, err)
			}
			if stage != "at-head" {
				e, _ := s.policyEntry(original, "current")
				if stage == "rotated" {
					key, _ := cdschain.PublicKeyPEM(&newKey(t).PublicKey)
					payload, _ := json.Marshal(cdschain.OperatorKeys{Keys: key})
					e = s.sign(cdschain.Body{
						Cluster: "lane",
						Seq:     original.Seq + 1,
						Prev:    original.Hash,
						Type:    cdschain.TypeOperatorKeys,
						Payload: payload,
					})
				}
				if _, done, err := n.Submit(context.Background(), e); err != nil || !done {
					t.Fatalf("next entry: done=%v err=%v", done, err)
				}
			}
			state := n.State()
			if stage == "rotated" && artifact.VerifySignature(state.OperatorKeys) == nil {
				t.Fatal("the artifact's signer is still authorized")
			}
			writes, applies, validates := store.writes.Load(), applied.Load(), validated.Load()
			confirmed := len(n.Status().Confirmed)
			for range 3 {
				head, done, err := n.Submit(context.Background(), artifact)
				if err != nil || !done || head != original {
					t.Fatalf("retry: head=%+v done=%v err=%v; want %+v", head, done, err, original)
				}
			}
			if n.State() != state || s.storeHead() != state.Head {
				t.Fatal("retry changed the held state or store head")
			}
			if store.writes.Load() != writes || applied.Load() != applies || validated.Load() != validates {
				t.Fatal("retry wrote the store, applied state or validated the payload again")
			}
			if len(n.Status().Confirmed) != confirmed {
				t.Fatal("retry added duplicate or redundant confirmation records")
			}
			if err := n.Resolve(original.Seq, cdschain.Hash{7}, original.Hash); !errors.Is(err, ErrInvalid) {
				t.Fatalf("resolution dropped a confirmed prefix: %v", err)
			}
		})
	}
}

func TestRetryRejectsChangedArtifact(t *testing.T) {
	s := newSet(t, 1)
	s.bootstrap()
	n := s.node(0)
	base := n.State().Head
	e := s.entry(base, 1)
	if _, done, err := n.Submit(context.Background(), e); err != nil || !done {
		t.Fatalf("initial submission: done=%v err=%v", done, err)
	}
	store := &retryStore{Store: s.store}
	n.setStore(store)
	state, confirmed := n.State(), len(n.Status().Confirmed)
	body, _ := e.Decode()
	resigned := s.sign(body)
	if resigned.Sig == e.Sig {
		t.Fatal("the replacement signature is not distinct")
	}
	changed := s.entry(base, 2)
	changed.Sig = e.Sig
	far := body
	far.Seq = ^uint64(0)
	for _, tc := range []struct {
		name  string
		entry cdschain.Entry
		want  error
	}{
		{name: "missing signature", entry: cdschain.Entry{Body: e.Body}, want: ErrConflict},
		{name: "another valid signature", entry: resigned, want: ErrConflict},
		{name: "changed body with original signature", entry: changed, want: ErrConflict},
		{name: "competing body", entry: s.entry(base, 2), want: ErrConflict},
		{name: "genesis", entry: s.genesis, want: ErrConflict},
		{name: "sequence outside held chain", entry: s.sign(far), want: ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, done, err := n.Submit(context.Background(), tc.entry); done || !errors.Is(err, tc.want) {
				t.Fatalf("changed artifact: done=%v err=%v; want %v", done, err, tc.want)
			}
			if n.State() != state || n.halted() != nil || s.storeHead() != state.Head ||
				store.writes.Load() != 0 || len(n.Status().Confirmed) != confirmed {
				t.Fatal("rejected artifact changed state, wrote the store, halted or confirmed")
			}
		})
	}
}

func postRetryEntry(t *testing.T, n *node, e cdschain.Entry) (int, cdschain.Head) {
	t.Helper()
	raw, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	n.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, EntriesPath, bytes.NewReader(raw)))
	var head cdschain.Head
	if rec.Code == http.StatusOK || rec.Code == http.StatusAccepted {
		if err := json.Unmarshal(rec.Body.Bytes(), &head); err != nil {
			t.Fatal(err)
		}
	}
	return rec.Code, head
}

func TestRetryRequiresFreshMajority(t *testing.T) {
	s := newSet(t, 3)
	s.bootstrap()
	n := s.node(0)
	stale := s.store.Clone()
	s.node(1).setStore(stale)
	s.node(2).setStore(stale)
	s.fault(0, true, 0)
	e := s.entry(n.State().Head, 1)
	code, original := postRetryEntry(t, n, e)
	if code != http.StatusAccepted {
		t.Fatalf("first submission: HTTP %d; want 202", code)
	}
	for range 2 {
		if code, head := postRetryEntry(t, n, e); code != http.StatusAccepted || head != original {
			t.Fatalf("stale peers: HTTP %d head=%+v; want 202 %+v", code, head, original)
		}
	}
	for _, slot := range []int{1, 2} {
		s.node(slot).setStore(s.store)
	}
	if code, head := postRetryEntry(t, n, e); code != http.StatusOK || head != original {
		t.Fatalf("recovered peers: HTTP %d head=%+v; want 200 %+v", code, head, original)
	}
	for _, slot := range []int{1, 2} {
		s.fault(slot, true, 0)
	}
	if code, head := postRetryEntry(t, n, e); code != http.StatusAccepted || head != original {
		t.Fatalf("unreachable peers after confirmation: HTTP %d head=%+v; want 202 %+v", code, head, original)
	}
	s.waitFor("cached freshness to expire", func() bool {
		_, err := n.Current(context.Background())
		return errors.Is(err, ErrUnavailable)
	})
	if code, _ := postRetryEntry(t, n, e); code != http.StatusServiceUnavailable {
		t.Fatalf("expired freshness: HTTP %d; want 503", code)
	}
	for _, slot := range []int{1, 2} {
		s.fault(slot, false, 0)
	}
	n.round(context.Background())
	if code, head := postRetryEntry(t, n, e); code != http.StatusOK || head != original {
		t.Fatalf("retry after recovery: HTTP %d head=%+v; want 200 %+v", code, head, original)
	}
	if confirmed := n.Status().Confirmed; len(confirmed) != 1 || confirmed[0] != original {
		t.Fatalf("confirmation records grew on retry: %+v", confirmed)
	}
}

type retryRoundKey struct{}

type retryFanout struct {
	http.RoundTripper
	gate  <-chan struct{}
	calls *atomic.Int64
}

func (f retryFanout) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Context().Value(retryRoundKey{}) != nil {
		f.calls.Add(1)
		select {
		case <-f.gate:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}
	return f.RoundTripper.RoundTrip(req)
}

func TestOverlappingRetryConfirmation(t *testing.T) {
	for _, change := range []string{"none", "cancel waiter", "cancel leader", "fork", "resolve", "newer entry"} {
		t.Run(change, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newSet(t, 3)
				n := s.node(0)
				gate := make(chan struct{})
				var calls atomic.Int64
				n.cfg.Peer.Transport = retryFanout{n.cfg.Peer.Transport, gate, &calls}
				s.bootstrap()
				for _, peer := range s.nodes {
					peer.cancel()
				}
				e := s.entry(n.State().Head, 1)
				s.storeWrite(e)
				for _, peer := range s.nodes {
					if _, err := peer.refresh(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				type result struct {
					head cdschain.Head
					done bool
					err  error
				}
				start := func(ctx context.Context, entry cdschain.Entry) chan result {
					ch := make(chan result, 1)
					go func() {
						head, done, err := n.Submit(ctx, entry)
						ch <- result{head, done, err}
					}()
					return ch
				}
				ctx := context.WithValue(context.Background(), retryRoundKey{}, true)
				leader, cancelLeader := context.WithCancel(ctx)
				defer cancelLeader()
				waiter, cancelWaiter := context.WithCancel(ctx)
				defer cancelWaiter()
				first := start(leader, e)
				synctest.Wait()
				second, third := start(waiter, e), start(ctx, e)
				synctest.Wait()
				if calls.Load() != 2 {
					t.Fatalf("overlapping retries sent %d peer requests, want 2", calls.Load())
				}
				var fourth chan result
				switch change {
				case "cancel waiter":
					cancelWaiter()
				case "cancel leader":
					cancelLeader()
				case "fork":
					n.mu.Lock()
					n.haltLocked(Fork{Seq: n.state.Head.Seq, Mine: e.Hash(), Theirs: cdschain.Hash{7}})
					n.mu.Unlock()
				case "resolve":
					if err := n.Resolve(n.State().Head.Seq, cdschain.Hash{7}, e.Hash()); err != nil {
						t.Fatal(err)
					}
				case "newer entry":
					fourth = start(ctx, s.entry(n.State().Head, 2))
					synctest.Wait()
					if calls.Load() != 4 {
						t.Fatal("a newer entry shared a round started before it was held")
					}
				}
				synctest.Wait()
				close(gate)
				for i, ch := range []chan result{first, second, third} {
					got := <-ch
					cancelled := change == "cancel leader" && i == 0 || change == "cancel waiter" && i == 1
					wantDone := change == "none" || change == "newer entry" || change == "cancel waiter" && !cancelled
					if got.done != wantDone || got.head.Hash != e.Hash() || (got.err != nil) != cancelled {
						t.Fatalf("caller %d after %s: %+v", i, change, got)
					}
				}
				if fourth != nil {
					if got := <-fourth; got.err != nil || !got.done || got.head.Seq != 2 {
						t.Fatalf("newer entry failed its separate round: %+v", got)
					}
				}
				if change == "none" || change == "cancel leader" {
					if got := <-start(ctx, e); got.err != nil || !got.done || calls.Load() != 4 {
						t.Fatalf("later retry must start another round: %+v, calls=%d", got, calls.Load())
					}
				}
			})
		})
	}
}

type retryBarrier struct {
	http.RoundTripper
	entered chan struct{}
	release chan struct{}
}

func (b retryBarrier) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	res, err := b.RoundTripper.RoundTrip(req)
	if req.Context().Value(retryRoundKey{}) != nil && req.URL.Host == "r2:8443" {
		close(b.entered)
		<-b.release
	}
	return res, err
}

func TestRetryRechecksHeldEntryAfterRound(t *testing.T) {
	for _, change := range []string{"fork", "resolve removes entry"} {
		t.Run(change, func(t *testing.T) {
			s := newSet(t, 3)
			n := s.node(0)
			entered, release := make(chan struct{}), make(chan struct{})
			n.cfg.Peer.Transport = retryBarrier{
				RoundTripper: n.cfg.Peer.Transport,
				entered:      entered,
				release:      release,
			}
			defer close(release)
			s.bootstrap()
			n.cancel()
			s.fault(0, true, 0)
			base := n.State().Head
			e := s.entry(base, 1)
			s.storeWrite(e)
			for _, peer := range s.nodes {
				if _, err := peer.refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			n.round(context.Background())
			original := n.State().Head
			type result struct {
				head cdschain.Head
				done bool
				err  error
			}
			resultCh := make(chan result, 1)
			before := time.Now()
			go func() {
				ctx := context.WithValue(context.Background(), retryRoundKey{}, true)
				head, done, err := n.Submit(ctx, e)
				resultCh <- result{head: head, done: done, err: err}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("retry did not start a fresh round")
			}
			s.waitFor("the first peer's confirmation", func() bool {
				n.mu.Lock()
				defer n.mu.Unlock()
				return n.heard[1].at.After(before) && n.heard[1].seq == original.Seq
			})
			if change == "fork" {
				n.mu.Lock()
				n.haltLocked(Fork{
					Seq:    original.Seq,
					Mine:   original.Hash,
					Theirs: cdschain.Hash{7},
					Source: "test",
				})
				n.mu.Unlock()
			} else if err := n.Resolve(original.Seq, cdschain.Hash{7}, original.Hash); err != nil {
				t.Fatal(err)
			}
			release <- struct{}{}
			select {
			case got := <-resultCh:
				if got.err != nil || got.done || got.head != original {
					t.Fatalf("concurrent %s: %+v", change, got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("retry did not finish its round")
			}
			if len(n.Status().Confirmed) != 0 {
				t.Fatal("retry recorded confirmation after a fork or removal")
			}
		})
	}
}
