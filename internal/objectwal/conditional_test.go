package objectwal

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func TestConditionalAppendHasOneWinnerAcrossReplicas(t *testing.T) {
	store := newStore()
	const replicas = 6
	results := make(chan response, replicas)
	start := make(chan struct{})
	for range replicas {
		log, _ := openLog(t, store)
		go func() {
			<-start
			value, err := log.AppendIfCurrent(t.Context(), 0, []byte("maintenance"))
			results <- response{value, err}
		}()
	}
	close(start)
	winners := 0
	for range replicas {
		result := <-results
		switch {
		case result.err == nil && result.value == 1:
			winners++
		case errors.Is(result.err, ErrStateChanged):
		default:
			t.Fatalf("conditional append: %+v", result)
		}
	}
	recovered, state := openLog(t, store)
	if err := recovered.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if winners != 1 || state.Index != 1 || !slices.Equal(state.Values, []string{"maintenance"}) {
		t.Fatalf("winners=%d recovered=%+v", winners, state)
	}
}

func TestConditionalAppendDoesNotRebaseAfterCASConflict(t *testing.T) {
	store := newStore()
	a, state := openLog(t, store)
	b, _ := openLog(t, store)
	if _, err := a.Append(t.Context(), []byte("seed")); err != nil {
		t.Fatal(err)
	}
	var raced atomic.Bool
	store.put = func(ctx context.Context, key string, body []byte, expected string) (string, error) {
		if key == "pilot/head" && raced.CompareAndSwap(false, true) {
			// A has already read the matching index and uploaded its object.
			// B changes the application before A's conditional publication.
			if _, err := b.Append(ctx, []byte("newer-state")); err != nil {
				return "", err
			}
		}
		return store.write(ctx, key, body, expected)
	}
	if _, err := a.AppendIfCurrent(t.Context(), 1, []byte("stale-maintenance")); !errors.Is(err, ErrStateChanged) {
		t.Fatalf("stale conditional append: %v", err)
	}
	if state.Index != 2 || !slices.Equal(state.Values, []string{"seed", "newer-state"}) || a.Stats().Stopped {
		t.Fatalf("rebased or stopped after conflict: %+v %+v", state, a.Stats())
	}
	if a.Fresh().IsZero() {
		t.Fatal("a successfully observed newer state lost its freshness")
	}
	recovered, cold := openLog(t, store)
	if err := recovered.Sync(t.Context()); err != nil || !slices.Equal(cold.Values, state.Values) {
		t.Fatalf("cold recovery applied the orphan: %+v %v", cold, err)
	}
}

func TestConditionalAppendReconcilesLostReplyBehindCheckpoint(t *testing.T) {
	store := newStore()
	a, state := openLog(t, store)
	b, _ := openLog(t, store)
	if _, err := a.Append(t.Context(), []byte("seed")); err != nil {
		t.Fatal(err)
	}
	var dropped atomic.Bool
	store.put = func(ctx context.Context, key string, body []byte, expected string) (string, error) {
		etag, err := store.write(ctx, key, body, expected)
		if err == nil && key == "pilot/head" && dropped.CompareAndSwap(false, true) {
			if _, err := b.Append(ctx, []byte("later")); err != nil {
				return "", err
			}
			if err := b.Checkpoint(ctx); err != nil {
				return "", err
			}
			return "", errors.New("committed response lost")
		}
		return etag, err
	}
	result, err := a.AppendIfCurrent(t.Context(), 1, []byte("maintenance"))
	if err != nil || result != 2 {
		t.Fatalf("lost reply mistaken for failed precondition: %v %v", result, err)
	}
	if state.Index != 3 || !slices.Equal(state.Values, []string{"seed", "maintenance", "later"}) {
		t.Fatalf("missing or duplicate conditional command: %+v", state)
	}
	recovered, cold := openLog(t, store)
	if err := recovered.Sync(t.Context()); err != nil || !slices.Equal(cold.Values, state.Values) {
		t.Fatalf("cold recovery: %+v %v", cold, err)
	}
}

func TestConditionalMaintenancePreservesWriterAcrossCheckpoint(t *testing.T) {
	store := newStore()
	forward := func(context.Context, Owner, ForwardRequest) error {
		return errors.New("maintenance must not forward")
	}
	a, _ := preferredLog(t, store, "a", forward)
	b, _ := preferredLog(t, store, "b", forward)
	if _, err := a.Append(t.Context(), []byte("seed")); err != nil {
		t.Fatal(err)
	}
	owner := a.Stats().Writer
	if err := b.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	expected := b.Stats().Applied
	if err := a.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	if result, err := b.AppendIfCurrent(t.Context(), expected, []byte("maintenance")); err != nil || result != 2 {
		t.Fatalf("maintenance after checkpoint: %v %v", result, err)
	}
	if got := b.Stats(); got.Writer != owner || got.Forwarded != 0 || got.Takeovers != 0 {
		t.Fatalf("maintenance changed writer ownership: %+v", got)
	}
	if _, err := a.Append(t.Context(), []byte("business")); err != nil || a.Stats().Writer != owner {
		t.Fatalf("preferred writer did not continue: %v %+v", err, a.Stats())
	}
}

func TestConditionalAppendCancellationRetainsBoundedAdmission(t *testing.T) {
	store := &gatedStore{Store: newStore(), entered: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(store.release) })
	defer release()
	log, state := actorLog(t, store, Options{QueueCapacity: 2, QueueBytes: 4, BatchEntries: 1})
	activeCtx, cancelActive := context.WithCancel(t.Context())
	defer cancelActive()
	active := make(chan error, 1)
	go func() { _, err := log.AppendIfCurrent(activeCtx, 0, []byte("aa")); active <- err }()
	<-store.entered
	queuedCtx, cancelQueued := context.WithCancel(t.Context())
	defer cancelQueued()
	queued := make(chan error, 1)
	go func() { _, err := log.AppendIfCurrent(queuedCtx, 0, []byte("bb")); queued <- err }()
	awaitAdmission(t, log, 2)
	if _, err := log.AppendIfCurrent(t.Context(), 0, []byte("cc")); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("overflow: %v", err)
	}
	cancelQueued()
	if err := <-queued; !errors.Is(err, context.Canceled) || errors.Is(err, ErrInDoubt) {
		t.Fatalf("queued cancellation: %v", err)
	}
	if log.Stats().AdmittedBytes != 4 {
		t.Fatal("cancellation released bytes while the actor still held them")
	}
	cancelActive()
	if err := <-active; !errors.Is(err, ErrInDoubt) {
		t.Fatalf("active cancellation concealed a possible commit: %v", err)
	}
	release()
	awaitAdmission(t, log, 0)
	if err := log.Sync(t.Context()); err != nil || state.Index != 0 {
		t.Fatalf("canceled operation applied: %+v %v", state, err)
	}
}
