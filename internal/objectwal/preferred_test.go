package objectwal

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func preferredLog(t *testing.T, s Store, id string, forward func(context.Context, Owner, ForwardRequest) error) (*Log, *counter) {
	t.Helper()
	return actorLog(t, s, Options{Writer: &WriterConfig{ID: id, Address: id, Forward: forward, ForwardTimeout: time.Second}})
}

func TestPreferredWriterCollectsRemoteCommandsWithoutCompetingUploads(t *testing.T) {
	s := newStore()
	nodes := map[string]*Log{}
	forward := func(ctx context.Context, owner Owner, r ForwardRequest) error {
		return nodes[owner.ID].CommitForwarded(ctx, r)
	}
	a, _ := preferredLog(t, s, "a", forward)
	nodes["a"] = a
	b, cb := preferredLog(t, s, "b", forward)
	nodes["b"] = b
	c, cc := preferredLog(t, s, "c", forward)
	nodes["c"] = c
	if _, err := a.Append(t.Context(), []byte("first")); err != nil {
		t.Fatal(err)
	}
	if result, err := b.Append(t.Context(), []byte("second")); err != nil || result != 2 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if result, err := c.Append(t.Context(), []byte("third")); err != nil || result != 3 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if b.Stats().Puts != 0 || c.Stats().Puts != 0 || cb.Index != 2 || cc.Index != 3 {
		t.Fatalf("followers uploaded or lost application: b=%+v c=%+v", b.Stats(), c.Stats())
	}
	if owner := c.Stats().Writer; owner.ID != "a" || owner.Epoch != 1 {
		t.Fatalf("owner=%+v", owner)
	}
}

func TestLostForwardResponseFindsOriginalResultBehindLaterCheckpoint(t *testing.T) {
	s := newStore()
	nodes := map[string]*Log{}
	var drop atomic.Bool
	forward := func(ctx context.Context, owner Owner, r ForwardRequest) error {
		if err := nodes[owner.ID].CommitForwarded(ctx, r); err != nil {
			return err
		}
		if drop.CompareAndSwap(false, true) {
			if _, err := nodes[owner.ID].Append(ctx, []byte("later")); err != nil {
				return err
			}
			if err := nodes[owner.ID].Checkpoint(ctx); err != nil {
				return err
			}
			return errors.New("lost HTTP receipt")
		}
		return nil
	}
	a, _ := preferredLog(t, s, "a", forward)
	nodes["a"] = a
	b, cb := preferredLog(t, s, "b", forward)
	nodes["b"] = b
	if _, err := a.Append(t.Context(), []byte("seed")); err != nil {
		t.Fatal(err)
	}
	if result, err := b.Append(t.Context(), []byte("original")); err != nil || result != 2 {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if cb.Index != 3 || b.Stats().Takeovers != 0 || b.Stats().Writer.ID != "a" {
		t.Fatalf("lost receipt replay: %+v %+v", cb, b.Stats())
	}
}

func TestTakeoverFencesAnOverlappingForwardedCommit(t *testing.T) {
	s := newStore()
	nodes := map[string]*Log{}
	var partition atomic.Bool
	forward := func(ctx context.Context, owner Owner, r ForwardRequest) error {
		if owner.ID == "a" && partition.Load() {
			return errors.New("writer unreachable")
		}
		return nodes[owner.ID].CommitForwarded(ctx, r)
	}
	a, _ := preferredLog(t, s, "a", forward)
	nodes["a"] = a
	b, _ := preferredLog(t, s, "b", forward)
	nodes["b"] = b
	c, cc := preferredLog(t, s, "c", forward)
	nodes["c"] = c
	if _, err := a.Append(t.Context(), []byte("seed")); err != nil {
		t.Fatal(err)
	}
	blocked, release := make(chan struct{}), make(chan struct{})
	var paused atomic.Bool
	s.put = func(ctx context.Context, key string, data []byte, etag string) (string, error) {
		if key == "pilot/head" && paused.CompareAndSwap(false, true) {
			close(blocked)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-release:
			}
		}
		return s.write(ctx, key, data, etag)
	}
	done := make(chan response, 1)
	go func() { value, err := c.Append(t.Context(), []byte("in-flight")); done <- response{value, err} }()
	<-blocked
	partition.Store(true)
	if result, err := b.Append(t.Context(), []byte("replacement")); err != nil || result != 2 {
		t.Fatalf("takeover result=%v err=%v", result, err)
	}
	if owner := b.Stats().Writer; owner.ID != "b" || owner.Epoch != 2 {
		t.Fatalf("takeover=%+v", owner)
	}
	close(release)
	result := <-done
	if result.err != nil || result.value != 3 || cc.Index != 3 {
		t.Fatalf("overlapping result=%+v state=%+v", result, cc)
	}
	if a.Stats().Conflicts == 0 {
		t.Fatal("old epoch was not fenced by the head CAS")
	}
	if err := a.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if a.Stats().Applied != 3 {
		t.Fatal("obsolete writer overwrote or duplicated a command")
	}
}

func TestForwardedDuplicatesUseRetainedHistoryAndRejectPayloadChanges(t *testing.T) {
	s := newStore()
	a, _ := preferredLog(t, s, "a", func(context.Context, Owner, ForwardRequest) error { return errors.New("unused") })
	if _, err := a.Append(t.Context(), []byte("seed")); err != nil {
		t.Fatal(err)
	}
	r := ForwardRequest{Owner: a.Stats().Writer, After: 1, Entries: []Entry{{ID: "request", Payload: []byte("once")}}}
	if err := a.CommitForwarded(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if err := a.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	puts := a.Stats().Puts
	if err := a.CommitForwarded(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if a.Stats().Applied != 2 || a.Stats().Puts != puts {
		t.Fatal("duplicate forwarded command committed twice")
	}
	r.Entries[0].Payload = []byte("changed")
	if err := a.CommitForwarded(t.Context(), r); !errors.Is(err, ErrRequestMismatch) {
		t.Fatalf("changed payload=%v", err)
	}
	r.Owner.Epoch++
	if err := a.CommitForwarded(t.Context(), r); !errors.Is(err, ErrNotWriter) {
		t.Fatalf("wrong epoch=%v", err)
	}
}

func TestPreferredWriterBackpressureDoesNotTriggerTakeover(t *testing.T) {
	base := newStore()
	s := &gatedStore{Store: base, entered: make(chan struct{}), release: make(chan struct{})}
	// Leave the first observation unblocked while establishing ownership.
	s.once.Store(true)
	nodes := map[string]*Log{}
	forward := func(ctx context.Context, owner Owner, r ForwardRequest) error {
		return nodes[owner.ID].CommitForwarded(ctx, r)
	}
	a, err := NewWithOptions(t.Context(), s, &counter{}, bytes.Repeat([]byte{7}, 32), "pilot", "cluster/measured-config", Options{QueueCapacity: 1, Writer: &WriterConfig{ID: "a", Address: "a", Forward: forward}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	nodes["a"] = a
	b, _ := preferredLog(t, base, "b", forward)
	nodes["b"] = b
	if _, err := a.Append(t.Context(), []byte("seed")); err != nil {
		t.Fatal(err)
	}
	s.once.Store(false)
	done := make(chan error, 1)
	go func() { done <- a.Sync(t.Context()) }()
	<-s.entered
	if _, err := b.Append(t.Context(), []byte("busy")); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("overload=%v", err)
	}
	if b.Stats().Takeovers != 0 || b.Stats().Puts != 0 {
		t.Fatal("backpressure displaced a healthy writer")
	}
	close(s.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
