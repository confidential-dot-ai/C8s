package objectwal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type gatedStore struct {
	Store
	entered chan struct{}
	release chan struct{}
	once    atomic.Bool
}

func (s *gatedStore) Get(ctx context.Context, key string) (Object, error) {
	if s.once.CompareAndSwap(false, true) {
		close(s.entered)
		select {
		case <-ctx.Done():
			return Object{}, ctx.Err()
		case <-s.release:
		}
	}
	return s.Store.Get(ctx, key)
}

func actorLog(t *testing.T, s Store, options Options) (*Log, *counter) {
	t.Helper()
	c := &counter{}
	l, err := NewWithOptions(t.Context(), s, c, bytes.Repeat([]byte{7}, 32), "pilot", "cluster/measured-config", options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l, c
}

func awaitAdmission(t *testing.T, l *Log, count int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for l.Stats().Admitted != count {
		if time.Now().After(deadline) {
			t.Fatalf("admission=%d, want %d", l.Stats().Admitted, count)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGroupCommitAcknowledgesIndividualResultsAfterOneCASPerBatch(t *testing.T) {
	synctest.Test(t, testGroupCommitAcknowledgesIndividualResultsAfterOneCASPerBatch)
}

func testGroupCommitAcknowledgesIndividualResultsAfterOneCASPerBatch(t *testing.T) {
	base := newStore()
	s := &gatedStore{Store: base, entered: make(chan struct{}), release: make(chan struct{})}
	l, c := actorLog(t, s, Options{BatchEntries: 8})
	synced := make(chan error, 1)
	go func() { synced <- l.Sync(t.Context()) }()
	<-s.entered
	const count = 32
	results := make(chan response, count)
	for i := range count {
		go func() { value, err := l.Append(t.Context(), []byte(fmt.Sprint(i))); results <- response{value, err} }()
	}
	awaitAdmission(t, l, count+1)
	// Admission precedes copying/enqueueing. Wait until every producer is
	// blocked on its reply; fake time keeps scheduling pauses from expiring
	// the batch timer while this fully queued workload is drained.
	synctest.Wait()
	// No enqueue, upload or partial batch is an acknowledgment.
	select {
	case <-results:
		t.Fatal("acknowledged before storage was available")
	default:
	}
	close(s.release)
	if err := <-synced; err != nil {
		t.Fatal(err)
	}
	seen := make(map[any]bool)
	for range count {
		r := <-results
		if r.err != nil || seen[r.value] {
			t.Fatalf("result=%v error=%v", r.value, r.err)
		}
		seen[r.value] = true
	}
	stats := l.Stats()
	if c.Index != count || stats.Batches != 4 || stats.CommittedCommands != count || stats.Puts != 8 || stats.LargestBatch != 8 {
		t.Fatalf("state=%+v stats=%+v", c, stats)
	}
	if err := l.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	recovered, state := actorLog(t, base, Options{})
	if err := recovered.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state.Index != count || fmt.Sprint(state.Values) != fmt.Sprint(c.Values) {
		t.Fatal("batch checkpoint changed order or results")
	}
}

func TestBackpressureIncludesActiveWorkAndCanceledQueueEntries(t *testing.T) {
	s := &gatedStore{Store: newStore(), entered: make(chan struct{}), release: make(chan struct{})}
	l, c := actorLog(t, s, Options{QueueCapacity: 3, QueueBytes: 6, BatchEntries: 1})
	first := make(chan error, 1)
	go func() { _, err := l.Append(t.Context(), []byte("aa")); first <- err }()
	<-s.entered
	ctx, cancel := context.WithCancel(t.Context())
	second := make(chan error, 1)
	go func() { _, err := l.Append(ctx, []byte("bb")); second <- err }()
	third := make(chan error, 1)
	go func() { _, err := l.Append(t.Context(), []byte("cc")); third <- err }()
	awaitAdmission(t, l, 3)
	if _, err := l.Append(t.Context(), []byte("dd")); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("overload=%v", err)
	}
	cancel()
	if err := <-second; !errors.Is(err, context.Canceled) || errors.Is(err, ErrInDoubt) {
		t.Fatalf("queued cancellation=%v", err)
	}
	if l.Stats().AdmittedBytes != 6 {
		t.Fatal("cancellation freed capacity before the actor removed the message")
	}
	close(s.release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-third; err != nil {
		t.Fatal(err)
	}
	if c.Index != 2 || strings.Join(c.Values, ",") != "aa,cc" {
		t.Fatalf("canceled request applied: %+v", c)
	}
	if stats := l.Stats(); stats.Admitted != 0 || stats.AdmittedBytes != 0 || stats.Rejected != 1 || stats.PeakAdmitted != 3 || stats.PeakAdmittedBytes != 6 {
		t.Fatalf("bad accounting: %+v", stats)
	}
}

func TestByteBudgetAndCancellationOfAnActiveBatch(t *testing.T) {
	s := &gatedStore{Store: newStore(), entered: make(chan struct{}), release: make(chan struct{})}
	l, _ := actorLog(t, s, Options{QueueCapacity: 10, QueueBytes: 3, BatchEntries: 1})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := l.Append(ctx, []byte("abc")); done <- err }()
	<-s.entered
	if _, err := l.Append(t.Context(), []byte("d")); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("byte budget=%v", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, ErrInDoubt) {
		t.Fatalf("active cancellation=%v", err)
	}
	close(s.release)
	l.Close()
	if stats := l.Stats(); stats.Admitted != 0 || stats.AdmittedBytes != 0 {
		t.Fatalf("shutdown leaked admission: %+v", stats)
	}
}

func TestShutdownRacesWithAdmissionWithoutStrandingRequests(t *testing.T) {
	l, _ := actorLog(t, newStore(), Options{QueueCapacity: 8, BatchEntries: 1})
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 100 {
		wg.Go(func() {
			<-start
			_, err := l.Append(t.Context(), []byte("one"))
			if err != nil && !errors.Is(err, ErrClosed) && !errors.Is(err, ErrBackpressure) && !errors.Is(err, context.Canceled) {
				t.Errorf("shutdown: %v", err)
			}
		})
	}
	close(start)
	l.Close()
	wg.Wait()
	if stats := l.Stats(); stats.Admitted != 0 || stats.AdmittedBytes != 0 {
		t.Fatalf("shutdown leaked: %+v", stats)
	}
	if _, err := l.Append(t.Context(), []byte("late")); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-close: %v", err)
	}
}

func TestLostBatchResponseAfterCheckpointReturnsEveryOriginalResult(t *testing.T) {
	base := newStore()
	s := &gatedStore{Store: base, entered: make(chan struct{}), release: make(chan struct{})}
	a, ca := actorLog(t, s, Options{BatchEntries: 4})
	b, _ := actorLog(t, base, Options{})
	var lost atomic.Bool
	base.put = func(ctx context.Context, key string, data []byte, etag string) (string, error) {
		v, err := base.write(ctx, key, data, etag)
		if err == nil && key == "pilot/head" && lost.CompareAndSwap(false, true) {
			if _, err := b.Append(ctx, []byte("later")); err != nil {
				return "", err
			}
			if err := b.Checkpoint(ctx); err != nil {
				return "", err
			}
			return "", errors.New("lost batch commit response")
		}
		return v, err
	}
	synced := make(chan error, 1)
	go func() { synced <- a.Sync(t.Context()) }()
	<-s.entered
	results := make(chan response, 4)
	for i := range 4 {
		go func() { value, err := a.Append(t.Context(), []byte(fmt.Sprint(i))); results <- response{value, err} }()
	}
	awaitAdmission(t, a, 5)
	close(s.release)
	if err := <-synced; err != nil {
		t.Fatal(err)
	}
	seen := map[any]bool{}
	for range 4 {
		r := <-results
		if r.err != nil || seen[r.value] {
			t.Fatalf("result=%v err=%v", r.value, r.err)
		}
		seen[r.value] = true
	}
	if ca.Index != 5 || len(seen) != 4 || a.Stats().Ambiguous != 1 {
		t.Fatalf("batch replay: %+v %+v", ca, a.Stats())
	}
}

func TestVersionOneHistoryContinuesWithBatchesAndCheckpoint(t *testing.T) {
	s := newStore()
	legacy, err := newState(s, &counter{}, bytes.Repeat([]byte{7}, 32), "pilot", "cluster/measured-config")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(record{ID: "legacy", Index: 1, Payload: []byte("old-format")})
	tail, err := legacy.immutable(t.Context(), "wal", 1, body)
	if err != nil {
		t.Fatal(err)
	}
	// Exact version-one head shape, before writer metadata existed.
	headBody, _ := json.Marshal(struct {
		Version  int    `json:"version"`
		Revision uint64 `json:"revision"`
		Tail     ref    `json:"tail"`
		Snapshot ref    `json:"snapshot,omitempty"`
	}{Version: 1, Revision: 1, Tail: tail})
	if _, err := s.Put(t.Context(), "pilot/head", legacy.seal("pilot/head", headBody), ""); err != nil {
		t.Fatal(err)
	}
	writer, state := actorLog(t, s, Options{})
	if err := writer.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state.Index != 1 || state.Values[0] != "old-format" {
		t.Fatal("legacy record not restored")
	}
	if result, err := writer.Append(t.Context(), []byte("new-format")); err != nil || result != 2 {
		t.Fatalf("append after old history: %v %v", result, err)
	}
	if err := writer.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted, restored := actorLog(t, s, Options{})
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(restored.Values, ",") != "old-format,new-format" {
		t.Fatal("mixed-format recovery changed history")
	}
}

func TestReplayBudgetFailsClosedAndColdCheckpointRecoveryWorks(t *testing.T) {
	s := newStore()
	writer, _ := actorLog(t, s, Options{BatchEntries: 1})
	for range 3 {
		if _, err := writer.Append(t.Context(), []byte("one")); err != nil {
			t.Fatal(err)
		}
	}
	lagging, state := actorLog(t, s, Options{ReplayBytes: 1})
	if err := lagging.Sync(t.Context()); !errors.Is(err, ErrReplayLimit) {
		t.Fatalf("replay budget: %v", err)
	}
	if !lagging.Fresh().IsZero() || state.Index != 0 {
		t.Fatal("partial replay was advertised as fresh")
	}
	if err := writer.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	restarted, restored := actorLog(t, s, Options{ReplayBytes: 1})
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if restored.Index != 3 {
		t.Fatal("cold recovery did not use checkpoint")
	}
}
