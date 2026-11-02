package objectwal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryStore struct {
	mu      sync.Mutex
	objects map[string]Object
	version int
	put     func(context.Context, string, []byte, string) (string, error)
}

func newStore() *memoryStore { return &memoryStore{objects: map[string]Object{}} }
func (s *memoryStore) Get(ctx context.Context, key string) (Object, error) {
	if err := ctx.Err(); err != nil {
		return Object{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.objects[key]
	if !ok {
		return Object{}, ErrNotFound
	}
	o.Data = bytes.Clone(o.Data)
	return o, nil
}
func (s *memoryStore) Put(ctx context.Context, key string, body []byte, expected string) (string, error) {
	if s.put != nil {
		return s.put(ctx, key, body, expected)
	}
	return s.write(ctx, key, body, expected)
}
func (s *memoryStore) write(ctx context.Context, key string, body []byte, expected string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.objects[key]
	if (expected == "" && exists) || (expected != "" && (!exists || old.ETag != expected)) {
		return "", ErrConflict
	}
	s.version++
	etag := fmt.Sprintf(`"%d"`, s.version)
	s.objects[key] = Object{Data: bytes.Clone(body), ETag: etag}
	return etag, nil
}

type counter struct {
	Index  uint64
	Values []string
}

func (c *counter) Apply(index uint64, value []byte) (any, error) {
	if index != c.Index+1 {
		return nil, errors.New("out of order")
	}
	c.Index = index
	c.Values = append(c.Values, string(value))
	return len(c.Values), nil
}
func (c *counter) Capture() ([]byte, error) { return json.Marshal(c) }
func (c *counter) Restore(data []byte) (uint64, error) {
	err := json.Unmarshal(data, c)
	return c.Index, err
}
func openLog(t testing.TB, s Store) (*Log, *counter) {
	t.Helper()
	c := &counter{}
	l, err := New(s, c, bytes.Repeat([]byte{7}, 32), "pilot", "cluster/measured-config")
	if err != nil {
		t.Fatal(err)
	}
	return l, c
}

func TestLostCommitResponseAfterAnotherWriterAdvances(t *testing.T) {
	s := newStore()
	a, ca := openLog(t, s)
	b, cb := openLog(t, s)
	var dropped atomic.Bool
	s.put = func(ctx context.Context, key string, data []byte, etag string) (string, error) {
		version, err := s.write(ctx, key, data, etag)
		if err == nil && key == "pilot/head" && dropped.CompareAndSwap(false, true) {
			if _, err := b.Append(ctx, []byte("second")); err != nil {
				t.Fatal(err)
			}
			// The first response is lost after B has also committed. A must
			// find its request in the chain, not just inspect the current head.
			return "", errors.New("response lost")
		}
		return version, err
	}
	answer, err := a.Append(t.Context(), []byte("first"))
	if err != nil || answer != 1 {
		t.Fatalf("answer=%v error=%v", answer, err)
	}
	if ca.Index != 2 || cb.Index != 2 || len(ca.Values) != 2 {
		t.Fatalf("duplicate or missing application: A=%+v B=%+v", ca, cb)
	}
	if a.Stats().Ambiguous != 1 {
		t.Fatal("lost response was not classified as ambiguous")
	}
}

func TestConcurrentWritersAndFreshRecovery(t *testing.T) {
	s := newStore()
	const writers, each = 6, 12
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	errors := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		l, _ := openLog(t, s)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if _, err := l.Append(ctx, []byte("one")); err != nil {
					errors <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	recovered, state := openLog(t, s)
	if err := recovered.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if state.Index != writers*each {
		t.Fatalf("applied %d, want %d", state.Index, writers*each)
	}
}

func TestCheckpointColdRestartAndEncryption(t *testing.T) {
	s := newStore()
	l, _ := openLog(t, s)
	secret := []byte("synthetic-secret-never-in-object-plaintext")
	if _, err := l.Append(t.Context(), secret); err != nil {
		t.Fatal(err)
	}
	if err := l.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(t.Context(), []byte("after-snapshot")); err != nil {
		t.Fatal(err)
	}
	restarted, state := openLog(t, s)
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if state.Index != 2 || state.Values[0] != string(secret) {
		t.Fatalf("bad restore: %+v", state)
	}
	if restarted.Stats().Replayed != 1 {
		t.Fatal("restart did not use snapshot plus suffix")
	}
	for key, obj := range s.objects {
		if bytes.Contains(obj.Data, secret) || bytes.Contains(obj.Data, []byte("payload")) {
			t.Fatalf("plaintext at %s", key)
		}
	}
}

func TestLostFirstCommitWithConcurrentCheckpoint(t *testing.T) {
	s := newStore()
	a, ca := openLog(t, s)
	b, _ := openLog(t, s)
	var dropped atomic.Bool
	s.put = func(ctx context.Context, key string, data []byte, etag string) (string, error) {
		v, err := s.write(ctx, key, data, etag)
		if err == nil && key == "pilot/head" && dropped.CompareAndSwap(false, true) {
			if err := b.Sync(ctx); err != nil {
				t.Fatal(err)
			}
			if err := b.Checkpoint(ctx); err != nil {
				t.Fatal(err)
			}
			return "", errors.New("lost first commit response")
		}
		return v, err
	}
	answer, err := a.Append(t.Context(), []byte("one"))
	if err != nil || answer != 1 || ca.Index != 1 {
		t.Fatalf("answer=%v state=%+v err=%v", answer, ca, err)
	}
}

func TestStalledWriterCannotPublishObsoleteHead(t *testing.T) {
	s := newStore()
	old, co := openLog(t, s)
	current, _ := openLog(t, s)
	started, release := make(chan struct{}), make(chan struct{})
	var paused atomic.Bool
	s.put = func(ctx context.Context, key string, data []byte, etag string) (string, error) {
		if key == "pilot/head" && paused.CompareAndSwap(false, true) {
			close(started)
			<-release
		}
		return s.write(ctx, key, data, etag)
	}
	done := make(chan error, 1)
	go func() { _, err := old.Append(t.Context(), []byte("resumed")); done <- err }()
	<-started
	if _, err := current.Append(t.Context(), []byte("winner")); err != nil {
		t.Fatal(err)
	}
	if err := current.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if co.Index != 2 || co.Values[0] != "winner" || old.Stats().Conflicts == 0 {
		t.Fatalf("obsolete head won: %+v", co)
	}
}

func TestUnpublishedRecordIsNeverApplied(t *testing.T) {
	s := newStore()
	l, c := openLog(t, s)
	s.put = func(ctx context.Context, key string, data []byte, etag string) (string, error) {
		if key == "pilot/head" {
			return "", errors.New("unavailable")
		}
		return s.write(ctx, key, data, etag)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 35*time.Millisecond)
	defer cancel()
	if _, err := l.Append(ctx, []byte("orphan")); !errors.Is(err, ErrInDoubt) {
		t.Fatalf("got %v", err)
	}
	if c.Index != 0 {
		t.Fatal("unpublished record applied")
	}
	restarted, rc := openLog(t, s)
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	if rc.Index != 0 {
		t.Fatal("recovery discovered an orphan as committed")
	}
}

func TestWrongKeyScopeTamperingAndRollback(t *testing.T) {
	s := newStore()
	l, _ := openLog(t, s)
	if _, err := l.Append(t.Context(), []byte("first")); err != nil {
		t.Fatal(err)
	}
	old, _ := s.Get(t.Context(), "pilot/head")
	for _, tc := range []struct {
		name  string
		key   []byte
		scope string
	}{
		{"key", bytes.Repeat([]byte{8}, 32), "cluster/measured-config"},
		{"scope", bytes.Repeat([]byte{7}, 32), "another/launch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other, err := New(s, &counter{}, tc.key, "pilot", tc.scope)
			if err != nil {
				t.Fatal(err)
			}
			if err := other.Sync(t.Context()); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v", err)
			}
		})
	}
	if _, err := l.Append(t.Context(), []byte("second")); err != nil {
		t.Fatal(err)
	}
	s.objects["pilot/head"] = old
	if err := l.Sync(t.Context()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("rollback: %v", err)
	}
	if !l.Stats().Stopped {
		t.Fatal("rollback did not stop replica")
	}
	old.Data[0] ^= 1
	s.objects["pilot/head"] = old
	other, _ := openLog(t, s)
	if err := other.Sync(t.Context()); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tamper: %v", err)
	}
}
