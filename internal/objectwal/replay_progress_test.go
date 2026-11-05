package objectwal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// A deterministic operation budget models slow storage reaching its deadline
// after a few GETs. No sleep or longer production timeout is needed to expose
// the bug: before retaining verified records, every retry fetches the same tail.
type replayBudgetStore struct {
	Store
	remaining atomic.Int64
	heads     atomic.Int64
	walGets   atomic.Int64
}

func (s *replayBudgetStore) Get(ctx context.Context, key string) (Object, error) {
	if s.remaining.Add(-1) < 0 {
		return Object{}, context.DeadlineExceeded
	}
	if strings.HasSuffix(key, "/head") {
		s.heads.Add(1)
	}
	o, err := s.Store.Get(ctx, key)
	if err == nil && strings.Contains(key, "/wal/") {
		s.walGets.Add(1)
	}
	return o, err
}

func TestInterruptedReplayMakesBoundedProgressAndReadsTheLatestHead(t *testing.T) {
	store := newStore()
	writer, written := actorLog(t, store, Options{BatchEntries: 1})
	for i := range 12 {
		if _, err := writer.Append(t.Context(), []byte(fmt.Sprintf("value-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	limited := &replayBudgetStore{Store: store}
	cold, recovered := actorLog(t, limited, Options{})
	for attempt := range 5 {
		// A head observation plus three uncached records per operation.
		limited.remaining.Store(4)
		err := cold.Sync(t.Context())
		if attempt < 4 {
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("attempt %d: %v", attempt, err)
			}
			if recovered.Index != 0 || !cold.Fresh().IsZero() {
				t.Fatal("incomplete chain became applied or fresh")
			}
			stats := cold.Stats()
			if stats.ReplayCachedRecords != 3*(attempt+1) || stats.ReplayCachedBytes <= 0 || stats.ReplayCachedBytes > 64<<20 {
				t.Fatalf("unbounded or lost progress: %+v", stats)
			}
			if attempt == 0 {
				// Committing a revocation while recovery is interrupted must be
				// observed before the replacement advertises any fresh state.
				if _, err := writer.Append(t.Context(), []byte("revoked")); err != nil {
					t.Fatal(err)
				}
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(recovered.Values, written.Values) || recovered.Values[len(recovered.Values)-1] != "revoked" {
		t.Fatal("recovery lost or reordered committed state")
	}
	s := cold.Stats()
	if limited.heads.Load() != 5 || limited.walGets.Load() != 13 || s.ReplayCacheHits == 0 || s.ReplayCachedRecords != 0 || s.ReplayCachedBytes != 0 || cold.Fresh().IsZero() {
		t.Fatalf("head freshness or bounded cache lifecycle: heads=%d GETs=%d stats=%+v", limited.heads.Load(), limited.walGets.Load(), s)
	}
}

func TestInterruptedReplayBudgetCannotGrowAcrossRetriesAndCheckpointSupersedesIt(t *testing.T) {
	store := newStore()
	writer, written := actorLog(t, store, Options{BatchEntries: 1})
	for range 8 {
		if _, err := writer.Append(t.Context(), []byte(strings.Repeat("x", 400))); err != nil {
			t.Fatal(err)
		}
	}
	cold, recovered := actorLog(t, store, Options{ReplayBytes: 2000})
	for range 3 {
		if err := cold.Sync(t.Context()); !errors.Is(err, ErrReplayLimit) {
			t.Fatalf("budget: %v", err)
		}
		s := cold.Stats()
		if s.ReplayCachedRecords < 1 || s.ReplayCachedBytes > 2000 || !cold.Fresh().IsZero() || recovered.Index != 0 {
			t.Fatalf("retained replay escaped its budget: %+v", s)
		}
	}
	if err := writer.Checkpoint(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := cold.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	s := cold.Stats()
	if !slices.Equal(recovered.Values, written.Values) || s.ReplayCachedBytes != 0 || s.ReplayCachedRecords != 0 {
		t.Fatal("checkpoint did not replace and release interrupted replay")
	}
}
