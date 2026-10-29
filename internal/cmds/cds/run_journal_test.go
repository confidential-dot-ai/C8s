package cds

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/allowlist"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

type journalReplicator func(allowlist.Command) (allowlist.Result, error)

func (f journalReplicator) Replicate(cmd allowlist.Command) (allowlist.Result, error) {
	return f(cmd)
}

func journalTestStore(t *testing.T) *allowlist.Store {
	t.Helper()
	s, err := allowlist.OpenInMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return &s
}

func TestStartJournalRetriesUnavailable(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(fmt.Sprintf("committed=%v", committed), func(t *testing.T) {
			s := journalTestStore(t)
			calls := 0
			var first []allowlist.HistoryEntry
			s.SetReplicator(journalReplicator(func(cmd allowlist.Command) (allowlist.Result, error) {
				calls++
				if cmd.Op != allowlist.OpStartJournal {
					t.Fatalf("unexpected operation: %s", cmd.Op)
				}
				// Distinct command times make a duplicate publication visible.
				cmd.AtMS = int64(calls * 1000)
				if calls == 1 {
					if committed {
						if err := s.Apply(cmd).Error(); err != nil {
							t.Fatal(err)
						}
						var err error
						first, err = s.History()
						if err != nil {
							t.Fatal(err)
						}
					}
					return allowlist.Result{}, fmt.Errorf("local apply pending: %w", allowlist.ErrUnavailable)
				}
				return s.Apply(cmd), nil
			}))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := startJournal(ctx, s); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatalf("calls = %d, want 2", calls)
			}
			history, err := s.History()
			if err != nil || len(history) != 1 {
				t.Fatalf("history = %v, error = %v", history, err)
			}
			if committed && !reflect.DeepEqual(first, history) {
				t.Fatalf("retry changed committed history: before %v, after %v", first, history)
			}
		})
	}
}

func TestStartJournalPermanentError(t *testing.T) {
	for _, resultError := range []bool{false, true} {
		t.Run(fmt.Sprintf("result=%v", resultError), func(t *testing.T) {
			s := journalTestStore(t)
			calls := 0
			want := errors.New("history corruption")
			s.SetReplicator(journalReplicator(func(allowlist.Command) (allowlist.Result, error) {
				calls++
				if resultError {
					return allowlist.Result{ErrKind: "other", Err: want.Error()}, nil
				}
				return allowlist.Result{}, want
			}))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := startJournal(ctx, s)
			if err == nil || err.Error() != want.Error() || calls != 1 {
				t.Fatalf("error = %v, calls = %d", err, calls)
			}
		})
	}
}

func TestStartJournalCancellation(t *testing.T) {
	for _, before := range []bool{false, true} {
		t.Run(fmt.Sprintf("before=%v", before), func(t *testing.T) {
			s := journalTestStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			s.SetReplicator(journalReplicator(func(allowlist.Command) (allowlist.Result, error) {
				calls++
				cancel()
				return allowlist.Result{}, allowlist.ErrUnavailable
			}))
			wantCalls := 1
			if before {
				cancel()
				wantCalls = 0
			}
			if err := startJournal(ctx, s); !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v, want cancellation", err)
			}
			if calls != wantCalls {
				t.Fatalf("calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

// A workload mutation may commit between the uncertain startup result and its
// retry. The retry must verify the new head, not republish an old document.
func TestStartJournalRetryPreservesInterleavedWrite(t *testing.T) {
	s := journalTestStore(t)
	digest, err := types.ParseDigest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatal(err)
	}
	workload := pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: digest}}}
	starts, writes := 0, 0
	var before []allowlist.HistoryEntry
	var beforeBody []byte
	s.SetReplicator(journalReplicator(func(cmd allowlist.Command) (allowlist.Result, error) {
		if cmd.Op == allowlist.OpPutWorkload {
			writes++
			cmd.AtMS = 2000
			return s.Apply(cmd), nil
		}
		if cmd.Op != allowlist.OpStartJournal {
			t.Fatalf("unexpected operation: %s", cmd.Op)
		}
		starts++
		cmd.AtMS = int64(starts * 3000)
		result := s.Apply(cmd)
		if err := result.Error(); err != nil {
			t.Fatal(err)
		}
		if starts == 1 {
			if err := s.PutWorkload("web", workload); err != nil {
				t.Fatal(err)
			}
			var err error
			before, err = s.History()
			if err != nil {
				t.Fatal(err)
			}
			doc, _, err := s.LoadAll()
			if err != nil {
				t.Fatal(err)
			}
			beforeBody, err = doc.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			return allowlist.Result{}, fmt.Errorf("committed but unavailable: %w", allowlist.ErrUnavailable)
		}
		return result, nil
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := startJournal(ctx, s); err != nil {
		t.Fatal(err)
	}
	if starts != 2 || writes != 1 {
		t.Fatalf("starts = %d, workload writes = %d", starts, writes)
	}
	after, err := s.History()
	if err != nil || len(after) != 2 || !reflect.DeepEqual(before, after) {
		t.Fatalf("history changed: before %v, after %v, error %v", before, after, err)
	}
	doc, _, err := s.LoadAll()
	if err != nil {
		t.Fatal(err)
	}
	afterBody, err := doc.Canonical()
	if err != nil || string(beforeBody) != string(afterBody) || len(doc.Workloads) != 1 {
		t.Fatalf("workload changed after retry: %s, error %v", afterBody, err)
	}
	if _, ok := doc.Workloads["web"]; !ok {
		t.Fatal("interleaved workload lost")
	}
}
