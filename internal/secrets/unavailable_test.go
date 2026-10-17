package secrets

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

type downRepl struct{}

func (downRepl) ReplicateSecret(Command) (Result, error) {
	return Result{}, fmt.Errorf("%w: %w", ErrUnavailable, errors.New("cds-ha: no leader"))
}

// An operator write the replicated store cannot commit is 503 and
// retryable, not 500.
func TestOperatorPutUnavailableIs503(t *testing.T) {
	oh := newOperatorHarness(t)
	oh.h.Store = ReplicatedStore{MemoryStore: oh.store, Repl: downRepl{}}
	for _, overwrite := range []bool{false, true} {
		w, _ := doPut(oh.h, putRequest(t, "/tenant-a/db", []byte("v"), overwrite))
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
			t.Errorf("overwrite=%v: %d %q, want 503 with Retry-After", overwrite, w.Code, w.Body)
		}
	}
	if _, _, err := (ReplicatedStore{MemoryStore: oh.store, Repl: downRepl{}}).PutIfAbsent(context.Background(), "/p", []byte("v"), WorkloadHolder("w")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("PutIfAbsent: %v", err)
	}
}
