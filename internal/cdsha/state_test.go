package cdsha

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cdschain"
)

// A replica whose CDS cannot serve the held state (say, the allowlist store
// refused the chain's policy) refuses instead of serving what the CDS still
// holds, and serves again once a later store read retries it with success.
func TestReplicaRefusesWhileTheCDSCannotServeItsState(t *testing.T) {
	s := newSet(t, 1)
	n := s.node(0)
	var failing atomic.Bool
	failing.Store(true)
	n.mu.Lock()
	n.cfg.OnState = func(*cdschain.State) error {
		if failing.Load() {
			return errors.New("database or disk is full")
		}
		return nil
	}
	n.mu.Unlock()
	s.start()
	s.waitFor("the replica to refuse on the failed state", func() bool {
		_, err := n.Current(context.Background())
		return errors.Is(err, ErrUnavailable) && strings.Contains(err.Error(), "disk is full")
	})
	if st := n.Status(); !strings.Contains(st.Serving, "disk is full") {
		t.Fatalf("status serving %q does not name the failed state", st.Serving)
	}
	failing.Store(false)
	s.waitServing(0)
}
