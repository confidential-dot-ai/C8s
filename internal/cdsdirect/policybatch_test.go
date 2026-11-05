package cdsdirect

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/directstate"
	"github.com/confidential-dot-ai/c8s/internal/objectwal"
	"github.com/confidential-dot-ai/c8s/internal/requestgate"
)

func TestPolicyBatchBoundsAdmissionAndKeepsBodiesUntilUnknownOutcome(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	var count, calls atomic.Int32
	b := newPolicyBatcher(t.Context(), func(ctx context.Context, commands []cdsha.OperatorCommand) ([]cdsha.OperatorResult, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-resume
		}
		for _, c := range commands {
			if string(c.Body) != "owned" {
				t.Error("body released before worker finished")
			}
		}
		count.Add(int32(len(commands)))
		return nil, objectwal.ErrInDoubt
	})
	defer b.close()
	var wg sync.WaitGroup
	for range directstate.ShardCapacity {
		wg.Go(func() {
			body := []byte("owned")
			_, err := b.submit(t.Context(), cdsha.OperatorCommand{Body: body})
			clear(body)
			if !errors.Is(err, objectwal.ErrInDoubt) {
				t.Errorf("unknown outcome changed: %v", err)
			}
		})
	}
	<-entered
	deadline := time.Now().Add(time.Second)
	for b.gate.Stats().Admitted < directstate.ShardCapacity && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if b.gate.Stats().Admitted != directstate.ShardCapacity {
		t.Fatal("did not fill bounded queue")
	}
	if _, err := b.submit(t.Context(), cdsha.OperatorCommand{}); !errors.Is(err, requestgate.ErrBusy) {
		t.Fatalf("overflow: %v", err)
	}
	close(resume)
	wg.Wait()
	b.close()
	if count.Load() != directstate.ShardCapacity || calls.Load() >= directstate.ShardCapacity {
		t.Fatalf("not coalesced or retried: %d commands in %d calls", count.Load(), calls.Load())
	}
	if b.gate.Stats().Admitted != 0 {
		t.Fatal("admission not drained")
	}
}

func TestPolicyBatchCancellationAndShutdownDoNotLeaveSenders(t *testing.T) {
	entered := make(chan struct{})
	b := newPolicyBatcher(t.Context(), func(ctx context.Context, _ []cdsha.OperatorCommand) ([]cdsha.OperatorResult, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, err := b.submit(ctx, cdsha.OperatorCommand{}); done <- err }()
	<-entered
	cancel()
	b.close()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	if _, err := b.submit(t.Context(), cdsha.OperatorCommand{}); !errors.Is(err, requestgate.ErrClosed) {
		t.Fatalf("closed queue: %v", err)
	}
}
