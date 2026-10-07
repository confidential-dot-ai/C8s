package httputil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestRetryConnectionRefusedBounds(t *testing.T) {
	refused := &url.Error{Op: "Post", URL: "https://node:8443/attest", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}
	t.Run("zero wait", func(t *testing.T) {
		calls := 0
		err := RetryConnectionRefused(context.Background(), time.Second, 0, func(context.Context) error {
			calls++
			return refused
		})
		if !errors.Is(err, syscall.ECONNREFUSED) || calls != 1 {
			t.Fatalf("calls=%d, err=%v", calls, err)
		}
	})
	t.Run("verification failures are final", func(t *testing.T) {
		calls := 0
		want := errors.New("quote verification failed")
		err := RetryConnectionRefused(context.Background(), time.Second, time.Minute, func(context.Context) error {
			calls++
			return want
		})
		if !errors.Is(err, want) || calls != 1 {
			t.Fatalf("calls=%d, err=%v", calls, err)
		}
	})
	t.Run("cancel while waiting", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		err := RetryConnectionRefused(ctx, time.Second, time.Minute, func(context.Context) error {
			cancel()
			return refused
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want cancellation, got %v", err)
		}
	})
	t.Run("collateral dial failure is final", func(t *testing.T) {
		calls := 0
		want := &url.Error{Op: "Post", URL: "https://node:8443/attest", Err: fmt.Errorf("armtls: verify evidence: %w", refused.Err)}
		err := RetryConnectionRefused(context.Background(), time.Second, time.Minute, func(context.Context) error {
			calls++
			return want
		})
		if !errors.Is(err, want) || calls != 1 {
			t.Fatalf("calls=%d, err=%v", calls, err)
		}
	})
	t.Run("deadline bounds the retry sleep", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := 0
		err := RetryConnectionRefused(ctx, time.Second, 10*time.Millisecond, func(context.Context) error {
			calls++
			return refused
		})
		if !errors.Is(err, syscall.ECONNREFUSED) || calls != 1 {
			t.Fatalf("wait deadline was not respected: calls=%d, err=%v", calls, err)
		}
	})
}

func TestRetryConnectionRefusedListenerStarts(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		calls := 0
		start := time.Now()
		err := RetryConnectionRefused(context.Background(), time.Second, time.Minute, func(ctx context.Context) error {
			calls++
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) != time.Second {
				t.Fatalf("attempt is not timeout-bounded: %v, %v", deadline, ok)
			}
			if calls == 1 {
				return &url.Error{Op: "Post", URL: "https://node/attest", Err: &net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}}
			}
			return nil
		})
		if err != nil || calls != 2 || time.Since(start) != 5*time.Second {
			t.Fatalf("listener did not recover after retry: calls=%d elapsed=%s err=%v", calls, time.Since(start), err)
		}
	})
}

func TestRetryConnectionRefusedCancelledBeforeAttempt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RetryConnectionRefused(ctx, time.Second, time.Minute, func(context.Context) error {
		t.Fatal("operation ran after cancellation")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation, got %v", err)
	}
}
