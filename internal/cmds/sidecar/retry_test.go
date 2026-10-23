package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRetryRecoversOnceReleased(t *testing.T) {
	var calls int
	err := Retry(context.Background(), testConfig("https://cds.example"), "volume", func(context.Context) error {
		calls++
		if calls < 3 {
			return errNotYet
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if calls != 3 {
		t.Fatalf("attempted %d times, want 3", calls)
	}
}

func TestRetryGivesUp(t *testing.T) {
	cfg := testConfig("https://cds.example")
	var calls int
	err := Retry(context.Background(), cfg, "volume", func(context.Context) error {
		calls++
		return errNotYet
	})
	if err == nil {
		t.Fatal("retry never gave up")
	}
	if calls != cfg.Attempts {
		t.Fatalf("attempted %d times, want %d", calls, cfg.Attempts)
	}
}

// With no attempt bound the loop outlasts any fixed count: the main image may
// still be pulling long after a bounded window would have expired (C8s #977).
func TestRetryWithoutABoundWaitsUntilReleased(t *testing.T) {
	cfg := testConfig("https://cds.example")
	cfg.Attempts = 0
	var calls int
	err := Retry(context.Background(), cfg, "volume", func(context.Context) error {
		calls++
		if calls < 8 {
			return errNotYet
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if calls != 8 {
		t.Fatalf("attempted %d times, want 8", calls)
	}
}

// CDS's 403 is opaque, so the log has to say what it usually means.
func TestRefusalReasonNamesTheContainerGate(t *testing.T) {
	forbidden := fmt.Errorf("volume weights: %w", &StatusError{Status: http.StatusForbidden, Err: errNotYet})
	if got := refusalReason(forbidden); !strings.Contains(got, "every main container") {
		t.Fatalf("403 reason = %q, want it to name the main-container gate", got)
	}
	missing := fmt.Errorf("volume weights: %w", &StatusError{Status: http.StatusNotFound, Err: errNotYet})
	if got := refusalReason(missing); !strings.Contains(got, "c8s volume create") {
		t.Fatalf("404 reason = %q, want it to name c8s volume create", got)
	}
	if got := refusalReason(errNotYet); strings.Contains(got, "every main container") {
		t.Fatalf("non-403 reason = %q, want it not to blame the container gate", got)
	}
}

func TestNextWait(t *testing.T) {
	for _, tc := range []struct{ wait, interval, want time.Duration }{
		{5 * time.Second, 5 * time.Second, 10 * time.Second},
		{20 * time.Second, 5 * time.Second, 30 * time.Second},
		{time.Minute, time.Minute, time.Minute},
	} {
		if got := nextWait(tc.wait, tc.interval); got != tc.want {
			t.Errorf("nextWait(%v, %v) = %v, want %v", tc.wait, tc.interval, got, tc.want)
		}
	}
}

// A Terminal error stops the loop on its first attempt, and reaches the caller
// intact through the wrapping an attempt does on the way out.
func TestRetryStopsOnATerminalError(t *testing.T) {
	cfg := testConfig("https://cds.example")
	var calls int
	err := Retry(context.Background(), cfg, "secret", func(context.Context) error {
		calls++
		return fmt.Errorf("secret /api/db: %w", Terminal(errNotYet))
	})
	if err == nil {
		t.Fatal("a terminal error was treated as success")
	}
	if !errors.Is(err, errNotYet) {
		t.Fatalf("err = %v, want the wrapped cause", err)
	}
	if calls != 1 {
		t.Fatalf("attempted %d times, want to stop after the first", calls)
	}
}

func TestRetryStopsWhenTheContextIsDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Retry(ctx, testConfig("https://cds.example"), "volume", func(context.Context) error {
		return errNotYet
	})
	if err == nil {
		t.Fatal("retry ignored a cancelled context")
	}
}

var errNotYet = &notYetError{}

type notYetError struct{}

func (*notYetError) Error() string { return "not released yet" }
