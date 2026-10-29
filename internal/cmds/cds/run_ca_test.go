package cds

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

// This exercises the production startup reader with a controlled admission
// transition, not a simulated cluster or a replay of the process failure.
func TestStartMeshCARetriesNotServing(t *testing.T) {
	want := testMeshCA(t).Current().CA
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := startMeshCA(ctx, func() (*issuer.CA, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("freshness changed: %w", cdsha.ErrNotServing)
		}
		return want, nil
	})
	if err != nil || got != want || calls != 2 {
		t.Fatalf("CA = %p, error = %v, calls = %d; want %p, nil, 2", got, err, calls, want)
	}
}

func TestStartMeshCACancellation(t *testing.T) {
	for _, mode := range []string{"before", "persistent", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantCalls := 0
			wantErr := context.Canceled
			switch mode {
			case "before":
				cancel()
			case "persistent":
				wantCalls = 3
			case "deadline":
				var expire context.CancelFunc
				ctx, expire = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer expire()
				wantErr = context.DeadlineExceeded
			}
			calls := 0
			got, err := startMeshCA(ctx, func() (*issuer.CA, error) {
				calls++
				if calls == 3 {
					cancel()
				}
				return nil, cdsha.ErrNotServing
			})
			if got != nil || !errors.Is(err, wantErr) || calls != wantCalls {
				t.Fatalf("CA = %p, error = %v, calls = %d; want nil, %v, %d", got, err, calls, wantErr, wantCalls)
			}
		})
	}
}

func TestStartMeshCAPermanentErrors(t *testing.T) {
	for _, want := range []error{
		errors.New("cds-ha: no mesh CA"),
		errors.New("authorization refused"),
		errors.New("policy mismatch"),
		errors.New(cdsha.ErrNotServing.Error()), // matching text is not authority to retry
		errors.Join(cdsha.ErrNotServing, context.Canceled),
		errors.Join(cdsha.ErrNotServing, context.DeadlineExceeded),
	} {
		t.Run(want.Error(), func(t *testing.T) {
			calls := 0
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			got, err := startMeshCA(ctx, func() (*issuer.CA, error) {
				calls++
				return nil, want
			})
			if got != nil || err != want || calls != 1 {
				t.Fatalf("CA = %p, error = %v, calls = %d; want nil, %v, 1", got, err, calls, want)
			}
		})
	}
}
