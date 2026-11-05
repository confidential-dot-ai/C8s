package cds

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
)

type startupCAResult struct {
	current issuer.CurrentCA
	err     error
}

func TestStartupWaitsForFreshnessWithoutReplacingRecoveredCA(t *testing.T) {
	expected := testMeshCA(t).MeshCA.Current().CA
	synctest.Test(t, func(t *testing.T) {
		mesh := &changingMesh{}
		mesh.ca.Store(expected)
		if _, ok := mesh.Current(); !ok {
			t.Fatal("initial readiness observation")
		}
		// The read watermark expires after joining, before startup reads CA.
		mesh.ca.Store(nil)
		result := make(chan startupCAResult, 1)
		go func() {
			current, err := awaitMeshCA(t.Context(), mesh, nil)
			result <- startupCAResult{current, err}
		}()
		synctest.Wait()
		select {
		case <-result:
			t.Fatal("startup accepted a CA without serving freshness")
		default:
		}
		mesh.ca.Store(expected)
		time.Sleep(joinPoll)
		synctest.Wait()
		got := <-result
		if got.err != nil || got.current.CA != expected {
			t.Fatalf("startup did not retain the recovered CA: %v", got.err)
		}
		mesh.ca.Store(nil)
		if _, ok := mesh.Current(); ok {
			t.Fatal("startup bypassed the later freshness gate")
		}
	})
}

func TestStartupCAWaitEndsWithCancellationOrBackendExit(t *testing.T) {
	for _, backendExit := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			stopped := make(chan struct{})
			result := make(chan startupCAResult, 1)
			go func() {
				current, err := awaitMeshCA(ctx, &changingMesh{}, stopped)
				result <- startupCAResult{current, err}
			}()
			synctest.Wait()
			if backendExit {
				close(stopped)
			} else {
				cancel()
			}
			got := <-result
			if got.current.CA != nil || got.err == nil || (!backendExit && !errors.Is(got.err, context.Canceled)) {
				t.Fatalf("stopped startup returned a CA or lost cancellation: %v", got.err)
			}
		})
	}
}
