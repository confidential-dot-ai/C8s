//go:build linux && podprovider_integration && podprovider_cloud

package podprovider

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/podstatus"
)

func TestCloudAcceptanceVerificationDelayReturnsRealResultAfterDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	abortCtx, abort := context.WithCancel(t.Context())
	defer abort()
	deadline := time.Now().Add(time.Second)
	want := podstatus.PodProjection{}
	want.Metadata.UID = "owned"
	delay := &cloudDelayedGuest{
		uid: "owned", deadline: deadline, deliverAt: deadline.Add(10 * time.Millisecond), abort: abortCtx,
		captured: make(chan time.Time, 1), delivered: make(chan time.Time, 1),
		read: func(context.Context, *record, string) (podstatus.PodProjection, error) { return want, nil },
	}
	type response struct {
		projection podstatus.PodProjection
		err        error
	}
	result := make(chan response, 1)
	go func() {
		projection, err := delay.readGuest(ctx, &record{UID: "owned"}, "unused")
		result <- response{projection, err}
	}()
	select {
	case captured := <-delay.captured:
		if !captured.Before(deadline) {
			t.Fatal("verified result was not captured before the deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reader did not capture the delegated result")
	}
	cancel()
	select {
	case <-result:
		t.Fatal("child cancellation released the result before the deadline")
	default:
	}
	select {
	case got := <-result:
		if got.err != nil || !reflect.DeepEqual(got.projection, want) || time.Now().Before(deadline) {
			t.Fatalf("late result changed or was delivered early: %v", got.err)
		}
		if delivered := <-delay.delivered; delivered.Before(deadline) {
			t.Fatal("delivery receipt preceded the deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("bounded delayed result did not finish")
	}
}

func TestCloudAcceptanceVerificationDelayAbortStopsReadAndHold(t *testing.T) {
	for _, duringRead := range []bool{false, true} {
		t.Run(map[bool]string{false: "hold", true: "read"}[duringRead], func(t *testing.T) {
			abortCtx, abort := context.WithCancel(t.Context())
			defer abort()
			entered := make(chan struct{})
			delay := &cloudDelayedGuest{
				uid: "owned", deadline: time.Now().Add(time.Minute), deliverAt: time.Now().Add(2 * time.Minute), abort: abortCtx,
				captured: make(chan time.Time, 1), delivered: make(chan time.Time, 1),
				read: func(ctx context.Context, _ *record, _ string) (podstatus.PodProjection, error) {
					close(entered)
					if duringRead {
						<-ctx.Done()
						return podstatus.PodProjection{}, ctx.Err()
					}
					return podstatus.PodProjection{}, nil
				},
			}
			result := make(chan error, 1)
			go func() { _, err := delay.readGuest(t.Context(), &record{UID: "owned"}, "unused"); result <- err }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("delegated reader did not start")
			}
			if !duringRead {
				select {
				case <-delay.captured:
				case <-time.After(time.Second):
					t.Fatal("reader did not reach its delayed result hold")
				}
			}
			abort()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) || len(delay.delivered) != 0 {
					t.Fatalf("abort produced a successful late-result receipt: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("scenario abort did not stop the reader promptly")
			}
		})
	}
}

func TestCloudAcceptanceVerificationDelayRefusesFailedOrForeignEvidence(t *testing.T) {
	readErr := errors.New("verification failed")
	for _, foreign := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed", true: "foreign"}[foreign], func(t *testing.T) {
			want := podstatus.PodProjection{}
			want.Metadata.UID = "guest"
			delay := &cloudDelayedGuest{
				uid: "owned", deadline: time.Now().Add(time.Minute), deliverAt: time.Now().Add(2 * time.Minute), abort: t.Context(),
				captured: make(chan time.Time, 1), delivered: make(chan time.Time, 1),
				read: func(context.Context, *record, string) (podstatus.PodProjection, error) {
					if foreign {
						return want, nil
					}
					return want, readErr
				},
			}
			rec := &record{UID: "owned"}
			if foreign {
				rec.UID = "foreign"
			}
			got, err := delay.readGuest(t.Context(), rec, "unused")
			if !reflect.DeepEqual(got, want) || (!foreign && !errors.Is(err, readErr)) || (foreign && err != nil) || len(delay.captured) != 0 || len(delay.delivered) != 0 {
				t.Fatal("failed or unrelated verification acquired a delayed-success receipt")
			}
		})
	}
}
