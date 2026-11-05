package snpaccept

import (
	"context"
	"testing"
	"time"
)

func TestRelayNeverAcknowledgesBeforeExternalCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := NewRelay(ctx)
	done := make(chan StorageResponse, 1)
	go func() {
		response, err := r.Exchange(ctx, StorageRequest{Method: "PUT", Path: "/pilot/a/head", Absent: "*", Data: []byte("ciphertext")})
		if err == nil {
			done <- response
		}
	}()
	q, err := r.Poll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("write acknowledged before durable host response")
	case <-time.After(20 * time.Millisecond):
	}
	if !r.Complete(ctx, StorageResponse{ID: q.ID, Status: 200, ETag: `"1"`}) {
		t.Fatal("completion refused")
	}
	select {
	case response := <-done:
		if response.ETag != `"1"` {
			t.Fatal("etag lost")
		}
	case <-time.After(time.Second):
		t.Fatal("completion not delivered")
	}
	if r.Complete(ctx, StorageResponse{ID: q.ID, Status: 200}) {
		t.Fatal("duplicate completion accepted")
	}
}

func TestRelayCancellationAndBackpressure(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r := NewRelay(ctx)
	for range cap(r.slots) {
		r.slots <- struct{}{}
	}
	if _, err := r.Exchange(ctx, StorageRequest{}); err == nil {
		t.Fatal("full admission budget accepted")
	}
	for range cap(r.slots) {
		<-r.slots
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	if _, err := r.Exchange(stopped, StorageRequest{}); err == nil {
		t.Fatal("canceled request succeeded")
	}
	cancel()
	<-r.done
	if _, err := r.Exchange(context.Background(), StorageRequest{}); err == nil {
		t.Fatal("stopped relay succeeded")
	}
}
