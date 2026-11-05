package snpaccept

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
)

func TestNativeMetadataRelayScopeAndCompletion(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	relay := NewRelay(ctx)
	handler := relay.WithMetadata("owned")
	request := func() *http.Request {
		q := httptest.NewRequest(http.MethodPost, metadatapilot.StateReadPath, bytes.NewBufferString(`{"checks":[]}`)).WithContext(ctx)
		q.Header.Set("X-CDS-Namespace", "owned")
		q.Header.Set("Authorization", "Bearer "+NativeMetadataToken)
		return q
	}
	for _, mutate := range []func(*http.Request){
		func(q *http.Request) { q.Header.Set("X-CDS-Namespace", "other") },
		func(q *http.Request) { q.Header.Del("Authorization") },
		func(q *http.Request) { q.Method = http.MethodGet },
		func(q *http.Request) { q.URL.RawQuery = "namespace=other" },
	} {
		q := request()
		mutate(q)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, q)
		if w.Code != 403 {
			t.Fatalf("out of scope accepted: %d", w.Code)
		}
	}
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { handler.ServeHTTP(w, request()); close(done) }()
	q, err := relay.Poll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if q.Method != "STATE_READ" || q.Path != "/pilot/owned/metadata/v1/state/read" || !bytes.Equal(q.Data, []byte(`{"checks":[]}`)) {
		t.Fatal("wrong tunnel scope")
	}
	if !relay.Complete(ctx, StorageResponse{ID: q.ID, Status: 412, Data: []byte("conflict")}) {
		t.Fatal("reply refused")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if w.Code != 412 || w.Body.String() != "conflict" {
		t.Fatal("commit outcome changed")
	}
}
