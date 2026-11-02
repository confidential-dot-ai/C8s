package objectwal

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestS3ConditionalHeadersAndNoHiddenRetry(t *testing.T) {
	var requests atomic.Int32
	var fail atomic.Bool
	var accessKey atomic.Value
	accessKey.Store("synthetic")
	store := newStore()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("unsigned S3 request")
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential="+accessKey.Load().(string)+"/") {
			t.Error("request used credentials from before attested refresh")
		}
		if r.URL.Path != "/pilot/key" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		switch r.Method {
		case http.MethodPut:
			if fail.Load() {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `<Error><Code>InternalError</Code></Error>`)
				return
			}
			if r.Header.Get("If-None-Match") != "*" && r.Header.Get("If-Match") == "" {
				t.Error("unconditional PUT")
			}
			data, _ := io.ReadAll(r.Body)
			etag, err := store.write(r.Context(), "key", data, r.Header.Get("If-Match"))
			if err != nil {
				w.WriteHeader(http.StatusPreconditionFailed)
				fmt.Fprint(w, `<Error><Code>PreconditionFailed</Code></Error>`)
				return
			}
			w.Header().Set("ETag", etag)
		case http.MethodGet:
			obj, err := store.Get(r.Context(), "key")
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `<Error><Code>NoSuchKey</Code></Error>`)
				return
			}
			w.Header().Set("ETag", obj.ETag)
			_, _ = w.Write(obj.Data)
		default:
			t.Errorf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()
	s, err := NewS3(S3Config{Bucket: "pilot", Region: "us-west-2", Endpoint: server.URL, PathStyle: true, HTTPClient: server.Client()}, Credentials{AccessKeyID: "synthetic", SecretAccessKey: "synthetic-secret"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := s.Get(ctx, "key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	etag, err := s.Put(ctx, "key", []byte("first"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, "key", []byte("collision"), ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("create conflict: %v", err)
	}
	if _, err := s.Put(ctx, "key", []byte("stale"), `"stale"`); !errors.Is(err, ErrConflict) {
		t.Fatalf("update conflict: %v", err)
	}
	if _, err := s.Put(ctx, "key", []byte("second"), etag); err != nil {
		t.Fatal(err)
	}
	obj, err := s.Get(ctx, "key")
	if err != nil || !bytes.Equal(obj.Data, []byte("second")) {
		t.Fatalf("read: %+v %v", obj, err)
	}
	fail.Store(true)
	before := requests.Load()
	if _, err := s.Put(ctx, "key", []byte("unknown"), obj.ETag); err == nil {
		t.Fatal("server error accepted")
	}
	if requests.Load() != before+1 {
		t.Fatal("SDK retried conditional PUT and hid an ambiguous outcome")
	}
	fail.Store(false)
	accessKey.Store("refreshed")
	if err := s.SetCredentials(Credentials{AccessKeyID: "refreshed", SecretAccessKey: "new-synthetic-secret", SessionToken: "synthetic-session"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, "key"); err != nil {
		t.Fatal(err)
	}
}
