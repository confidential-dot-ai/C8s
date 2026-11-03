package metadatapilot

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/objectwal"
)

const testToken = "synthetic-metadata-token-not-the-wal-key"

func openTest(t *testing.T, path string) (*Service, *Client) {
	t.Helper()
	s, err := Open(path, "pilot", testToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	server := httptest.NewTLSServer(s)
	t.Cleanup(server.Close)
	c, err := NewClient(server.URL, "pilot", testToken, server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return s, c
}

func TestConditionalPublicationHasOneWinnerAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	s, c := openTest(t, path)
	first, err := c.Put(t.Context(), "pilot/head", []byte("encrypted-first"), "")
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			_, err := c.Put(t.Context(), "pilot/head", []byte("encrypted-next"), first)
			if err == nil {
				winners.Add(1)
			} else if !errors.Is(err, objectwal.ErrConflict) {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("winners=%d", winners.Load())
	}
	head, err := c.Get(t.Context(), "pilot/head")
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, c2 := openTest(t, path)
	restored, err := c2.Get(t.Context(), "pilot/head")
	if err != nil || restored.ETag != head.ETag || !bytes.Equal(restored.Data, head.Data) {
		t.Fatalf("reopen: %v %+v", err, restored)
	}
	var count int
	if err := s2.db.QueryRow(`SELECT count(*) FROM receipts`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("receipts=%d err=%v", count, err)
	}
	if wrong, err := Open(path, "another-cluster", testToken); err == nil {
		wrong.Close()
		t.Fatal("reused database with another namespace")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestLostCommitReplyIsNotRetriedByClient(t *testing.T) {
	_, c := openTest(t, filepath.Join(t.TempDir(), "metadata.db"))
	base := c.client.Transport
	var puts atomic.Int32
	c.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		res, err := base.RoundTrip(r)
		if r.Method == http.MethodPut {
			puts.Add(1)
			if err != nil {
				return res, err
			}
			res.Body.Close()
			return nil, errors.New("lost reply after commit")
		}
		return res, err
	})
	if _, err := c.Put(t.Context(), "pilot/head", []byte("committed"), ""); err == nil {
		t.Fatal("lost response succeeded")
	}
	obj, err := c.Get(t.Context(), "pilot/head")
	if err != nil || string(obj.Data) != "committed" || puts.Load() != 1 {
		t.Fatalf("outcome=%+v err=%v puts=%d", obj, err, puts.Load())
	}
}

func TestAuthenticationNamespaceAndRedirects(t *testing.T) {
	s, c := openTest(t, filepath.Join(t.TempDir(), "metadata.db"))
	wrong, err := NewClient(c.endpoint, "pilot", strings.Repeat("wrong", 8), c.client.Transport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrong.Put(t.Context(), "pilot/head", []byte("forged"), ""); err == nil {
		t.Fatal("accepted wrong token")
	}
	if _, err := c.Put(t.Context(), "elsewhere/head", []byte("forged"), ""); err == nil {
		t.Fatal("accepted wrong key")
	}
	if s.Stats().Writes != 0 {
		t.Fatal("unauthorized call reached actor")
	}
	var redirected atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	rc, _ := NewClient(redirect.URL, "pilot", testToken, redirect.Client().Transport)
	defer rc.Close()
	if _, err := rc.Put(t.Context(), "pilot/head", []byte("opaque"), ""); err == nil || redirected.Load() != 0 {
		t.Fatal("followed authenticated redirect")
	}
}

func TestBackpressureIncludesBodiesAndCloseUnblocksRequests(t *testing.T) {
	s, _ := openTest(t, filepath.Join(t.TempDir(), "metadata.db"))
	var wg sync.WaitGroup
	var pipes []*io.PipeWriter
	for range Capacity {
		reader, writer := io.Pipe()
		pipes = append(pipes, writer)
		r := httptest.NewRequest(http.MethodPut, "https://metadata"+HeadPath, reader)
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Authorization", "Bearer "+testToken)
		r.Header.Set("X-CDS-Namespace", "pilot")
		r.Header.Set("If-None-Match", "*")
		wg.Go(func() { s.ServeHTTP(httptest.NewRecorder(), r) })
	}
	deadline := time.Now().Add(time.Second)
	for len(s.slots) != Capacity && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.slots) != Capacity {
		t.Fatal("requests did not reach body admission")
	}
	r := httptest.NewRequest(http.MethodGet, "https://metadata"+HeadPath, nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("X-CDS-Namespace", "pilot")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("overflow HTTP %d", w.Code)
	}
	s.Close()
	for _, p := range pipes {
		_ = p.Close()
	}
	wg.Wait()
	if len(s.slots) != 0 {
		t.Fatal("admission slots leaked")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	r = httptest.NewRequestWithContext(ctx, http.MethodGet, "https://metadata"+HeadPath, nil)
	r.Header.Set("Authorization", "Bearer "+testToken)
	r.Header.Set("X-CDS-Namespace", "pilot")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed service HTTP %d", w.Code)
	}
}
