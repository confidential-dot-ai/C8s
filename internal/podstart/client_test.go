package podstart

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func socketDir(t *testing.T) string {
	t.Helper()
	// Short names also fit Darwin's smaller sockaddr_un.sun_path.
	dir, err := os.MkdirTemp("/tmp", "podstart-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	return dir
}

func mockUnixServer(t *testing.T, h http.Handler) string {
	t.Helper()
	socket := filepath.Join(socketDir(t), "gate.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(l) }()
	t.Cleanup(func() {
		_ = srv.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("mock server: %v", err)
		}
	})
	return socket
}

func TestConsumeRequiresExplicitPermissionWithoutRedirectOrRetry(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusOK, http.StatusAccepted, http.StatusForbidden, http.StatusInternalServerError, http.StatusTemporaryRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			socket := mockUnixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path == "/redirected" {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				var got Request
				if err := json.NewDecoder(r.Body).Decode(&got); err != nil || got != testStart || r.Method != http.MethodPost {
					t.Errorf("unexpected request: identity=%+v error=%v method=%s", got, err, r.Method)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Location", "http://pod-start/redirected")
				w.WriteHeader(status)
			}))
			err := Consume(context.Background(), socket, testStart)
			if (err == nil) != (status == http.StatusNoContent) || calls.Load() != 1 {
				t.Fatalf("Consume error=%v calls=%d; only one explicit 204 may authorize", err, calls.Load())
			}
		})
	}
}

func TestConsumeUnavailableOrCancelledAuthorityDenies(t *testing.T) {
	missing := filepath.Join(socketDir(t), "missing.sock")
	if err := Consume(context.Background(), missing, testStart); err == nil {
		t.Fatal("missing authority permitted start")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Consume(ctx, missing, testStart); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller was not preserved: %v", err)
	}
	invalid := testStart
	invalid.PID = 0
	if err := Consume(context.Background(), missing, invalid); err == nil || strings.Contains(err.Error(), "contact") {
		t.Fatalf("invalid request was not refused before connecting: %v", err)
	}
}

func TestConsumePreservesShorterCallerDeadline(t *testing.T) {
	entered := make(chan struct{})
	socket := mockUnixServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-r.Context().Done()
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := Consume(ctx, socket, testStart)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked authority did not fail at caller deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= Timeout {
		t.Fatalf("caller deadline was replaced by the default timeout: %s", elapsed)
	}
	select {
	case <-entered:
	default:
		t.Fatal("deadline test never reached the authority")
	}
}

func TestConsumeRejectsBrokenOrOversizedHTTPResponse(t *testing.T) {
	for _, response := range []string{"", "not HTTP\r\n\r\n", "HTTP/1.1 204 No Content\r\nX-Oversized: " + strings.Repeat("x", 8192) + "\r\n\r\n"} {
		t.Run(responseName(response), func(t *testing.T) {
			socket := filepath.Join(socketDir(t), "gate.sock")
			l, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				_, _ = io.WriteString(c, response)
			}()
			t.Cleanup(func() { _ = l.Close(); <-done })
			if err := Consume(context.Background(), socket, testStart); err == nil {
				t.Fatal("broken or unbounded response permitted start")
			}
		})
	}
}

func responseName(response string) string {
	if response == "" {
		return "connection lost"
	}
	if strings.HasPrefix(response, "HTTP/") {
		return "oversized headers"
	}
	return "malformed response"
}
