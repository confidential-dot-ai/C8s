package allowlistclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// hangingServer accepts the connection and never answers.
func hangingServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanup is LIFO: release the handler before Close waits on it.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}

// TestNewClientBoundsRequests pins the overall deadline. This client is the
// shared transport for both enforcers and the CLI; http.DefaultClient has no
// timeout, so an unanswered fetch would park the caller indefinitely.
func TestNewClientBoundsRequests(t *testing.T) {
	if got := NewClient("https://cds.example.com").httpClient.Timeout; got != requestTimeout {
		t.Errorf("Timeout = %v, want %v", got, requestTimeout)
	}
}

func TestListReturnsWithinItsTimeout(t *testing.T) {
	srv := hangingServer(t)
	c := NewClientWithHTTP(srv.URL, &http.Client{Timeout: 100 * time.Millisecond})

	done := make(chan error, 1)
	go func() { _, _, err := c.List(context.Background()); done <- err }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("List returned no error against a server that never answers")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List did not return within its timeout")
	}
}

func TestListReturnsOnContextCancel(t *testing.T) {
	srv := hangingServer(t)
	c := NewClient(srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, err := c.List(ctx); done <- err }()
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("List error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List did not return after context cancel")
	}
}

// TestListNonOKYieldsStatusError pins the typed error callers branch on, and
// that it carries the code and the server's message.
func TestListNonOKYieldsStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "cds is not ready\n")
	}))
	defer srv.Close()

	_, _, err := NewClient(srv.URL).List(context.Background())
	var se *operatorauth.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("List error = %v (%T), want *StatusError", err, err)
	}
	if se.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", se.Status, http.StatusServiceUnavailable)
	}
	if se.Body != "cds is not ready" {
		t.Errorf("Body = %q, want %q", se.Body, "cds is not ready")
	}
}

// TestListRejectsNonJSONContentType keeps a captive portal or an HTML error
// page from being parsed as an allowlist.
func TestListRejectsNonJSONContentType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `{"schema":"c8s.allowlist/v1","workloads":{}}`)
	}))
	defer srv.Close()

	if _, _, err := NewClient(srv.URL).List(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "unexpected content type") {
		t.Fatalf("List error = %v, want an unexpected-content-type refusal", err)
	}
}

// TestListEnforcesTheResponseCap: a compromised or buggy CDS must not be able
// to OOM the enforcer process by answering with an unbounded body.
func TestListEnforcesTheResponseCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := strings.Repeat("a", 64*1024)
		for written := int64(0); written <= maxAllowlistResponseBytes; written += int64(len(chunk)) {
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	if _, _, err := NewClient(srv.URL).List(context.Background()); !errors.Is(err, errAllowlistResponseTooLarge) {
		t.Fatalf("List error = %v, want %v", err, errAllowlistResponseTooLarge)
	}
}
