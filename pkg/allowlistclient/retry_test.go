package allowlistclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// countingAuth mints a distinct token per call, so a test can tell whether
// each attempt was signed afresh.
type countingAuth struct {
	mu sync.Mutex
	n  int
}

func (a *countingAuth) Authorization(string, string, []byte) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	return "Bearer token-" + string(rune('a'+a.n)), nil
}

// statusSequence answers each write with the next status, then 204; it records
// the Authorization and If-Match of every request.
func statusSequence(t *testing.T, retryAfter string, statuses ...int) (*httptest.Server, func() (tokens, ifMatch []string)) {
	t.Helper()
	var mu sync.Mutex
	var tokens, ifMatch []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		tokens = append(tokens, r.Header.Get("Authorization"))
		ifMatch = append(ifMatch, r.Header.Get("If-Match"))
		if len(statuses) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		status := statuses[0]
		statuses = statuses[1:]
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		http.Error(w, http.StatusText(status), status)
	}))
	t.Cleanup(srv.Close)
	return srv, func() ([]string, []string) {
		mu.Lock()
		defer mu.Unlock()
		return tokens, ifMatch
	}
}

// emptyDocument is the allowlist a write test sends; what it holds is beside
// the point here.
func emptyDocument() *allowlist.Allowlist {
	return &allowlist.Allowlist{Schema: allowlist.Schema}
}

func TestWriteRetriesRateLimitAndUnavailable(t *testing.T) {
	srv, seen := statusSequence(t, "0", http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusTooManyRequests)
	auth := &countingAuth{}
	if err := NewClient(srv.URL).ReplaceAll(context.Background(), emptyDocument(), "", auth); err != nil {
		t.Fatalf("write refused twice with 429 and once with 503, then accepted: %v", err)
	}
	tokens, _ := seen()
	if len(tokens) != 4 {
		t.Fatalf("sent %d requests, want 4", len(tokens))
	}
	distinct := map[string]bool{}
	for _, token := range tokens {
		distinct[token] = true
	}
	if len(distinct) != 4 {
		t.Fatalf("attempts reused a token: %v", tokens)
	}
}

func TestWriteGivesUpAfterMaxAttempts(t *testing.T) {
	statuses := make([]int, maxWriteAttempts+5)
	for i := range statuses {
		statuses[i] = http.StatusTooManyRequests
	}
	srv, seen := statusSequence(t, "0", statuses...)
	err := NewClient(srv.URL).ReplaceAll(context.Background(), emptyDocument(), "", &countingAuth{})
	var se *operatorauth.StatusError
	if !errors.As(err, &se) || se.Status != http.StatusTooManyRequests {
		t.Fatalf("err = %v, want a 429 StatusError", err)
	}
	if tokens, _ := seen(); len(tokens) != maxWriteAttempts {
		t.Fatalf("sent %d requests, want %d", len(tokens), maxWriteAttempts)
	}
}

// A refusal of the write itself is final: sending it again cannot help.
func TestWriteDoesNotRetryOtherRefusals(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
		http.StatusPreconditionFailed, http.StatusUnprocessableEntity, http.StatusInternalServerError} {
		srv, seen := statusSequence(t, "0", status)
		err := NewClient(srv.URL).ReplaceAll(context.Background(), emptyDocument(), "", &countingAuth{})
		var se *operatorauth.StatusError
		if !errors.As(err, &se) || se.Status != status {
			t.Fatalf("status %d: err = %v", status, err)
		}
		if tokens, _ := seen(); len(tokens) != 1 {
			t.Fatalf("status %d: sent %d requests, want 1", status, len(tokens))
		}
	}
}

func TestWriteRetryStopsOnContextCancel(t *testing.T) {
	srv, _ := statusSequence(t, "30", http.StatusTooManyRequests)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := NewClient(srv.URL).ReplaceAll(ctx, emptyDocument(), "", &countingAuth{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context's deadline", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("waited out Retry-After despite the cancelled context")
	}
}

func TestRetryWait(t *testing.T) {
	for _, tt := range []struct {
		header  string
		attempt int
		want    time.Duration
	}{
		{"0", 1, 0},
		{"2", 1, 2 * time.Second},
		{"3600", 1, maxRetryWait},
		{"", 1, firstRetryWait},
		{"", 3, 4 * firstRetryWait},
		{"", 20, maxRetryWait},
		{"Wed, 21 Oct 2015 07:28:00 GMT", 2, 2 * firstRetryWait},
		{"-1", 1, firstRetryWait},
	} {
		if got := retryWait(tt.header, tt.attempt); got != tt.want {
			t.Errorf("retryWait(%q, %d) = %v, want %v", tt.header, tt.attempt, got, tt.want)
		}
	}
}

func TestReplaceAllSendsStrongIfMatch(t *testing.T) {
	srv, seen := statusSequence(t, "")
	c := NewClient(srv.URL)
	if err := c.ReplaceAll(context.Background(), emptyDocument(), "7", &countingAuth{}); err != nil {
		t.Fatal(err)
	}
	if err := c.ReplaceAll(context.Background(), emptyDocument(), "", &countingAuth{}); err != nil {
		t.Fatal(err)
	}
	if _, ifMatch := seen(); len(ifMatch) != 2 || ifMatch[0] != `"7"` || ifMatch[1] != "" {
		t.Fatalf("If-Match headers = %q, want [\"7\" none]", ifMatch)
	}
}
