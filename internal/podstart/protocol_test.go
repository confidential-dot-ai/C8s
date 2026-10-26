package podstart

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var testStart = Request{ContainerID: "container-123", SandboxID: "sandbox-456", PID: 731}

const testBody = `{"containerId":"container-123","sandboxId":"sandbox-456","pid":731}`

func TestRequestRejectsAmbiguousProcessIdentity(t *testing.T) {
	for _, id := range []string{"", ".", "..", "a/b", "a\\b", "a b", "a\x00b", "café", strings.Repeat("a", 129)} {
		t.Run(id, func(t *testing.T) {
			start := testStart
			start.ContainerID = id
			if start.Validate() == nil {
				t.Fatal("invalid container ID was accepted")
			}
			start = testStart
			start.SandboxID = id
			if start.Validate() == nil {
				t.Fatal("invalid sandbox ID was accepted")
			}
		})
	}
	start := testStart
	start.PID = 0
	if start.Validate() == nil {
		t.Fatal("a request without a created process was accepted")
	}
	start = Request{ContainerID: strings.Repeat("a", 128), SandboxID: "A_b.c-9", PID: 1}
	if err := start.Validate(); err != nil {
		t.Fatalf("valid bounded runtime identity refused: %v", err)
	}
}

func TestHandlerRejectsBeforeCallingAuthority(t *testing.T) {
	tests := []struct {
		name, method, path, body string
		root                     bool
		status                   int
	}{
		{"non-root", http.MethodPost, "/v1/consume", testBody, false, http.StatusForbidden},
		{"wrong method", http.MethodGet, "/v1/consume", testBody, true, http.StatusBadRequest},
		{"wrong path", http.MethodPost, "/v1/consume/", testBody, true, http.StatusBadRequest},
		{"query", http.MethodPost, "/v1/consume?containerId=other", testBody, true, http.StatusBadRequest},
		{"malformed", http.MethodPost, "/v1/consume", "{", true, http.StatusBadRequest},
		{"null", http.MethodPost, "/v1/consume", "null", true, http.StatusBadRequest},
		{"missing process", http.MethodPost, "/v1/consume", `{"containerId":"c","sandboxId":"s"}`, true, http.StatusBadRequest},
		{"negative process", http.MethodPost, "/v1/consume", `{"containerId":"c","sandboxId":"s","pid":-1}`, true, http.StatusBadRequest},
		{"overflow process", http.MethodPost, "/v1/consume", `{"containerId":"c","sandboxId":"s","pid":4294967296}`, true, http.StatusBadRequest},
		{"string process", http.MethodPost, "/v1/consume", `{"containerId":"c","sandboxId":"s","pid":"1"}`, true, http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/v1/consume", `{"containerId":"c","sandboxId":"s","pid":1,"allowed":true}`, true, http.StatusBadRequest},
		{"second object", http.MethodPost, "/v1/consume", testBody + testBody, true, http.StatusBadRequest},
		{"trailing scalar", http.MethodPost, "/v1/consume", testBody + " true", true, http.StatusBadRequest},
		{"oversized trailing whitespace", http.MethodPost, "/v1/consume", testBody + strings.Repeat(" ", requestLimit), true, http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			h := handler(func(context.Context, Request) error { calls++; return nil })
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			req = req.WithContext(context.WithValue(req.Context(), rootPeerKey{}, tt.root))
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != tt.status || calls != 0 {
				t.Fatalf("status=%d authority calls=%d; want %d and zero calls", out.Code, calls, tt.status)
			}
		})
	}
}

func TestHandlerRequiresSuccessfulUncancelledAuthority(t *testing.T) {
	for _, name := range []string{"allowed", "denied", "cancelled during admission"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var got Request
			h := handler(func(ctx context.Context, start Request) error {
				got = start
				if _, ok := ctx.Deadline(); !ok {
					t.Error("authority received an unbounded context")
				}
				switch name {
				case "denied":
					return errors.New("policy refusal")
				case "cancelled during admission":
					cancel()
				}
				return nil
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/consume", strings.NewReader(testBody))
			req = req.WithContext(context.WithValue(ctx, rootPeerKey{}, true))
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			want := http.StatusForbidden
			if name == "allowed" {
				want = http.StatusNoContent
			}
			if out.Code != want || got != testStart {
				t.Fatalf("status=%d identity=%+v; want %d and %+v", out.Code, got, want, testStart)
			}
		})
	}
}
