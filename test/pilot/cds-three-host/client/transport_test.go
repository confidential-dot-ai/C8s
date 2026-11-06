package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestOnlyTimedOutTLSBeforeDispatchCanRetry(t *testing.T) {
	for _, scenario := range []struct {
		name                                      string
		failure                                   error
		persistent                                bool
		wantHandshakes, wantRequests, wantRetries int32
	}{
		{"transient_verifier_deadline", fmt.Errorf("verification transport: %w", context.DeadlineExceeded), false, 2, 1, 1},
		{"persistent_verifier_deadline", context.DeadlineExceeded, true, 2, 0, 1},
		{"rejected_attestation", errors.New("unapproved image"), true, 1, 0, 0},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var handshakes, requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, _ := io.ReadAll(r.Body)
				if string(body) != "fixed phase" || r.Header.Get("Authorization") != "unchanged authorization" {
					t.Error("phase body or authorization changed")
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			client := server.Client()
			transport := client.Transport.(*http.Transport)
			transport.TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error {
				if handshakes.Add(1) == 1 || scenario.persistent {
					return scenario.failure
				}
				return nil
			}
			req, _ := http.NewRequestWithContext(t.Context(), "POST", server.URL, strings.NewReader("fixed phase"))
			req.Header.Set("Authorization", "unchanged authorization")
			response, retries, err := sendPhase(client, req)
			if response != nil {
				response.Body.Close()
			}
			if (err == nil) != (scenario.wantRequests == 1) || handshakes.Load() != scenario.wantHandshakes ||
				requests.Load() != scenario.wantRequests || int32(retries) != scenario.wantRetries {
				t.Fatalf("err=%v handshakes=%d requests=%d retries=%d", err, handshakes.Load(), requests.Load(), retries)
			}
		})
	}
}

func TestDeadlineAfterDispatchNeverResubmitsPhase(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).ResponseHeaderTimeout = 30 * time.Millisecond
	req, _ := http.NewRequestWithContext(t.Context(), "POST", server.URL, strings.NewReader("fixed phase"))
	response, retries, err := sendPhase(client, req)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || requests.Load() != 1 || retries != 0 {
		t.Fatalf("dispatched request retried: err=%v requests=%d retries=%d", err, requests.Load(), retries)
	}
}
