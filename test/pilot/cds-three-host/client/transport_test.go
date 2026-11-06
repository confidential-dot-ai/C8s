package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTLSFailureClassificationNeverDispatchesOrRetries(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		failure error
		code    int
	}{
		{"verifier_deadline", fmt.Errorf("verification transport: %w", context.DeadlineExceeded), 75},
		{"rejected_attestation", errors.New("unapproved image"), 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var handshakes, requests atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			defer server.Close()
			client := server.Client()
			client.Transport.(*http.Transport).TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error {
				handshakes.Add(1)
				return scenario.failure
			}
			req, _ := http.NewRequestWithContext(t.Context(), "POST", server.URL, strings.NewReader("fixed phase"))
			response, err := sendPhase(client, req)
			if response != nil {
				response.Body.Close()
			}
			if err == nil || exitCode(err) != scenario.code || handshakes.Load() != 1 || requests.Load() != 0 {
				t.Fatalf("err=%v handshakes=%d requests=%d", err, handshakes.Load(), requests.Load())
			}
		})
	}
}

func TestStalledTunnelHasBoundedPredispatchFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Model virtctl accepting a connection while its upstream websocket
		// has failed: consume ClientHello but never answer the TLS handshake.
		_, _ = io.Copy(io.Discard, conn)
	}()
	client := &http.Client{Transport: &http.Transport{TLSHandshakeTimeout: 30 * time.Millisecond}}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://"+listener.Addr().String(), strings.NewReader("fixed phase"))
	response, err := sendPhase(client, req)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || exitCode(err) != 75 || ctx.Err() != nil {
		t.Fatalf("stalled TLS was not distinguished before overall deadline: %v", err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("failed TLS connection was not closed")
	}
}

func TestDeadlineAfterDispatchNeverAllowsRetry(t *testing.T) {
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
	response, err := sendPhase(client, req)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || exitCode(err) != 1 || requests.Load() != 1 {
		t.Fatalf("dispatched request allowed retry: err=%v requests=%d", err, requests.Load())
	}
}
