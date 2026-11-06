package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

// sendPhase permits one retry only when TLS itself times out before any HTTP
// headers were written. A phase is never retried after dispatch or after an
// attestation/pin rejection. Both attempts share the original overall deadline.
func sendPhase(client *http.Client, request *http.Request) (*http.Response, int, error) {
	for attempt := 0; ; attempt++ {
		var handshakeTimeout, wroteHeaders atomic.Bool
		trace := &httptrace.ClientTrace{
			TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
				handshakeTimeout.Store(errors.Is(err, context.DeadlineExceeded))
			},
			WroteHeaders: func() { wroteHeaders.Store(true) },
		}
		req := request.Clone(httptrace.WithClientTrace(request.Context(), trace))
		if attempt > 0 {
			body, err := request.GetBody()
			if err != nil {
				return nil, attempt, err
			}
			req.Body = body
		}
		response, err := client.Do(req)
		if err == nil || attempt == 1 || !handshakeTimeout.Load() || wroteHeaders.Load() ||
			request.Context().Err() != nil || request.GetBody == nil {
			return response, attempt, err
		}
		if response != nil {
			response.Body.Close()
		}
		pause := time.NewTimer(time.Second)
		select {
		case <-request.Context().Done():
			pause.Stop()
			return nil, attempt, request.Context().Err()
		case <-pause.C:
		}
	}
}
