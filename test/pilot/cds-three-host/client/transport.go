package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync/atomic"
)

// The controller may replace its broken tunnel only for this typed failure.
// An arbitrary peer error string cannot select the dedicated exit status.
type notDispatched struct{ error }

func (e *notDispatched) Unwrap() error { return e.error }

func exitCode(err error) int {
	var absent *notDispatched
	if errors.As(err, &absent) {
		return 75
	}
	return 1
}

// sendPhase makes one attempt. Only a TLS timeout before any HTTP headers were
// written permits the controller to replace the tunnel and retry once. There is
// no retry within the broken listener, nor after dispatch or pin rejection.
func sendPhase(client *http.Client, request *http.Request) (*http.Response, error) {
	var handshakeTimeout, wroteHeaders atomic.Bool
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			var timeout net.Error
			handshakeTimeout.Store(errors.Is(err, context.DeadlineExceeded) ||
				(errors.As(err, &timeout) && timeout.Timeout()))
		},
		WroteHeaders: func() { wroteHeaders.Store(true) },
	}
	req := request.Clone(httptrace.WithClientTrace(request.Context(), trace))
	response, err := client.Do(req)
	if err != nil && handshakeTimeout.Load() && !wroteHeaders.Load() && request.Context().Err() == nil {
		return response, &notDispatched{err}
	}
	return response, err
}
