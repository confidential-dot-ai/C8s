package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// maxBody bounds the body copied into the report.
const maxBody = 4096

// report is the one JSON object the tool prints. Handshake is true only once
// the proxy relayed an application byte: in TLS 1.3 the client's Finished goes
// first, so a server that rejects the client certificate alerts after
// Handshake has returned, on the first read.
type report struct {
	Handshake bool   `json:"handshake"`
	Error     string `json:"error"`
	Bytes     int    `json:"bytes"`
	Status    int    `json:"status"`
	Body      string `json:"body"`
}

// dial connects to the inbound proxy at nodeAddr, presents cert, names dest
// (internal/cmds/armtlsmesh/proxy.go handleInbound: one "<host:port>\n"
// header, then the relayed stream) and sends GET /. timeout bounds the
// whole exchange. Every failure is reported, none returned.
func dial(ctx context.Context, nodeAddr, dest string, cert tls.Certificate, timeout time.Duration) report {
	var r report
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", nodeAddr)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer raw.Close()
	if err := raw.SetDeadline(deadline); err != nil {
		r.Error = err.Error()
		return r
	}

	conn := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The peer under test is the proxy's verification of us, not ours of
		// it. Under TLS 1.2 a rejected client certificate would fail the
		// handshake itself and change the report shape, hence the pin.
		InsecureSkipVerify: true,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	})
	if err := conn.HandshakeContext(ctx); err != nil {
		r.Error = err.Error()
		return r
	}

	// Header and request in one write; a rejecting server has sent its alert
	// by now and the write may fail with EPIPE, but the alert still waits in
	// the receive buffer, so read regardless.
	_, werr := fmt.Fprintf(conn, "%s\nGET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", dest, dest)
	data, rerr := readAll(conn)
	r.Bytes = len(data)
	if len(data) == 0 {
		if rerr == nil {
			rerr = io.EOF
		}
		r.Error = joinErrors(werr, rerr)
		return r
	}
	r.Handshake = true
	r.Error = joinErrors(werr, rerr)
	r.Status, r.Body = parseResponse(data)
	return r
}

// readAll reads until EOF or error; a clean EOF is not an error.
func readAll(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}

// parseResponse reads data as an HTTP response. Without one, the status is 0
// and the body is the raw bytes, so the report still shows what arrived.
func parseResponse(data []byte) (int, string) {
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return 0, string(data[:min(len(data), maxBody)])
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	return resp.StatusCode, string(body)
}
