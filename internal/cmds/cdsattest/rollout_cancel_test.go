package cdsattest

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestRolloutBoundChangeResetsUpstreamPool(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	var handshakes atomic.Int32
	backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{
		TrustedCAFile: caFile,
		ServerName:    "example.com",
		VerifyPeer: func(*x509.Certificate) error {
			handshakes.Add(1)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	fence.onBoundChange(backend.ResetConnections)
	poll := func() {
		t.Helper()
		if _, err := fence.poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	forward := func() {
		t.Helper()
		if _, err := backend.Forward(context.Background(), types.TunnelRequest{Method: http.MethodGet, Path: "/"}); err != nil {
			t.Fatal(err)
		}
	}

	poll()
	forward()
	forward()
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("handshakes after two requests on one bound = %d, want 1 (pooled)", got)
	}
	poll()
	forward()
	if got := handshakes.Load(); got != 1 {
		t.Fatalf("an unchanged bound dropped the pool: handshakes = %d, want 1", got)
	}
	cds.setBound("sha256:p", "sha256:q")
	poll()
	forward()
	if got := handshakes.Load(); got != 2 {
		t.Fatalf("handshakes after the bound changed = %d, want 2 (pool dropped, peer re-checked)", got)
	}
	cds.setBound("sha256:q")
	poll()
	forward()
	if got := handshakes.Load(); got != 3 {
		t.Fatalf("handshakes after the bound narrowed = %d, want 3", got)
	}
}

func TestRolloutRequestContextCancelledOnBoundChange(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := fence.requestContext(context.Background())
	defer cancel()
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil {
		t.Fatal("an unchanged bound cancelled the request")
	}
	cds.setBound("sha256:p", "sha256:q")
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("bound change did not cancel the request")
	}
	if !errors.Is(context.Cause(ctx), errBoundChanged) {
		t.Fatalf("cause = %v, want errBoundChanged", context.Cause(ctx))
	}
	later, cancelLater := fence.requestContext(context.Background())
	defer cancelLater()
	if later.Err() != nil {
		t.Fatal("a request admitted under the new bound starts cancelled")
	}
}

// TestLBForwarderEndsStreamOnBoundChange: a streamed response (SSE) in flight
// when the bound changes is cut off, and the upstream request is cancelled.
func TestLBForwarderEndsStreamOnBoundChange(t *testing.T) {
	upstreamDone := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("data: first\n\n"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			close(upstreamDone)
		case <-time.After(10 * time.Second):
		}
	}))
	defer upstream.Close()
	backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	forwarder, err := newLBForwarder(fence, backend, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(forwarder)
	defer front.Close()

	req, _ := http.NewRequest(http.MethodGet, front.URL+"/v1/stream", nil)
	req.Header.Set(connectionTimeHeader, "0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first\n" {
		t.Fatalf("first event = %q, %v", line, err)
	}

	cds.setBound("sha256:p", "sha256:q")
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	ended := make(chan struct{})
	go func() {
		io.Copy(io.Discard, resp.Body)
		close(ended)
	}()
	select {
	case <-ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the stream kept flowing after the bound changed")
	}
	select {
	case <-upstreamDone:
	case <-time.After(3 * time.Second):
		t.Fatal("the upstream request was not cancelled")
	}
}

// blockingBackend holds every forward until its context ends.
type blockingBackend struct {
	started chan struct{}
	cause   chan error
}

func (b *blockingBackend) Forward(ctx context.Context, _ types.TunnelRequest) (types.TunnelResponse, error) {
	b.started <- struct{}{}
	<-ctx.Done()
	b.cause <- context.Cause(ctx)
	return types.TunnelResponse{}, ctx.Err()
}

func TestTunnelForwardCancelledOnBoundChange(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	backend := &blockingBackend{started: make(chan struct{}, 1), cause: make(chan error, 1)}
	srv := NewServer(Config{
		Evidence:             FixtureEvidenceProvider{Raw: json.RawMessage(`{"attestation_report":"AAAA","cert_chain":{"vcek":"BBBB"}}`), Platform: "snp", Generation: "genoa"},
		FrontDoorMode:        types.FrontDoorModeCDS,
		MeshIdentityCertFile: identity.certFile,
		MeshIdentityKeyFile:  identity.keyFile,
		MeshIdentityCAFile:   identity.caFile,
		Backend:              backend,
		Rollout:              newRollout(cdsSrv.URL, identity.caFile),
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	nonce := make([]byte, 32)
	rand.Read(nonce)
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := fetchBundle(t, ts.URL, ck, nonce)
	channel, sessionID := clientChannelFromBundle(t, bundle, ck, nonce)
	done := make(chan int, 1)
	go func() {
		resp := postSealedTunnel(t, ts.URL, channel, sessionID, types.TunnelRequest{Method: "GET", Path: "/stream"})
		resp.Body.Close()
		done <- resp.StatusCode
	}()
	select {
	case <-backend.started:
	case <-time.After(3 * time.Second):
		t.Fatal("forward never started")
	}
	// A narrowing keeps the session's envelope covering the bound, so only
	// the request context can end this forward.
	cds.setBound()
	if _, err := srv.rollout.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case cause := <-backend.cause:
		if !errors.Is(cause, errBoundChanged) {
			t.Fatalf("forward ended with %v, want errBoundChanged", cause)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the forward kept running after the bound changed")
	}
	<-done
}
