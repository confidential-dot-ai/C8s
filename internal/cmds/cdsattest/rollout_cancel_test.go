package cdsattest

import (
	"bufio"
	"bytes"
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

	"github.com/fxamacker/cbor/v2"

	"github.com/confidential-dot-ai/c8s/pkg/overenc"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

func TestRolloutBoundChangeResetsUpstreamPool(t *testing.T) {
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var heldConn, lastConn atomic.Value
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			heldConn.Store(r.RemoteAddr)
			entered <- struct{}{}
			<-release
			return
		}
		lastConn.Store(r.RemoteAddr)
	}))
	defer upstream.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	fence := newRollout(cdsSrv.URL, identity.caFile)
	var handshakes atomic.Int32
	// newUpstream is the constructor run() uses: it registers the pool reset.
	backend, err := newUpstream(config{upstream: upstream.URL, upstreamCAFile: caFile, upstreamServerName: "example.com"}, fence,
		func(*x509.Certificate) error {
			handshakes.Add(1)
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	poll := func() {
		t.Helper()
		if _, err := fence.poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	forwardPath := func(path string) error {
		_, err := backend.Forward(context.Background(), types.TunnelRequest{Method: http.MethodGet, Path: path})
		return err
	}
	forward := func() {
		t.Helper()
		if err := forwardPath("/"); err != nil {
			t.Fatal(err)
		}
	}
	want := func(n int32, what string) {
		t.Helper()
		if got := handshakes.Load(); got != n {
			t.Fatalf("handshakes %s = %d, want %d", what, got, n)
		}
	}

	poll()
	forward()
	forward()
	want(1, "after two requests on one bound (pooled)")
	poll()
	forward()
	want(1, "after an unchanged bound")
	cds.setBound("sha256:p", "sha256:q")
	poll()
	forward()
	want(2, "after the bound changed (pool dropped, peer re-checked)")
	cds.setBound("sha256:q")
	poll()
	forward()
	want(3, "after the bound narrowed")

	// A connection busy across the change, checked under the old bound,
	// must not return to the pool later requests use.
	held := make(chan error, 1)
	go func() { held <- forwardPath("/hold") }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("held request never reached the upstream")
	}
	cds.setBound("sha256:r")
	poll()
	forward()
	want(4, "for a request while another connection is busy across the change")
	close(release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	forward()
	if lastConn.Load() == heldConn.Load() {
		t.Fatal("the connection busy across the bound change was reused without a new peer check")
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
	cds.setJournal("sha256:a", 1, "sha256:h1")
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
	req.Header.Set(verifiedStateHeader, "sha256:h1")
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

// blockingBackend holds every forward until its context ends or stop closes.
type blockingBackend struct {
	started chan struct{}
	cause   chan error
	stop    chan struct{}
}

func (b *blockingBackend) Forward(ctx context.Context, _ types.TunnelRequest) (types.TunnelResponse, error) {
	b.started <- struct{}{}
	select {
	case <-ctx.Done():
		b.cause <- context.Cause(ctx)
	case <-b.stop:
	}
	return types.TunnelResponse{}, ctx.Err()
}

func TestTunnelForwardCancelledOnBoundChange(t *testing.T) {
	identity := writeTestMeshIdentity(t)
	cds := &fakeCDSState{key: identity.caKey}
	cds.setBound("sha256:p")
	cdsSrv := httptest.NewServer(cds)
	defer cdsSrv.Close()
	backend := &blockingBackend{started: make(chan struct{}, 1), cause: make(chan error, 1), stop: make(chan struct{})}
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
	// Registered after ts.Close, so it runs first: a failing test releases
	// the held forward instead of hanging in ts.Close.
	defer close(backend.stop)

	nonce := make([]byte, 32)
	rand.Read(nonce)
	ck, err := overenc.GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	bundle := fetchBundle(t, ts.URL, ck, nonce)
	channel, sessionID := clientChannelFromBundle(t, bundle, ck, nonce)
	// Sealed here, not in postSealedTunnel inside the goroutine: t.Fatal
	// must not run off the test goroutine.
	plain, _ := cbor.Marshal(types.TunnelRequest{Method: "GET", Path: "/stream"})
	rec, err := channel.SealRequest(plain)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := cbor.Marshal(rec)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/.well-known/c8s/tunnel", bytes.NewReader(body))
	req.Header.Set(sessionHeader, sessionID)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
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
