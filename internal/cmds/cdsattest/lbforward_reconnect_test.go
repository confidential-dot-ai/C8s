package cdsattest

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"testing"
	"time"
)

// keepAliveGet sends a GET through client and reports its status and whether
// it rode a reused (keepalive) connection.
func keepAliveGet(t *testing.T, client *http.Client, url, connectionTime string) (int, bool) {
	t.Helper()
	var reused bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set(connectionTimeHeader, connectionTime)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, reused
}

// A keepalive client refused because its connection predates a widened bound
// must get a new connection on its next request, not the refusal forever.
func TestLBForwarderReconnectRefusalClosesConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	backend, err := NewHTTPBackend(upstream.URL, HTTPBackendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fence := newRollout("", "")
	fence.lease = time.Hour
	fence.seenAt = time.Now()
	fence.widenedAt = time.Now().Add(-10 * time.Second)
	forwarder, err := newLBForwarder(fence, backend, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(forwarder)
	defer front.Close()
	client := &http.Client{Transport: &http.Transport{}}

	if code, _ := keepAliveGet(t, client, front.URL, "1"); code != http.StatusOK {
		t.Fatalf("fresh connection = %d, want 200", code)
	}
	code, reused := keepAliveGet(t, client, front.URL, "20")
	if code != reconnectStatus || !reused {
		t.Fatalf("old connection = %d (reused %v), want %d on the kept-alive connection", code, reused, reconnectStatus)
	}
	if code, reused := keepAliveGet(t, client, front.URL, "0"); code != http.StatusOK || reused {
		t.Fatalf("after the refusal = %d (reused %v), want 200 on a new connection", code, reused)
	}
}

// A forward cancelled in flight by a bound change, before the upstream
// answered, closes the client's connection too.
func TestLBForwarderInFlightCancelClosesConnection(t *testing.T) {
	entered := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hold" {
			return
		}
		entered <- struct{}{}
		<-r.Context().Done()
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
	client := &http.Client{Transport: &http.Transport{}}

	if code, _ := keepAliveGet(t, client, front.URL+"/", "0"); code != http.StatusOK {
		t.Fatalf("warm-up = %d, want 200", code)
	}
	type result struct {
		code   int
		reused bool
	}
	held := make(chan result, 1)
	go func() {
		code, reused := keepAliveGet(t, client, front.URL+"/hold", "0")
		held <- result{code, reused}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("the forward never reached the upstream")
	}
	cds.setBound("sha256:p", "sha256:q")
	if _, err := fence.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	var got result
	select {
	case got = <-held:
	case <-time.After(3 * time.Second):
		t.Fatal("the held forward was not cancelled")
	}
	if got.code != reconnectStatus || !got.reused {
		t.Fatalf("cancelled forward = %d (reused %v), want %d on the kept-alive connection", got.code, got.reused, reconnectStatus)
	}
	if code, reused := keepAliveGet(t, client, front.URL+"/", "0"); code != http.StatusOK || reused {
		t.Fatalf("after the cancel = %d (reused %v), want 200 on a new connection", code, reused)
	}
}
