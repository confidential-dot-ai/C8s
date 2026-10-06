//go:build linux

package armtlsmesh

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/armtls/cdsclient"
)

// unseededProvider builds a provider whose /ca endpoint always fails, so
// refresh ticks take the error path without a CDS fake.
func unseededProvider(t *testing.T) *cdsclient.Provider {
	t.Helper()
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ca.Close)

	p, err := cdsclient.NewProvider(&cdsclient.Config{
		CDSURL:            "http://unused",
		AttestationApiURL: "http://unused",
		CDSCAURL:          ca.URL,
		NodeIP:            "10.0.0.1",
		TEEType:           armtls.TEETypeSEVSNP,
		HTTPClient:        &http.Client{Timeout: time.Second},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestCABundleRefreshWarnsAndExits covers the loop's failure path: a refresh
// that errors must warn under the run's prefix and must not push certs into
// the managers (nil managers panic if it does), and cancelling the run ctx
// must stop the loop.
func TestCABundleRefreshWarnsAndExits(t *testing.T) {
	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		caBundleRefresh{
			logger:    slog.New(slog.NewJSONHandler(&buf, nil)),
			logPrefix: "in-guest cds",
			provider:  unseededProvider(t),
			interval:  10 * time.Millisecond,
			opTimeout: time.Second,
		}.run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for !hasMsg(decodeLogRecords(buf.String()), "in-guest cds CA bundle refresh failed") {
		if time.Now().After(deadline) {
			t.Fatalf("refresh never warned; logs: %s", buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after context cancel")
	}
}
