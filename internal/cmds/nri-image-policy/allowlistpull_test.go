package nriimagepolicy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/allowlistclient"
)

// testPull is a tracker whose clock the caller moves.
func testPull(logger *slog.Logger) (*allowlistPull, func(time.Duration)) {
	now := time.Now()
	pull := newAllowlistPull("cds.private:8443", func() time.Time { return now }, logger)
	return pull, func(waited time.Duration) { now = now.Add(waited) }
}

// quietPull is a tracker for the pull tests that assert on the index.
func quietPull() *allowlistPull {
	return newAllowlistPull("cds.test:8443", time.Now, discardLogger())
}

func TestAllowlistPullStallNamesTheUnreachedCDS(t *testing.T) {
	pull, advance := testPull(discardLogger())

	pull.failed(errors.New("lookup cds.private: no such host"))
	if stall := pull.stall(); stall != "" {
		t.Fatalf("stall = %q before the bound, want none", stall)
	}

	advance(pullStallAfter)
	pull.failed(errors.New("lookup cds.private: no such host"))
	stall := pull.stall()
	if !strings.Contains(stall, "cds.private:8443") || !strings.Contains(stall, "no such host") {
		t.Fatalf("stall = %q, want the CDS endpoint and the resolution failure", stall)
	}

	pull.reached()
	if stall := pull.stall(); stall != "" {
		t.Fatalf("stall = %q after a pull reached CDS, want none", stall)
	}
}

func TestAllowlistPullWithoutAFailureDoesNotStall(t *testing.T) {
	pull, advance := testPull(discardLogger())
	advance(2 * pullStallAfter)
	if stall := pull.stall(); stall != "" {
		t.Fatalf("stall = %q with no failed pull, want none", stall)
	}
}

func TestAllowlistPullReportsEachStallOnce(t *testing.T) {
	logged := countErrors()
	pull, advance := testPull(slog.New(logged))

	advance(pullStallAfter)
	for range 3 {
		pull.failed(io.ErrUnexpectedEOF)
	}
	if *logged.count != 1 {
		t.Fatalf("logged %d errors for one stall, want 1", *logged.count)
	}

	pull.reached()
	advance(pullStallAfter)
	pull.failed(io.ErrUnexpectedEOF)
	if *logged.count != 2 {
		t.Fatalf("logged %d errors for a second stall, want 2", *logged.count)
	}
}

func TestPullLoopStallsOnACDSItCannotReach(t *testing.T) {
	pull, advance := testPull(discardLogger())
	advance(pullStallAfter)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runPullLoop(ctx, pullLoopArgs{
			pull:        pull,
			client:      allowlistclient.NewClientWithHTTP("https://cds.invalid:8443", &http.Client{Timeout: time.Second}),
			store:       newPolicyStore(nil),
			interval:    10 * time.Millisecond,
			timeout:     time.Second,
			logger:      discardLogger(),
			killRevoked: func(context.Context) {},
		})
		close(done)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for pull.stall() == "" {
		if time.Now().After(deadline) {
			t.Fatal("the loop reported no stall for a CDS it never reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stall := pull.stall(); !strings.Contains(stall, "cds.private:8443") {
		t.Fatalf("stall = %q, want the CDS this node reached none from", stall)
	}
	cancel()
	<-done
}

func TestStartHealthServer_HealthzShowsTheAllowlistStall(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "health.sock")
	p := newTestPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}})
	p.SetReady()
	pull, advance := testPull(discardLogger())
	if err := startHealthServer(t.Context(), healthServerConfig{
		logger:       discardLogger(),
		plugin:       p,
		pull:         pull,
		addr:         "unix://" + sock,
		readTimeout:  time.Second,
		writeTimeout: time.Second,
	}); err != nil {
		t.Fatalf("startHealthServer: %v", err)
	}
	httpClient := unixHealthClient(sock)

	if _, body := healthz(t, httpClient); body.AllowlistStall != "" {
		t.Fatalf("allowlist_stall = %q before the bound, want none", body.AllowlistStall)
	}

	advance(pullStallAfter)
	pull.failed(errors.New("lookup cds.private: no such host"))
	_, body := healthz(t, httpClient)
	if !strings.Contains(body.AllowlistStall, "cds.private:8443") {
		t.Fatalf("allowlist_stall = %q, want the CDS this node reached none from", body.AllowlistStall)
	}
}

// errorCounter handles every record itself, so a With logger keeps counting.
type errorCounter struct {
	count *int
}

func countErrors() errorCounter {
	var count int
	return errorCounter{count: &count}
}

func (c errorCounter) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelError
}

func (c errorCounter) Handle(_ context.Context, record slog.Record) error {
	if record.Level >= slog.LevelError {
		*c.count++
	}
	return nil
}

func (c errorCounter) WithAttrs(_ []slog.Attr) slog.Handler {
	return c
}

func (c errorCounter) WithGroup(_ string) slog.Handler {
	return c
}
