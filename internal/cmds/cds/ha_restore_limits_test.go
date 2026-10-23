package cds

// Bounded restore admission and authorization regressions.
// Handler-only: at most 64 KiB of synthetic request data, no network or replica Run.
import (
	"context"
	"encoding/json"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"io"
	"k8s.io/apimachinery/pkg/util/wait"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type r3CountingReader struct {
	r io.Reader
	n int
}

func (r *r3CountingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += n
	return n, err
}
func TestR3SurfaceRestoreConsumesSnapshotBeforeAuth(t *testing.T) {
	node, _ := unjoinedNode(t)
	// Empty decree is invalid. Snapshot base64 is 60 KiB, decodes to 45 KiB.
	body := `{"decree":{},"snapshot":"` + strings.Repeat("A", 60<<10) + `"}`
	if len(body) > 64<<10 {
		t.Fatal("probe payload exceeded bound")
	}
	rd := &r3CountingReader{r: strings.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/ha/restore", rd)
	// No Authorization, client TLS identity, attestation evidence or signature.
	rec := httptest.NewRecorder()
	preJoinMux(node).ServeHTTP(rec, req)
	if rd.n != len(body) {
		t.Fatalf("read %d of %d bytes", rd.n, len(body))
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	t.Logf("invalid unsigned restore consumed all %d bytes before refusal", rd.n)
	// This is an observational probe, not an OOM test. Static cap is 256 MiB.
}

func TestRestoreHeaderRefusedBeforeBody(t *testing.T) {
	node, _ := unjoinedNode(t)
	rd := &r3CountingReader{r: strings.NewReader(strings.Repeat("A", 60<<10))}
	req := httptest.NewRequest(http.MethodPost, "/ha/restore", rd)
	req.Header.Set(restoreDecreeHeader, `{}`)
	rec := httptest.NewRecorder()
	preJoinMux(node).ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict || rd.n != 0 {
		t.Fatalf("status=%d read=%d", rec.Code, rd.n)
	}
}
func TestRestoreLegacyLimitAndAdmission(t *testing.T) {
	node, _ := unjoinedNode(t)
	handler := handleRestore(node)
	rd := &r3CountingReader{r: strings.NewReader(`{"snapshot":"` + strings.Repeat("A", 2*maxLegacyRestoreBytes) + `"}`)}
	rec := httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/ha/restore", rd))
	if rec.Code != http.StatusBadRequest || rd.n > maxLegacyRestoreBytes+1 {
		t.Fatalf("status=%d read=%d", rec.Code, rd.n)
	}
	restoreAdmission <- struct{}{}
	defer func() { <-restoreAdmission }()
	rd = &r3CountingReader{r: strings.NewReader(`{}`)}
	rec = httptest.NewRecorder()
	handler(rec, httptest.NewRequest(http.MethodPost, "/ha/restore", rd))
	if rec.Code != http.StatusTooManyRequests || rd.n != 0 {
		t.Fatalf("status=%d read=%d", rec.Code, rd.n)
	}
}

func TestRestoreAuthenticatedLargeEnvelope(t *testing.T) {
	node, k := unjoinedNode(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = node.Run(ctx) }()
	defer func() { cancel(); <-done }()
	sd, err := cdsha.SignDecree(cdsha.Decree{ClusterID: "c1", IntentID: "surface", Kind: cdsha.Restore, BootstrapNode: "n0", SnapshotSHA256: cdsha.SnapshotSHA256([]byte("different")), ExpiresAt: time.Now().Add(time.Hour)}, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, 5*time.Second, true, func(context.Context) (bool, error) { return node.CheckRestore(sd) == nil, nil }); err != nil {
		t.Fatal(err)
	}
	header, _ := json.Marshal(sd)
	body, _ := json.Marshal(RestoreRequest{Decree: sd, Snapshot: make([]byte, 1<<20)})
	rd := &r3CountingReader{r: strings.NewReader(string(body))}
	req := httptest.NewRequest(http.MethodPost, "/ha/restore", rd)
	req.Header.Set(restoreDecreeHeader, string(header))
	rec := httptest.NewRecorder()
	handleRestore(node)(rec, req)
	if rd.n != len(body) || rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "snapshot differs") {
		t.Fatalf("read=%d/%d code=%d body=%s", rd.n, len(body), rec.Code, rec.Body.String())
	}
	sd.Decree.IntentID = "substituted"
	body, _ = json.Marshal(RestoreRequest{Decree: sd})
	req = httptest.NewRequest(http.MethodPost, "/ha/restore", strings.NewReader(string(body)))
	req.Header.Set(restoreDecreeHeader, string(header))
	rec = httptest.NewRecorder()
	handleRestore(node)(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "differs from header") {
		t.Fatal(rec.Code, rec.Body.String())
	}
}
