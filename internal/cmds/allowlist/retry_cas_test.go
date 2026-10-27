package allowlist

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/time/rate"

	"github.com/confidential-dot-ai/c8s/internal/issuer"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// rateLimitedCDS is the fake CDS behind the limiter CDS meters allowlist
// writes with, at its defaults (cds --rate-limit 10 --rate-burst 20). Reads
// are not metered, as in CDS.
func rateLimitedCDS(t *testing.T, pinned []*ecdsa.PublicKey) (*httptest.Server, *fakeCDS) {
	t.Helper()
	f := newFakeCDS(pinned)
	rl, err := issuer.NewIPRateLimiter(rate.Limit(10), 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	mux := f.mux()
	writes := issuer.RateLimitMiddleware(rl, mux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mux.ServeHTTP(w, r)
			return
		}
		writes.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, f
}

// nthDigest is a distinct container digest per n.
func nthDigest(n int) string { return fmt.Sprintf("sha256:%064x", n+1) }

func entryMap(names ...string) string {
	parts := make([]string, len(names))
	for i, name := range names {
		parts[i] = `"` + name + `":{"containers":[` + ctrJSON(nthDigest(i), "/app") + `]}`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func workloadOf(t *testing.T, n int) pkgallowlist.Workload {
	return pkgallowlist.Workload{Containers: []pkgallowlist.Container{{Digest: mustDigest(t, nthDigest(n))}}}
}

// A file larger than the rate limiter's burst is applied whole: before, apply
// wrote one entry per request and stopped at the first 429, about entry 21,
// leaving the first 20 written.
func TestApplyLargeFileThroughRateLimit(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := rateLimitedCDS(t, []*ecdsa.PublicKey{pub})
	names := make([]string, 60)
	for i := range names {
		names[i] = fmt.Sprintf("app-%02d", i)
	}
	file := writeFile(t, "big.json", entryMap(names...))
	before := cds.currentVersion()

	if _, _, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatalf("apply of %d entries: %v (store holds %d)", len(names), err, cds.count())
	}
	if got := cds.count(); got != len(names) {
		t.Fatalf("store holds %d entries, want %d", got, len(names))
	}
	if got := cds.currentVersion(); got != before+1 {
		t.Fatalf("version %d -> %d, want one atomic write", before, got)
	}
}

// Writes that stay one per entry wait out the rate limit instead of stopping.
func TestDeleteManyThroughRateLimit(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := rateLimitedCDS(t, []*ecdsa.PublicKey{pub})
	args := []string{"delete"}
	for i := range 30 {
		name := fmt.Sprintf("app-%02d", i)
		cds.seedWorkload(name, workloadOf(t, i))
		args = append(args, name)
	}
	if _, _, err := runCmd(append(args, "--url", srv.URL, "--insecure", "--operator-key", keyPath)...); err != nil {
		t.Fatalf("delete of 30 entries: %v (store holds %d)", err, cds.count())
	}
	if got := cds.count(); got != 0 {
		t.Fatalf("store holds %d entries after deleting all", got)
	}
}

func TestDeleteReportsWhatWasDeleted(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	cds.seedWorkload("a", workloadOf(t, 0))
	cds.seedWorkload("c", workloadOf(t, 2))
	_, _, err := runCmd("delete", "a", "b", "c", "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), `no workload entry named "b"`) ||
		!strings.Contains(err.Error(), "deleted: [a]; not deleted: [b c]") {
		t.Fatalf("err = %v, want it to name what was and was not deleted", err)
	}
}

// A whole-document write never overwrites a write that landed after the read
// it was built from. Before, upload and apply replaced the allowlist
// unconditionally and the racing entry was lost.
func TestWholeDocumentWriteKeepsARacingWrite(t *testing.T) {
	for _, command := range []string{"upload", "apply"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			keyPath, pub := newOperatorKeypair(t, dir, "op.key")
			srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
			cds.seedWorkload("keep", workloadOf(t, 5))
			cds.beforeReplace = func() { cds.put("racer", workloadOf(t, 6)) }

			body := entryMap("web")
			args := []string{command}
			if command == "upload" {
				body = `{"schema":"c8s.allowlist/v1","workloads":` + body + `}`
				args = append(args, "--force")
			}
			file := writeFile(t, "doc.json", body)
			_, _, err := runCmd(append(args, file, "--url", srv.URL, "--insecure", "--operator-key", keyPath)...)
			if err == nil || !strings.Contains(err.Error(), "changed since it was read") || !strings.Contains(err.Error(), "nothing was") {
				t.Fatalf("err = %v, want a refusal saying nothing was written", err)
			}
			if _, ok := cds.workload("racer"); !ok {
				t.Fatal("the racing write was overwritten")
			}
			if _, ok := cds.workload("web"); ok {
				t.Fatal("the refused write landed")
			}
			if _, ok := cds.workload("keep"); !ok {
				t.Fatal("an entry the write did not name was lost")
			}
		})
	}
}

// CDS can commit a write and still answer 503 (HA: the reply is lost). The
// client sends it again, which the version it was conditional on now refuses;
// the allowlist holds exactly what was sent, so the write succeeded.
func TestWholeDocumentWriteAfterALost503(t *testing.T) {
	for _, command := range []string{"upload", "apply"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			keyPath, pub := newOperatorKeypair(t, dir, "op.key")
			srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
			cds.lost503 = 1
			before := cds.currentVersion()

			body := entryMap("web")
			args := []string{command}
			if command == "upload" {
				body = `{"schema":"c8s.allowlist/v1","workloads":` + body + `}`
				args = append(args, "--force")
			}
			file := writeFile(t, "doc.json", body)
			if _, _, err := runCmd(append(args, file, "--url", srv.URL, "--insecure", "--operator-key", keyPath)...); err != nil {
				t.Fatalf("a write committed before its 503 reported as failed: %v", err)
			}
			if _, ok := cds.workload("web"); !ok {
				t.Fatal("entry not stored")
			}
			if got := cds.currentVersion(); got != before+1 {
				t.Fatalf("version %d -> %d, want the one committed write", before, got)
			}
		})
	}
}
