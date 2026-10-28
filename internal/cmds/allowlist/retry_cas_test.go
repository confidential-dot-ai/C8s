package allowlist

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
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
// it was built from. Before, upload replaced the allowlist unconditionally and
// the racing entry was lost. upload does not retry: its file is the whole
// document, so writing it onto the newer one would remove the racing entry.
func TestUploadKeepsARacingWrite(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	cds.seedWorkload("keep", workloadOf(t, 5))
	cds.beforeReplace = func() { cds.put("racer", workloadOf(t, 6)) }

	file := writeFile(t, "doc.json", `{"schema":"c8s.allowlist/v1","workloads":`+entryMap("web")+`}`)
	_, _, err := runCmd("upload", file, "--force", "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), "changed since it was read") || !strings.Contains(err.Error(), "nothing was uploaded") {
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
}

// raceReplaces makes the next n whole-document writes lose to a write of entry
// name landing just before each, and returns how many writes it raced.
func raceReplaces(cds *fakeCDS, n int, name func(i int) string, w pkgallowlist.Workload) *int {
	raced := 0
	var race func()
	race = func() {
		raced++
		cds.put(name(raced), w)
		if raced < n {
			cds.beforeReplace = race
		}
	}
	cds.beforeReplace = race
	return &raced
}

// apply sets the entries in its file. A write that landed since its read, to
// other entries, does not change what that means: apply re-reads and puts the
// entries into the newer document, keeping the other write. Before, each such
// race failed the apply.
func TestApplyAfterRacingWritesToOtherEntries(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	cds.seedWorkload("keep", workloadOf(t, 5))
	raced := raceReplaces(cds, 2, func(i int) string { return fmt.Sprintf("racer-%d", i) }, workloadOf(t, 6))
	before := cds.currentVersion()

	file := writeFile(t, "doc.json", entryMap("web"))
	_, stderr, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("apply after %d racing writes: %v", *raced, err)
	}
	if *raced != 2 {
		t.Fatalf("raced %d writes, want 2", *raced)
	}
	for _, name := range []string{"web", "keep", "racer-1", "racer-2"} {
		if _, ok := cds.workload(name); !ok {
			t.Fatalf("entry %q missing after apply", name)
		}
	}
	if got := cds.currentVersion(); got != before+3 {
		t.Fatalf("version %d -> %d, want the 2 racing writes and one apply", before, got)
	}
	if !strings.Contains(stderr, "racer-1") || !strings.Contains(stderr, "racer-2") {
		t.Fatalf("stderr does not show what the racing writes changed:\n%s", stderr)
	}
}

// When the racing write changed an entry the file also sets, the file's value
// is what apply leaves, as a second apply run after that write would.
func TestApplyOverARacingWriteToTheSameEntry(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	cds.seedWorkload("web", workloadOf(t, 5))
	raceReplaces(cds, 1, func(int) string { return "web" }, workloadOf(t, 6))

	file := writeFile(t, "doc.json", entryMap("web"))
	if _, _, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got, _ := cds.workload("web")
	if want := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":`+entryMap("web")+`}`).Workloads["web"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("web = %+v, want the file's value %+v", got, want)
	}
}

// apply gives up after maxApplyAttempts writes that all lost a race, and
// then nothing it wrote is served.
func TestApplyGivesUpWhenEveryWriteLosesARace(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	raced := raceReplaces(cds, maxApplyAttempts+1, func(i int) string { return fmt.Sprintf("racer-%d", i) }, workloadOf(t, 6))

	file := writeFile(t, "doc.json", entryMap("web"))
	_, _, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), "nothing was applied") ||
		!strings.Contains(err.Error(), fmt.Sprintf("%d attempts", maxApplyAttempts)) {
		t.Fatalf("err = %v, want a refusal after %d attempts", err, maxApplyAttempts)
	}
	if *raced != maxApplyAttempts {
		t.Fatalf("apply wrote %d times, want %d", *raced, maxApplyAttempts)
	}
	if _, ok := cds.workload("web"); ok {
		t.Fatal("a refused write landed")
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

// A write CDS committed but answered 500 for is not sent again by the client;
// reading the allowlist back finds it served, so the command reports success.
func TestWholeDocumentWriteAfterALost500(t *testing.T) {
	for _, command := range []string{"upload", "apply"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			keyPath, pub := newOperatorKeypair(t, dir, "op.key")
			srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
			cds.lost500 = 1
			before := cds.currentVersion()

			if _, _, err := runCmd(append(wholeDocArgs(t, command), "--url", srv.URL, "--insecure", "--operator-key", keyPath)...); err != nil {
				t.Fatalf("a committed write whose answer was a 500 reported as failed: %v", err)
			}
			if got := cds.currentVersion(); got != before+1 {
				t.Fatalf("version %d -> %d, want the one committed write", before, got)
			}
		})
	}
}

// A write answered 500 and not committed has not landed but still can until
// another write lands: the command says so, with the version, and does not
// claim nothing was written.
func TestWholeDocumentWriteUnconfirmed(t *testing.T) {
	for _, command := range []string{"upload", "apply"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			keyPath, pub := newOperatorKeypair(t, dir, "op.key")
			srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
			cds.fail500 = 1
			version := strconv.Itoa(cds.currentVersion())

			_, _, err := runCmd(append(wholeDocArgs(t, command), "--url", srv.URL, "--insecure", "--operator-key", keyPath)...)
			if err == nil || !strings.Contains(err.Error(), "not confirmed") ||
				!strings.Contains(err.Error(), "still serves version "+version+" without it") ||
				strings.Contains(err.Error(), "nothing was") || strings.Contains(err.Error(), "none") {
				t.Fatalf("err = %v, want it to say the write is unconfirmed at version %s", err, version)
			}
		})
	}
}

// apply's write lands but is answered 500, and another write lands on top
// before apply reads back. apply finds its write in the history, or, with the
// history pruned, re-merges onto the newer document, which already holds its
// entries: either way it reports success without writing again.
func TestApplyUnconfirmedWriteThatLandedUnderAnother(t *testing.T) {
	for _, pruned := range []bool{false, true} {
		t.Run(fmt.Sprintf("history pruned %v", pruned), func(t *testing.T) {
			dir := t.TempDir()
			keyPath, pub := newOperatorKeypair(t, dir, "op.key")
			srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
			cds.lost500 = 1
			cds.historyPruned = pruned
			cds.afterReplace = func() { cds.put("racer", workloadOf(t, 6)) }
			before := cds.currentVersion()

			file := writeFile(t, "doc.json", entryMap("web"))
			if _, _, err := runCmd("apply", file, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
				t.Fatalf("apply: %v", err)
			}
			if got := cds.currentVersion(); got != before+2 {
				t.Fatalf("version %d -> %d, want apply's one write and the racing one", before, got)
			}
			for _, name := range []string{"web", "racer"} {
				if _, ok := cds.workload(name); !ok {
					t.Fatalf("entry %q missing", name)
				}
			}
		})
	}
}

// upload's write lands but is answered 500, and another write lands on top:
// the history shows the upload landed, so upload reports success, not that
// nothing was uploaded.
func TestUploadUnconfirmedWriteThatLandedUnderAnother(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	cds.lost500 = 1
	cds.afterReplace = func() { cds.put("racer", workloadOf(t, 6)) }
	if _, _, err := runCmd(append(wholeDocArgs(t, "upload"), "--url", srv.URL, "--insecure", "--operator-key", keyPath)...); err != nil {
		t.Fatalf("upload: %v", err)
	}
}

// wholeDocArgs is the command and a file writing entry "web" with it.
func wholeDocArgs(t *testing.T, command string) []string {
	body := entryMap("web")
	args := []string{command}
	if command == "upload" {
		body = `{"schema":"c8s.allowlist/v1","workloads":` + body + `}`
		args = append(args, "--force")
	}
	return append(args, writeFile(t, "doc.json", body))
}
