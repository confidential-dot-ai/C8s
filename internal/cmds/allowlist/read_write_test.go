package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// servingCDS is an httptest server that serves the given digests on GET (as a
// canonical allowlist document of any-argv entries) and accepts writes with
// 204, recording the HTTP methods it saw.
func servingCDS(t *testing.T, digests map[string]string) (url string, methods *[]string) {
	t.Helper()
	doc := pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: anyWorkloads(t, digests),
	}
	body, err := doc.Canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method)
		mu.Unlock()
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("ETag", `W/"7"`)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

// listFailingCDS fails every GET with 500 but accepts writes (recording the
// methods it saw), so the "could not fetch allowlist" warning paths run.
func listFailingCDS(t *testing.T) (url string, methods *[]string) {
	t.Helper()
	var mu sync.Mutex
	seen := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method)
		mu.Unlock()
		if r.Method == http.MethodGet {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

// --- validate / client flag handling ---

func TestValidateRejectsBadOutputFormat(t *testing.T) {
	_, _, err := runCmd("list", "--url", "http://cds.example", "--insecure", "-o", "yaml")
	if err == nil || !strings.Contains(err.Error(), "--output must be text or json") {
		t.Fatalf("expected an output-format error, got %v", err)
	}
}

func TestClientRejectsInvalidURL(t *testing.T) {
	_, _, err := runCmd("list", "--url", "http://")
	if err == nil || !strings.Contains(err.Error(), "invalid --url") {
		t.Fatalf("expected an invalid --url error, got %v", err)
	}
}

func TestClientRejectsUnknownScheme(t *testing.T) {
	_, _, err := runCmd("list", "--url", "ftp://cds.example")
	if err == nil || !strings.Contains(err.Error(), "scheme must be http or https") {
		t.Fatalf("expected a scheme error, got %v", err)
	}
}

// --- signer error paths ---

func TestSignerMissingKeyFile(t *testing.T) {
	o := &options{Options: cdsconn.Options{OperatorKey: filepath.Join(t.TempDir(), "nope.key")}}
	if _, err := o.signer(); err == nil || !strings.Contains(err.Error(), "read operator key") {
		t.Fatalf("expected a read error, got %v", err)
	}
}

func TestSignerRejectsGarbagePEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(path, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	o := &options{Options: cdsconn.Options{OperatorKey: path, Measurements: []string{"abababababababababababababababababababababababababababababababababababababababababababababababab"}}}
	if _, err := o.signer(); err == nil || !strings.Contains(err.Error(), "load operator key") {
		t.Fatalf("expected a key-parse error, got %v", err)
	}
}

// --- list / export ---

func TestListJSONOutput(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})

	out, _, err := runCmd("list", "--url", url, "--insecure", "-o", "json")
	if err != nil {
		t.Fatalf("list -o json: %v", err)
	}
	var resp pkgallowlist.Allowlist
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(resp.Workloads) != 1 || resp.Workloads["w-"+digA[7:19]].Containers[0].Digest.String() != digA {
		t.Fatalf("unexpected response round-trip: %+v", resp)
	}
}

// TestListTextWorkloadTable pins the text rendering of the workload summary
// table: init/main counts, the aggregated command/args policy sets, and the
// entry-level secret grant tallies.
func TestListTextWorkloadTable(t *testing.T) {
	web := pkgallowlist.Workload{
		Label: "web-img",
		Containers: []pkgallowlist.Container{
			{
				Digest:  mustDigest(t, digA),
				Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/app"}},
				Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
			},
			{
				Digest:  mustDigest(t, digB),
				Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
				Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
			},
		},
		Secrets: &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/a", "/b"}, Write: []string{"/w"}},
	}
	plain := pkgallowlist.Workload{
		Containers: []pkgallowlist.Container{
			{
				Digest:  mustDigest(t, digC),
				Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/p"}},
				Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyDeny},
			},
		},
		Secrets: &pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/r"}},
	}
	al := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"web": web, "plain": plain},
	}
	url, _ := servingAllowlistCDS(t, al)

	out, _, err := runCmd("list", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "2 workload(s)") {
		t.Fatalf("missing summary line:\n%s", out)
	}

	if strings.Index(out, "\nplain ") > strings.Index(out, "\nweb ") {
		t.Fatalf("workload rows are not sorted:\n%s", out)
	}

	rows := map[string][]string{}
	for line := range strings.SplitSeq(out, "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			rows[f[0]] = f
		}
	}
	want := map[string][]string{
		"web":   {"web", "web-img", "0", "2", "command=any,exact", "args=any,deny", "env=any", "allow(r=2,w=1)"},
		"plain": {"plain", "0", "1", "command=exact", "args=deny", "env=any", "allow(r=1,w=0)"},
	}
	for name, wantRow := range want {
		got, ok := rows[name]
		if !ok {
			t.Fatalf("workload row %q missing:\n%s", name, out)
		}
		if strings.Join(got, " ") != strings.Join(wantRow, " ") {
			t.Errorf("row %q = %v, want %v", name, got, wantRow)
		}
	}
}

func TestExportToStdout(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})

	out, _, err := runCmd("export", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if !strings.Contains(out, digA) {
		t.Fatalf("exported JSON missing digest:\n%s", out)
	}

	// "-" is an explicit stdout spelling.
	dashOut, _, err := runCmd("export", "-", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("export -: %v", err)
	}
	if dashOut != out {
		t.Fatalf("export - differs from bare export:\n%s\nvs\n%s", dashOut, out)
	}
}

func TestExportMatchesServedCanonicalBytes(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})
	response, err := http.Get(url + "/allowlist")
	if err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	// A workload stamp hashes the served canonical bytes. An export must be
	// usable as a verifier pin without a different digest from whitespace.
	for _, mode := range []string{"stdout", "dash", "file"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"export"}
			file := filepath.Join(t.TempDir(), "allowlist.json")
			if mode == "dash" {
				args = append(args, "-")
			} else if mode == "file" {
				args = append(args, file)
			}
			args = append(args, "--url", url, "--insecure")
			out, _, err := runCmd(args...)
			if err != nil {
				t.Fatal(err)
			}
			got := []byte(out)
			if mode == "file" {
				got, err = os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("export differs from served bytes: got SHA256 %x, want %x", sha256.Sum256(got), sha256.Sum256(want))
			}
		})
	}
}

func TestExportToFileRoundTrips(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})
	path := filepath.Join(t.TempDir(), "backup.json")

	_, _, err := runCmd("export", path, "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("export to file: %v", err)
	}

	// The exported file must round-trip through the same loader upload/diff use.
	wl, err := loadAllowlistFile(path)
	if err != nil {
		t.Fatalf("re-load exported file: %v", err)
	}
	if got := wl.Workloads["w-"+digA[7:19]].Label; got != "registry/app@"+digA {
		t.Fatalf("round-trip lost the entry: %#v", wl.Workloads)
	}
}

func TestExportWriteFailure(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "registry/app@" + digA})
	path := filepath.Join(t.TempDir(), "missing-dir", "backup.json")

	_, _, err := runCmd("export", path, "--url", url, "--insecure")
	if err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("expected a write error, got %v", err)
	}
}

// --- diff ---

func TestDiffJSONOutput(t *testing.T) {
	url, _ := servingCDS(t, map[string]string{digA: "img-a"})
	file := writeAllowlistFile(t, t.TempDir(), map[string]string{digB: "img-b"})

	out, _, err := runCmd("diff", file, "--url", url, "--insecure", "-o", "json")
	if err != nil {
		t.Fatalf("diff -o json: %v", err)
	}
	var d allowlistDiff
	if err := json.Unmarshal([]byte(out), &d); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(d.WorkloadsAdded) != 1 || d.WorkloadsAdded[0] != "w-"+digB[7:19] ||
		len(d.WorkloadsRemoved) != 1 || d.WorkloadsRemoved[0] != "w-"+digA[7:19] {
		t.Fatalf("unexpected diff: %#v", d)
	}
}

func TestDiffRejectsBadFile(t *testing.T) {
	url, _ := servingCDS(t, nil)

	if _, _, err := runCmd("diff", filepath.Join(t.TempDir(), "nope.json"), "--url", url, "--insecure"); err == nil {
		t.Fatal("expected a missing allowlist file to fail")
	}

	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := runCmd("diff", bad, "--url", url, "--insecure"); err == nil || !strings.Contains(err.Error(), "parse allowlist file") {
		t.Fatalf("expected a parse error, got %v", err)
	}
}

// --- add ---

func TestAddWritesDerivedEntry(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	url, methods := recordingCDS(t)

	out, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT, saw %v", *methods)
	}
	if want := "added app-" + digA[7:19]; !strings.Contains(out, want) {
		t.Fatalf("missing %q:\n%s", want, out)
	}
}

func TestAddDryRunMakesNoCall(t *testing.T) {
	url, methods := recordingCDS(t)
	out, _, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--insecure", "--dry-run")
	if err != nil {
		t.Fatalf("add --dry-run: %v", err)
	}
	if len(*methods) != 0 {
		t.Fatalf("dry-run must not call CDS, saw %v", *methods)
	}
	if !strings.Contains(out, "would add app-"+digA[7:19]) {
		t.Fatalf("missing dry-run line:\n%s", out)
	}
}

func TestAddRejectsInvalidDigestAndWildcardImage(t *testing.T) {
	url, methods := recordingCDS(t)
	if _, _, err := runCmd("add", "sha256:short", "registry/app", "--url", url, "--insecure"); err == nil {
		t.Fatal("expected an invalid digest to be rejected")
	}
	if _, _, err := runCmd("add", digA, "*", "--url", url, "--insecure", "--dry-run"); err == nil {
		t.Fatal("expected a bare-wildcard image to be rejected")
	}
	if len(*methods) != 0 {
		t.Fatalf("must not call CDS with invalid arguments, saw %v", *methods)
	}
}

// An any-argv entry for a digest a narrower served entry already declares
// would shadow it, so add refuses like apply does.
func TestAddRefusesShadowingLiveEntry(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"api":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)
	url, methods := servingAllowlistCDS(t, live)

	_, stderr, err := runCmd("add", digA, "registry/app@"+digA, "--url", url, "--insecure", "--operator-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), "lint error") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if !strings.Contains(stderr, `workload "api" can never be the unique match`) {
		t.Fatalf("shadow finding missing:\n%s", stderr)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("must not write a shadowing entry")
	}
}

// --- upload ---

func TestUploadProceedsWhenListFailsForDiff(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	file := writeAllowlistFile(t, dir, coreImages())
	url, methods := listFailingCDS(t)

	_, _, err := runCmd("upload", file, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT despite the failing diff pre-fetch, saw %v", *methods)
	}
}

func TestUploadRequireOverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	// Names none of the defaults, but satisfies the overridden requirement.
	file := writeAllowlistFile(t, dir, map[string]string{digA: "registry/team/myapp@" + digA})
	url, _ := servingCDS(t, nil)

	if _, _, err := runCmd("upload", file, "--url", url, "--insecure", "--require", "myapp", "--dry-run"); err != nil {
		t.Fatalf("upload with --require override failed: %v", err)
	}

	// And the override is enforced, not just accepted.
	if _, _, err := runCmd("upload", file, "--url", url, "--insecure", "--require", "otherapp", "--dry-run"); err == nil {
		t.Fatal("expected an unmet --require component to refuse the upload")
	}
}

func TestUploadStrictLint(t *testing.T) {
	dir := t.TempDir()
	clean := writeAllowlistFile(t, dir, coreImages())
	url, methods := recordingCDS(t)

	if _, _, err := runCmd("upload", clean, "--url", url, "--insecure", "--strict", "--dry-run"); err != nil {
		t.Fatalf("--strict with a clean file must succeed, got %v", err)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("dry-run must not PUT")
	}

	warny := writeFile(t, "warny.json", `{"schema":"c8s.allowlist/v1","workloads":{"w":{"label":"docker.io/library/busybox:latest","containers":[
		{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}}]}}}`)
	_, _, err := runCmd("upload", warny, "--url", url, "--insecure", "--strict")
	if err == nil || !strings.Contains(err.Error(), "lint warning(s) with --strict") {
		t.Fatalf("expected a strict lint refusal, got %v", err)
	}
}

// Without --require the default component guard must stay armed.
func TestUploadGuardOnByDefault(t *testing.T) {
	file := writeAllowlistFile(t, t.TempDir(), map[string]string{digA: "registry/app/only@" + digA})
	url, _ := recordingCDS(t)

	_, _, err := runCmd("upload", file, "--url", url, "--insecure", "--dry-run")
	if err == nil || !strings.Contains(err.Error(), "refusing to upload an allowlist missing core components") {
		t.Fatalf("expected the component guard to refuse, got %v", err)
	}
}

func TestUploadRejectsBadFile(t *testing.T) {
	if _, _, err := runCmd("upload", filepath.Join(t.TempDir(), "nope.json"), "--url", "http://cds.example", "--insecure"); err == nil {
		t.Fatal("expected a missing upload file to fail")
	}
}

// --- lint (offline) ---

func TestLintOfflineWarningSurface(t *testing.T) {
	file := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"empty":{},
		"tagged":{"label":"docker.io/library/busybox:latest","containers":[
			{"digest":"`+digA+`","image":"docker.io/library/busybox:latest",
			 "command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]},
		"other":{"secrets":{"policy":"allow","read":["/**"]},"containers":[
			{"digest":"`+digA+`","command":{"policy":"exact","argv":["/app"]},"args":{"policy":"deny"}},
			{"digest":"`+digB+`","command":{"policy":"deny"},"args":{"policy":"deny"}}]}}}`)

	out, _, err := runCmd("lint", file)
	if err != nil {
		t.Fatalf("lint: %v", err)
	}
	for _, want := range []string{
		`workload "empty" has no init or main containers`,
		`workload "tagged" label "docker.io/library/busybox:latest" is a tag`,
		`image "docker.io/library/busybox:latest" is a tag`,
		"the container can never start",
		`grants the root secret subtree "/**"`,
		"appears in 2 entries and one grants 'any'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lint output missing %q:\n%s", want, out)
		}
	}

	// --strict turns those warnings into a non-zero exit.
	if _, _, err := runCmd("lint", "--strict", file); err == nil {
		t.Fatal("expected --strict to turn warnings into a failure")
	}
}

func TestLintRejectsMissingAndInvalidFile(t *testing.T) {
	if _, _, err := runCmd("lint", filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected a missing lint file to fail")
	}
	bad := writeFile(t, "bad.json", `{"schema":"wrong/schema"}`)
	if _, _, err := runCmd("lint", bad); err == nil || !strings.Contains(err.Error(), "schema") {
		t.Fatalf("expected a schema error, got %v", err)
	}
}
