package allowlist

import (
	"bytes"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// servingAllowlistCDS serves an arbitrary parsed allowlist document on GET and
// accepts writes with 204, recording the HTTP methods it saw.
func servingAllowlistCDS(t *testing.T, al *pkgallowlist.Allowlist) (url string, methods *[]string) {
	t.Helper()
	body, err := al.Canonical()
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
			w.Header().Set("ETag", `W/"3"`)
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

// runCmdIn is runCmd with a stdin payload, for '-' file arguments and prompts.
func runCmdIn(stdin string, args ...string) (string, string, error) {
	cmd := NewCmd()
	var out, errb bytes.Buffer
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

// ctrJSON renders one canonical exact-command container entry.
func ctrJSON(digest, argv string) string {
	return `{"digest":"` + digest + `","command":{"policy":"exact","argv":["` + argv + `"]},"args":{"policy":"deny"}}`
}

// oneContainerEntry is an entry admitting digest under one exact command.
func oneContainerEntry(t *testing.T, digest string) pkgallowlist.Workload {
	t.Helper()
	doc := `{"schema":"c8s.allowlist/v1","workloads":{"e":{"containers":[` + ctrJSON(digest, "/app") + `]}}}`
	return mustParseAllowlist(t, doc).Workloads["e"]
}

// mustParseAllowlist parses a JSON allowlist document or fails the test.
func mustParseAllowlist(t *testing.T, doc string) *pkgallowlist.Allowlist {
	t.Helper()
	al, err := pkgallowlist.ParseJSON([]byte(doc))
	if err != nil {
		t.Fatalf("parse allowlist: %v", err)
	}
	return al
}

// writeFile writes data to a fresh temp file and returns its path.
func writeFile(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// --- workload list / get ---

func TestWorkloadListJSON(t *testing.T) {
	al := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)
	url, _ := servingAllowlistCDS(t, al)

	out, _, err := runCmd("list", "--url", url, "--insecure", "-o", "json")
	if err != nil {
		t.Fatalf("workload list -o json: %v", err)
	}
	if !strings.Contains(out, `"web"`) || !strings.Contains(out, digA) {
		t.Fatalf("unexpected JSON output:\n%s", out)
	}
}

func TestWorkloadGet(t *testing.T) {
	al := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"label":"registry/app","containers":[`+ctrJSON(digA, "/app")+`]}}}`)
	url, _ := servingAllowlistCDS(t, al)

	out, _, err := runCmd("get", "web", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("workload get: %v", err)
	}
	if !strings.Contains(out, digA) || !strings.Contains(out, "registry/app") {
		t.Fatalf("unexpected get output:\n%s", out)
	}

	_, _, err = runCmd("get", "nope", "--url", url, "--insecure")
	if err == nil || !strings.Contains(err.Error(), `no workload entry named "nope"`) {
		t.Fatalf("expected a not-found error, got %v", err)
	}
}

// --- workload apply ---

func TestWorkloadApplyDryRunDiff(t *testing.T) {
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"same":{"containers":[`+ctrJSON(digA, "/app")+`]},
		"web":{"containers":[`+ctrJSON(digB, "/old")+`]}}}`)
	url, methods := servingAllowlistCDS(t, live)

	file := writeFile(t, "wl.json", `{"schema":"c8s.allowlist/v1",
		"workloads":{
			"same":{"containers":[`+ctrJSON(digA, "/app")+`]},
			"web":{"containers":[`+ctrJSON(digB, "/new")+`]},
			"new":{"containers":[`+ctrJSON(digC, "/fresh")+`]}}}`)

	out, _, err := runCmd("apply", file, "--url", url, "--insecure", "--dry-run")
	if err != nil {
		t.Fatalf("workload apply --dry-run: %v", err)
	}
	// The diff must classify each entry: unchanged, changed, and new.
	for _, want := range []string{"= same (unchanged)", "~ web", "+ new (new)"} {
		if !strings.Contains(out, want) {
			t.Errorf("apply output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "/old") || !strings.Contains(out, "/new") {
		t.Errorf("apply output missing the container-level diff:\n%s", out)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("dry-run must not PUT")
	}
}

func TestWorkloadApplyWrites(t *testing.T) {
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1"}`)
	url, methods := servingAllowlistCDS(t, live)
	keyPath := writeOperatorKey(t, t.TempDir())
	file := writeFile(t, "wl.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)

	_, _, err := runCmd("apply", file, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("workload apply: %v", err)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT, saw %v", *methods)
	}
}

func TestWorkloadApplyFromStdinBareMap(t *testing.T) {
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1"}`)
	url, _ := servingAllowlistCDS(t, live)

	// A bare name-keyed map (not an allowlist document) read from stdin.
	stdin := `{"w1":{"containers":[` + ctrJSON(digA, "/app") + `]}}`
	out, _, err := runCmdIn(stdin, "apply", "-", "--url", url, "--insecure", "--dry-run")
	if err != nil {
		t.Fatalf("workload apply -: %v", err)
	}
	if !strings.Contains(out, "+ w1 (new)") {
		t.Fatalf("missing new-entry line:\n%s", out)
	}
}

func TestWorkloadApplyRejectsEmptyAndBadInput(t *testing.T) {
	url, _ := servingCDS(t, nil)

	empty := writeFile(t, "empty.json", `{"schema":"c8s.allowlist/v1"}`)
	if _, _, err := runCmd("apply", empty, "--url", url, "--insecure"); err == nil ||
		!strings.Contains(err.Error(), "no workload entries") {
		t.Fatalf("expected a no-entries error, got %v", err)
	}

	missing := filepath.Join(t.TempDir(), "nope.json")
	if _, _, err := runCmd("apply", missing, "--url", url, "--insecure"); err == nil ||
		!strings.Contains(err.Error(), "read") {
		t.Fatalf("expected a read error, got %v", err)
	}

	// A body with neither a schema nor an entry is refused by the decoder: it
	// names no shape, so it must not read as an allowlist with nothing in it.
	for _, body := range []string{`not json at all`, `{}`, `null`} {
		f := writeFile(t, "bad.json", body)
		if _, _, err := runCmd("apply", f, "--url", url, "--insecure"); err == nil ||
			!strings.Contains(err.Error(), "parse workload entries") {
			t.Fatalf("expected a parse error for %q, got %v", body, err)
		}
	}
}

// The entry a new one is shadowed by is usually one already served — a seeded
// unconstrained entry for the same image — so apply checks against the live
// document too.
func TestWorkloadApplyRefusesEntryShadowedByLive(t *testing.T) {
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"app-aaaaaaaaaaaa":{"containers":[{"digest":"`+digA+`","command":{"policy":"any"},"args":{"policy":"any"},"mounts":{"policy":"any"}}]}}}`)
	url, methods := servingAllowlistCDS(t, live)

	file := writeFile(t, "wl.json", `{"schema":"c8s.allowlist/v1","workloads":{
		"api":{"containers":[`+ctrJSON(digA, "/app")+`],"secrets":{"policy":"allow","read":["/api/**"]}}}}`)
	_, stderr, err := runCmd("apply", file, "--url", url, "--insecure", "--dry-run")
	if err == nil || !strings.Contains(err.Error(), "lint error") {
		t.Fatalf("expected a refusal, got %v", err)
	}
	if !strings.Contains(stderr, `workload "api" can never be the unique match: "app-aaaaaaaaaaaa"`) {
		t.Fatalf("shadow finding missing:\n%s", stderr)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("must not write a shadowed entry")
	}
}

func TestParseWorkloadEntriesBadEntry(t *testing.T) {
	// Valid JSON map, but the entry body fails workload validation (no digest).
	_, err := parseWorkloadEntries([]byte(`{"w1":{"containers":[{"command":{"policy":"any"},"args":{"policy":"any"}}]}}`))
	if err == nil || !strings.Contains(err.Error(), `workload "w1"`) {
		t.Fatalf("expected an entry validation error, got %v", err)
	}
}

// --- workload edit ---

// setEditor installs a fake $EDITOR that replaces the edited file with content.
func setEditor(t *testing.T, content string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-editor")
	script := "#!/bin/sh\ncat > \"$1\" <<'EOF'\n" + content + "\nEOF\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write editor: %v", err)
	}
	t.Setenv("EDITOR", path)
}

func editFixtureCDS(t *testing.T) (url string, methods *[]string) {
	t.Helper()
	live := mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
		"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`)
	return servingAllowlistCDS(t, live)
}

func TestWorkloadEditApplies(t *testing.T) {
	url, methods := editFixtureCDS(t)
	keyPath := writeOperatorKey(t, t.TempDir())
	setEditor(t, `{"label":"v2","containers":[`+ctrJSON(digA, "/app")+`]}`)

	out, _, err := runCmdIn("y\n", "edit", "web", "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("workload edit: %v", err)
	}
	// The edited content must be diffed against the live entry before applying.
	if !strings.Contains(out, "~ web") || !strings.Contains(out, `label: "" -> "v2"`) {
		t.Fatalf("missing edit diff:\n%s", out)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT, saw %v", *methods)
	}
	if !strings.Contains(out, "applied web") {
		t.Fatalf("missing applied confirmation:\n%s", out)
	}
}

func TestWorkloadEditNoChanges(t *testing.T) {
	url, methods := editFixtureCDS(t)
	t.Setenv("EDITOR", "true") // leaves the file untouched

	_, _, err := runCmd("edit", "web", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("workload edit (no changes): %v", err)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("an unchanged edit must not PUT")
	}
}

func TestWorkloadEditAborted(t *testing.T) {
	url, methods := editFixtureCDS(t)
	setEditor(t, `{"label":"v2","containers":[`+ctrJSON(digA, "/app")+`]}`)

	_, _, err := runCmdIn("n\n", "edit", "web", "--url", url, "--insecure")
	if err != nil {
		t.Fatalf("workload edit (aborted): %v", err)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("an aborted edit must not PUT")
	}
}

func TestWorkloadEditEditorFails(t *testing.T) {
	url, _ := editFixtureCDS(t)
	t.Setenv("EDITOR", "false") // exits non-zero

	_, _, err := runCmd("edit", "web", "--url", url, "--insecure")
	if err == nil || !strings.Contains(err.Error(), "editor") {
		t.Fatalf("expected an editor error, got %v", err)
	}
}

// TestWorkloadEditKeepsTheEditWhenTheWriteFails proves an edit whose write
// fails after the editor exits is saved in a file that apply then writes.
func TestWorkloadEditKeepsTheEditWhenTheWriteFails(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	unpinnedKeyPath, _ := newOperatorKeypair(t, dir, "unpinned.key")
	t.Setenv(cdsconn.EnvOperatorKey, "")

	cases := []struct {
		name     string
		keyFlags []string
	}{
		{name: "CDS refuses the write", keyFlags: []string{"--operator-key", unpinnedKeyPath}},
		{name: "no operator key to sign it"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
			cds.seedWorkload("web", mustParseAllowlist(t, `{"schema":"c8s.allowlist/v1","workloads":{
				"web":{"containers":[`+ctrJSON(digA, "/app")+`]}}}`).Workloads["web"])
			setEditor(t, `{"label":"v2","containers":[`+ctrJSON(digA, "/app")+`]}`)

			args := append([]string{"edit", "web", "--url", srv.URL, "--insecure"}, tc.keyFlags...)
			_, errOut, err := runCmdIn("y\n", args...)
			if err == nil {
				t.Fatal("expected the write to fail")
			}
			saved := savedEditPath(t, errOut)

			if _, _, err := runCmd("apply", saved, "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
				t.Fatalf("apply the saved edit: %v", err)
			}
			if wl, _ := cds.workload("web"); wl.Label != "v2" {
				t.Fatalf("label after applying the saved edit = %q, want v2", wl.Label)
			}
		})
	}
}

// savedEditPath returns the file edit's stderr names as holding the edit.
func savedEditPath(t *testing.T, stderr string) string {
	t.Helper()
	m := regexp.MustCompile(`your edit is saved in (\S+);`).FindStringSubmatch(stderr)
	if m == nil {
		t.Fatalf("stderr names no saved edit:\n%s", stderr)
	}
	t.Cleanup(func() { os.Remove(m[1]) })
	return m[1]
}

// --- workload delete ---

// Every named entry goes in one write, and an entry the command does not name
// stays.
func TestWorkloadDelete(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	for _, name := range []string{"web", "old", "keep"} {
		cds.seedWorkload(name, oneContainerEntry(t, digA))
	}

	if _, _, err := runCmd("delete", "web", "old", "--url", srv.URL, "--insecure", "--operator-key", keyPath); err != nil {
		t.Fatalf("workload delete: %v", err)
	}
	for _, name := range []string{"web", "old"} {
		if _, ok := cds.workload(name); ok {
			t.Fatalf("entry %q survived the delete", name)
		}
	}
	if _, ok := cds.workload("keep"); !ok {
		t.Fatal("an entry the delete did not name was lost")
	}
}

// A name the allowlist does not hold stops the whole delete before it writes.
func TestWorkloadDeleteNotFound(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := newOperatorKeypair(t, dir, "op.key")
	srv, cds := cdsTestServer(t, []*ecdsa.PublicKey{pub})
	cds.seedWorkload("web", oneContainerEntry(t, digA))

	_, _, err := runCmd("delete", "web", "ghost", "--url", srv.URL, "--insecure", "--operator-key", keyPath)
	if err == nil || !strings.Contains(err.Error(), `no workload entry named "ghost"`) {
		t.Fatalf("expected the absent name to be refused, got %v", err)
	}
	if _, ok := cds.workload("web"); !ok {
		t.Fatal("the refused delete removed an entry")
	}
}

// --- small helpers ---

func TestSanitizeFileName(t *testing.T) {
	if got := sanitizeFileName("web-1_A.b/..\\x y"); got != "web-1_A_b____x_y" {
		t.Fatalf("sanitizeFileName = %q", got)
	}
}

// Boundary characters of every allowed range must pass through untouched, and
// their immediate ASCII neighbours must map to underscores.
func TestSanitizeFileNameBoundaries(t *testing.T) {
	if got := sanitizeFileName("azAZ09-_"); got != "azAZ09-_" {
		t.Fatalf("in-range characters mangled: %q", got)
	}
	if got := sanitizeFileName("`{@[/:"); got != "______" {
		t.Fatalf("out-of-range characters kept: %q", got)
	}
}

func TestArgvPolicyName(t *testing.T) {
	if got := argvPolicyName(pkgallowlist.ArgvPolicy{}); got != pkgallowlist.PolicyDeny {
		t.Fatalf("empty policy = %q, want %q", got, pkgallowlist.PolicyDeny)
	}
	if got := argvPolicyName(pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}); got != pkgallowlist.PolicyAny {
		t.Fatalf("any policy = %q", got)
	}
	if got := argvPolicyName(pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/x"}}); got != pkgallowlist.PolicyExact {
		t.Fatalf("exact policy = %q", got)
	}
}

func TestValidateRequiresURL(t *testing.T) {
	_, _, err := runCmd("list")
	if err == nil || !strings.Contains(err.Error(), "--url is required") {
		t.Fatalf("expected a missing --url error, got %v", err)
	}
}

func TestArgvSummary(t *testing.T) {
	if got := argvSummary(pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyExact, Argv: []string{"/bin/sh", "-c"}}); got != "exact[/bin/sh -c]" {
		t.Fatalf("exact summary = %q", got)
	}
	if got := argvSummary(pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny}); got != "any" {
		t.Fatalf("any summary = %q", got)
	}
	if got := argvSummary(pkgallowlist.ArgvPolicy{}); got != "deny" {
		t.Fatalf("deny summary = %q", got)
	}
}

func TestSecretsSummary(t *testing.T) {
	if got := secretsSummary(&pkgallowlist.SecretsPolicy{Policy: pkgallowlist.PolicyAllow, Read: []string{"/a"}, Write: []string{"/b", "/c"}}); got != "allow(r=1,w=2)" {
		t.Fatalf("allow summary = %q", got)
	}
	if got := secretsSummary(&pkgallowlist.SecretsPolicy{}); got != "deny" {
		t.Fatalf("deny summary = %q", got)
	}
}
