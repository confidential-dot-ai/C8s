package allowlist

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/internal/crane/cranetest"
	"github.com/confidential-dot-ai/c8s/internal/localverify"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

const (
	// digA/digB alias the crane stub's sentinels so the --online tests and
	// the stub cannot drift apart.
	digA = cranetest.DigA
	digB = cranetest.DigB
	digC = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	digD = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
)

func mustDigest(t *testing.T, s string) types.Digest {
	t.Helper()
	d, err := types.ParseDigest(s)
	if err != nil {
		t.Fatalf("parse digest %q: %v", s, err)
	}
	return d
}

// coreImages names every default-required component so an allowlist built from
// it passes the core-component gate.
func coreImages() map[string]string {
	m := map[string]string{}
	digits := "0123456789abcdef"
	for i, comp := range defaultRequiredComponents {
		// distinct valid digests per component
		d := "sha256:" + string(digits[i]) + "000000000000000000000000000000000000000000000000000000000000000"
		m[d] = "registry.example.com/c8s/" + comp + "@" + d
	}
	return m
}

// anyWorkloads renders a digest -> image map as one any-argv entry per digest,
// named "w-" plus the first 12 hex digits of the digest.
func anyWorkloads(t *testing.T, digests map[string]string) map[string]pkgallowlist.Workload {
	t.Helper()
	out := make(map[string]pkgallowlist.Workload, len(digests))
	for d, image := range digests {
		out["w-"+d[len("sha256:"):][:12]] = pkgallowlist.Workload{
			Label: image,
			Containers: []pkgallowlist.Container{{
				Digest:  mustDigest(t, d),
				Image:   image,
				Command: pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
				Args:    pkgallowlist.ArgvPolicy{Policy: pkgallowlist.PolicyAny},
			}},
		}
	}
	return out
}

// writeAllowlistFile writes a valid allowlist document holding one any-argv
// entry per digest and returns its path.
func writeAllowlistFile(t *testing.T, dir string, digests map[string]string) string {
	t.Helper()
	path := filepath.Join(dir, "allowlist.json")
	data, err := json.Marshal(map[string]any{"schema": pkgallowlist.Schema, "workloads": anyWorkloads(t, digests)})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// writeOperatorKey writes an EC private key PEM to dir and returns its path.
func writeOperatorKey(t *testing.T, dir string) (keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	keyPath = filepath.Join(dir, "op.key")
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return keyPath
}

// recordingCDS is an httptest server that records the HTTP methods it saw and
// serves an empty (but valid) canonical allowlist on GET.
func recordingCDS(t *testing.T) (url string, methods *[]string) {
	t.Helper()
	empty := pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{},
	}
	body, err := empty.Canonical()
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
			w.Header().Set("ETag", `W/"1"`)
			w.Write(body)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, &seen
}

func runCmd(args ...string) (string, string, error) {
	cmd := NewCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

func contains(methods []string, m string) bool {
	return slices.Contains(methods, m)
}

// --- pure helpers ---

func TestMissingComponents(t *testing.T) {
	full := coreImages()
	if got := missingComponents(full, defaultRequiredComponents); len(got) != 0 {
		t.Fatalf("expected no missing components, got %v", got)
	}

	partial := map[string]string{digA: "registry/c8s/cds@" + digA}
	got := missingComponents(partial, defaultRequiredComponents)
	if len(got) != len(defaultRequiredComponents)-1 {
		t.Fatalf("expected all but cds missing, got %v", got)
	}
	for _, c := range got {
		if c == "cds" {
			t.Fatal("cds should not be reported missing")
		}
	}
}

// TestMissingComponentsMatchesRealChartImages pins the defaultRequiredComponents
// substring needles against the actual chart image repositories, so a rename
// (notably the router "nginxinc/nginx-unprivileged" image, which only matches
// the "nginx" needle as a substring) can't silently defeat the upload guard.
func TestMissingComponentsMatchesRealChartImages(t *testing.T) {
	chartImages := map[string]string{
		"a": "ghcr.io/confidential-dot-ai/cds@sha256:1",
		"b": "ghcr.io/confidential-dot-ai/armtls-mesh@sha256:2",
		"c": "ghcr.io/confidential-dot-ai/nri-image-policy@sha256:3",
		"d": "ghcr.io/confidential-dot-ai/attestation-api@sha256:4",
		"e": "nginxinc/nginx-unprivileged@sha256:5",
	}
	if got := missingComponents(chartImages, defaultRequiredComponents); len(got) != 0 {
		t.Fatalf("real chart images should satisfy every required component, missing: %v", got)
	}

	// Sanity: dropping the router image reports exactly "nginx" — proving that
	// entry is really carried by nginxinc/nginx-unprivileged and nothing else.
	delete(chartImages, "e")
	got := missingComponents(chartImages, defaultRequiredComponents)
	if len(got) != 1 || got[0] != "nginx" {
		t.Fatalf("dropping the nginx image should report exactly [nginx], got %v", got)
	}
}

// TestUploadImageLabelsScansWorkloads proves the upload component guard scans
// workload container images: component images on an entry's containers
// satisfy every required component.
func TestUploadImageLabelsScansWorkloads(t *testing.T) {
	digits := "0123456789abcdef"
	var ctrs []pkgallowlist.Container
	for i, comp := range defaultRequiredComponents {
		d := "sha256:" + string(digits[i]) + "000000000000000000000000000000000000000000000000000000000000000"
		ctrs = append(ctrs, pkgallowlist.Container{
			Digest: mustDigest(t, d),
			Image:  "ghcr.io/confidential-dot-ai/" + comp + "@" + d,
		})
	}
	al := &pkgallowlist.Allowlist{
		Schema:    pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"core": {Containers: ctrs}},
	}
	if got := missingComponents(uploadImageLabels(al), defaultRequiredComponents); len(got) != 0 {
		t.Fatalf("workload container images should satisfy the guard, missing: %v", got)
	}

	// An allowlist with no component images reports all.
	empty := &pkgallowlist.Allowlist{Schema: pkgallowlist.Schema}
	if got := missingComponents(uploadImageLabels(empty), defaultRequiredComponents); len(got) != len(defaultRequiredComponents) {
		t.Fatalf("empty allowlist should be missing every component, got %v", got)
	}
}

// --- command behavior ---

func TestUploadRefusesMissingCoreWithoutForce(t *testing.T) {
	dir := t.TempDir()
	file := writeAllowlistFile(t, dir, map[string]string{digA: "registry/app/only@" + digA})

	_, _, err := runCmd("upload", file, "--url", "https://cds.example:8443")
	if err == nil {
		t.Fatal("expected upload to refuse a file missing core components")
	}
}

func TestUploadForceProceedsInDryRun(t *testing.T) {
	dir := t.TempDir()
	// Missing core components, but --force + --dry-run: should not error and not write.
	file := writeAllowlistFile(t, dir, map[string]string{digA: "registry/app/only@" + digA})
	url, methods := recordingCDS(t)

	_, _, err := runCmd("upload", file, "--url", url, "--insecure", "--force", "--dry-run")
	if err != nil {
		t.Fatalf("force+dry-run should succeed, got %v", err)
	}
	if contains(*methods, http.MethodPut) {
		t.Fatal("dry-run must not issue a PUT")
	}
}

func TestUploadReplacesWhenCoreComplete(t *testing.T) {
	dir := t.TempDir()
	file := writeAllowlistFile(t, dir, coreImages())
	keyPath := writeOperatorKey(t, dir)
	url, methods := recordingCDS(t)

	_, _, err := runCmd("upload", file, "--url", url, "--insecure", "--operator-key", keyPath)
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if !contains(*methods, http.MethodPut) {
		t.Fatalf("expected a PUT, saw %v", *methods)
	}
}

func TestHTTPRefusedWithoutInsecure(t *testing.T) {
	url, methods := recordingCDS(t) // http:// httptest endpoint
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)

	_, _, err := runCmd("delete", "app", "--url", url, "--operator-key", keyPath)
	if err == nil {
		t.Fatal("expected a plaintext http:// CDS URL to be refused without --insecure")
	}
	if contains(*methods, http.MethodDelete) {
		t.Fatal("must not connect to a plaintext endpoint when --insecure is absent")
	}
}

func TestDiffExitCodeNonZeroOnDifference(t *testing.T) {
	dir := t.TempDir()
	file := writeAllowlistFile(t, dir, coreImages())
	url, _ := recordingCDS(t) // serves an empty live allowlist

	_, _, err := runCmd("diff", file, "--url", url, "--insecure", "--exit-code")
	if err == nil {
		t.Fatal("expected --exit-code to fail when the file differs from live")
	}
}

func TestDiffNoChanges(t *testing.T) {
	dir := t.TempDir()
	file := writeAllowlistFile(t, dir, map[string]string{}) // empty, matches empty live
	url, _ := recordingCDS(t)

	out, _, err := runCmd("diff", file, "--url", url, "--insecure", "--exit-code")
	if err != nil {
		t.Fatalf("no-change diff should exit zero, got %v", err)
	}
	if !strings.Contains(out, "no changes") {
		t.Fatalf("expected 'no changes', got:\n%s", out)
	}
}

func TestWriteRequiresOperatorCredential(t *testing.T) {
	url, _ := recordingCDS(t)
	// No key and no env: a write must fail before reaching CDS.
	t.Setenv(cdsconn.EnvOperatorKey, "")
	_, _, err := runCmd("delete", "app", "--url", url, "--insecure")
	if err == nil {
		t.Fatal("expected a write without an operator key to fail")
	}
}

func TestSignerPrefersFlagOverEnv(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	t.Setenv(cdsconn.EnvOperatorKey, filepath.Join(dir, "nonexistent.key"))

	o := &options{Options: cdsconn.Options{OperatorKey: keyPath, Measurements: []string{"abababababababababababababababababababababababababababababababababababababababababababababababab"}}}
	if _, err := o.signer(); err != nil {
		t.Fatalf("flag should take precedence over (broken) env, got %v", err)
	}
}

func TestSignerFallsBackToEnv(t *testing.T) {
	dir := t.TempDir()
	keyPath := writeOperatorKey(t, dir)
	t.Setenv(cdsconn.EnvOperatorKey, keyPath)

	o := &options{Options: cdsconn.Options{Measurements: []string{"abababababababababababababababababababababababababababababababababababababababababababababababab"}}} // no key flag
	if _, err := o.signer(); err != nil {
		t.Fatalf("env fallback should work, got %v", err)
	}
}

// stubVerify approves everything; the paths under test never reach it.
func stubVerify(context.Context, string, json.RawMessage, localverify.Params) (*teetypes.VerificationResult, error) {
	return &teetypes.VerificationResult{}, nil
}

// captureStderr runs fn with os.Stderr redirected to a pipe and returns what
// was written.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = old
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestClientWarnsOnlyWithoutMeasurements(t *testing.T) {
	const warning = "no --measurements set"
	base := options{Options: cdsconn.Options{URL: "https://127.0.0.1:1", Timeout: 2 * time.Second, Verifier: testutil.VerifierStub(stubVerify)}, output: "text"}

	t.Run("unpinned warns", func(t *testing.T) {
		o := base
		out := captureStderr(t, func() {
			if _, err := o.client(context.Background()); err != nil {
				t.Errorf("client: %v", err)
			}
		})
		if !strings.Contains(out, warning) {
			t.Fatalf("stderr = %q, want the unpinned-measurements warning", out)
		}
	})

	t.Run("pinned does not warn", func(t *testing.T) {
		o := base
		o.Measurements = []string{strings.Repeat("ab", 48)}
		out := captureStderr(t, func() {
			if _, err := o.client(context.Background()); err != nil {
				t.Errorf("client: %v", err)
			}
		})
		if strings.Contains(out, warning) {
			t.Fatalf("stderr = %q, warned despite pinned measurements", out)
		}
	})
}

// uploadImageLabels keys every gathered image under sequential synthetic keys.
func TestUploadImageLabelsSequentialKeys(t *testing.T) {
	al := &pkgallowlist.Allowlist{
		Schema: pkgallowlist.Schema,
		Workloads: map[string]pkgallowlist.Workload{"web": {
			Label:          "label-img",
			InitContainers: []pkgallowlist.Container{{Digest: mustDigest(t, digB), Image: "init-img"}},
			Containers:     []pkgallowlist.Container{{Digest: mustDigest(t, digC), Image: "main-img"}},
		}},
	}
	want := map[string]string{"0": "label-img", "1": "init-img", "2": "main-img"}
	if got := uploadImageLabels(al); !maps.Equal(got, want) {
		t.Fatalf("uploadImageLabels = %#v, want %#v", got, want)
	}
}

type ctxTestKey struct{}

func TestCtxPrefersCommandContext(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.WithValue(context.Background(), ctxTestKey{}, "v"))
	if got := ctx(cmd); got.Value(ctxTestKey{}) != "v" {
		t.Fatal("ctx did not return the command's own context")
	}
	if got := ctx(&cobra.Command{}); got == nil {
		t.Fatal("ctx returned nil for a command without a context")
	}
}

// guard against accidental duplicate flag registration panics.
func TestNewCmdWiring(t *testing.T) {
	cmd := NewCmd()
	want := []string{"list", "get", "export", "diff", "add", "apply", "derive", "edit", "delete", "upload", "lint", "inspect-image"}
	for _, name := range want {
		found := false
		for _, c := range cmd.Commands() {
			if c.Name() == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("subcommand %q not registered", name)
		}
	}
	_ = fmt.Sprint(cmd.Use)
}

func TestHelpDistinguishesCDSIssuedAndWebPKIRouter(t *testing.T) {
	cmd := NewCmd()
	wantLong := `Read and mutate the image allowlist that CDS serves and nri-image-policy
enforces on every node: named workload entries, each pinning an init/main
container set with per-container argv and path policy. An image that may run
with any command line is an entry whose command and args policy are both "any";
'add' writes one.

Reads (list, get, export, diff, lint, inspect-image) are unauthenticated. Writes
(add, apply, edit, delete, upload) are signed with an operator EC private key
you supply to THIS CLI via --operator-key
(or C8S_OPERATOR_KEY). The private key never leaves the CLI — it signs a
short-lived token that CDS verifies against the operator public keys it was
configured to pin separately (cds --operator-keys, set by 'c8s install
--operator-keys').

The default chart publishes /allowlist through router. Point --url at that
front door only when it uses CDS-issued public TLS (discovery reports
public_tls.mode=cds), and use the router launch digest with --measurements. A
WebPKI front door cannot yet bind its public certificate to the attestation
evidence, so this CLI refuses it; use a direct CDS ARmTLS URL instead (for
example through a port-forward) and pin the CDS launch digest. To generate an
operator key and pin its public half, see the c8s README ("Managing the image
allowlist").`
	if cmd.Long != wantLong {
		t.Fatalf("allowlist long help mismatch\n--- got ---\n%s\n--- want ---\n%s", cmd.Long, wantLong)
	}

	wantFlags := map[string]string{
		"url":          "CDS-issued-TLS router or direct CDS base URL (required); WebPKI router URLs are not attestation-bound",
		"measurements": "trusted endpoint build ID(s) (repeatable/comma-separated); use the router value for CDS-issued public TLS or the CDS value for a direct URL; empty trusts any attested build (UNSAFE)",
	}
	for name, want := range wantFlags {
		flag := cmd.PersistentFlags().Lookup(name)
		if flag == nil {
			t.Fatalf("persistent flag %q missing", name)
		}
		if flag.Usage != want {
			t.Errorf("--%s help = %q, want %q", name, flag.Usage, want)
		}
	}
}
