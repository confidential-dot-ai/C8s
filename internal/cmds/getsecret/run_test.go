package getsecret

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// TestPrepareOutDir: the "must be memory-backed" invariant on --out-dir is
// enforced, not merely documented.
func TestPrepareOutDir(t *testing.T) {
	dir := t.TempDir()
	if fileutil.RequireRAMBacked(dir) == nil {
		t.Skipf("%s is RAM-backed; no on-disk path to reject", dir)
	}
	out := filepath.Join(dir, "secrets")
	if _, err := prepareOutDir(out); err == nil {
		t.Fatal("expected an out-dir on persistent storage to be refused")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("refusal must not create the out-dir on the storage it rejects")
	}
}

func TestParseSecretSpec(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spec     string
		wantName string
		wantPath string
		wantErr  bool
	}{
		{name: "simple", spec: "DB=/api/db", wantName: "DB", wantPath: "/api/db"},
		{name: "spaces are trimmed", spec: " DB = /api/db ", wantName: "DB", wantPath: "/api/db"},
		{name: "nested path", spec: "K=/a/b/c", wantName: "K", wantPath: "/a/b/c"},
		{name: "no separator", spec: "/api/db", wantErr: true},
		{name: "empty name", spec: "=/api/db", wantErr: true},
		// The name becomes a filename, so anything path-shaped is refused
		// rather than resolved.
		{name: "name is a path", spec: "a/b=/api/db", wantErr: true},
		{name: "name escapes the dir", spec: "..=/api/db", wantErr: true},
		{name: "relative store path", spec: "DB=api/db", wantErr: true},
		{name: "unclean store path", spec: "DB=/api/../etc", wantErr: true},
		{name: "wildcard store path", spec: "DB=/api/**", wantErr: true},
		{name: "percent-encoded store path", spec: "DB=/api%2Fdb", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSecretSpec(tc.spec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseSecretSpec(%q) = %+v, want an error", tc.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseSecretSpec(%q): %v", tc.spec, err)
			}
			if got.Name != tc.wantName || got.Path != tc.wantPath {
				t.Fatalf("parseSecretSpec(%q) = %+v, want {%s %s}", tc.spec, got, tc.wantName, tc.wantPath)
			}
		})
	}
}

func validConfig(t *testing.T) config {
	t.Helper()
	return config{
		SecretsURL:        "https://cds.example",
		AttestationApiURL: "http://127.0.0.1:8080",
		Attempts:          3,
		RetryInterval:     time.Second,
		RequestTimeout:    time.Second,
		InventoryTimeout:  time.Second,
		Secrets:           []secretRequest{{Name: "DB", Path: "/api/db"}},
		OutDir:            t.TempDir(),
		FileMode:          "0640",
	}
}

func TestValidate(t *testing.T) {
	if err := validate(new(validConfig(t))); err != nil {
		t.Fatalf("a valid config was refused: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*config)
		want   string
	}{
		{"no cds url", func(c *config) { c.SecretsURL = "" }, "--cds-secrets-url"},
		{"plaintext cds url", func(c *config) { c.SecretsURL = "http://cds.example" }, "https"},
		{"no attestation api", func(c *config) { c.AttestationApiURL = "" }, "--attestation-api-url"},
		{"no secrets", func(c *config) { c.Secrets = nil }, "--secret"},
		{"zero attempts", func(c *config) { c.Attempts = 0 }, "--attempts"},
		{"zero retry interval", func(c *config) { c.RetryInterval = 0 }, "--retry-interval"},
		{"bad file mode", func(c *config) { c.FileMode = "rw-r-----" }, "--file-mode"},
		{"file mode out of range", func(c *config) { c.FileMode = "7777" }, "--file-mode"},
		{
			"repeated secret name",
			func(c *config) {
				c.Secrets = append(c.Secrets, secretRequest{Name: "DB", Path: "/api/other"})
			},
			"repeated",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			tc.mutate(&cfg)
			err := validate(&cfg)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// A trailing slash on --cds-secrets-url must not produce a double slash in the request
// path, which the server would reject as non-canonical.
func TestValidateTrimsURL(t *testing.T) {
	cfg := validConfig(t)
	cfg.SecretsURL = "https://cds.example/"
	if err := validate(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.SecretsURL != "https://cds.example" {
		t.Fatalf("SecretsURL = %q, want the trailing slash trimmed", cfg.SecretsURL)
	}
}

func TestWriteAll(t *testing.T) {
	cfg := validConfig(t)
	root := openOutRoot(t, cfg.OutDir)
	values := map[string][]byte{
		"DB":    []byte("s3cret"),
		"OTHER": {0x00, 0xff, '\n', '"'}, // raw bytes, not text
	}
	if err := writeAll(root, cfg, values); err != nil {
		t.Fatal(err)
	}
	for name, want := range values {
		path := filepath.Join(cfg.OutDir, name)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != string(want) {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("%s mode = %o, want 640", name, info.Mode().Perm())
		}
	}
}

// Nothing is left behind by the atomic write: a consumer polling the directory
// must not find a temp file and mistake it for its secret.
func TestWriteAllLeavesNoTempFiles(t *testing.T) {
	cfg := validConfig(t)
	root := openOutRoot(t, cfg.OutDir)
	if err := writeAll(root, cfg, map[string][]byte{"DB": []byte("v")}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(cfg.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "DB" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory holds %v, want just [DB]", names)
	}
}

// Rewriting is how a renewal or a re-fetch lands, so it must replace rather
// than fail or append.
func TestWriteAllOverwrites(t *testing.T) {
	cfg := validConfig(t)
	root := openOutRoot(t, cfg.OutDir)
	if err := writeAll(root, cfg, map[string][]byte{"DB": []byte("first")}); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(root, cfg, map[string][]byte{"DB": []byte("second")}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(cfg.OutDir, "DB"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "second" {
		t.Fatalf("value = %q, want the rewritten one", got)
	}
}

func TestWriteAllWritesPreparedDir(t *testing.T) {
	cfg := validConfig(t)
	cfg.OutDir = filepath.Join(cfg.OutDir, "nested", "secrets")
	if err := os.MkdirAll(cfg.OutDir, 0o750); err != nil {
		t.Fatal(err)
	}
	root := openOutRoot(t, cfg.OutDir)
	if err := writeAll(root, cfg, map[string][]byte{"DB": []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(cfg.OutDir, "DB")); err != nil {
		t.Fatal(err)
	}
}

func TestParseFileMode(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    os.FileMode
		wantErr bool
	}{
		{in: "0640", want: 0o640},
		{in: "640", want: 0o640},
		{in: "0400", want: 0o400},
		{in: "0", wantErr: true},
		{in: "1000", wantErr: true},
		{in: "notamode", wantErr: true},
	} {
		got, err := parseFileMode(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseFileMode(%q) = %o, want an error", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("parseFileMode(%q) = %o, %v; want %o", tc.in, got, err, tc.want)
		}
	}
}

// An unwritable output directory fails loudly rather than reporting success
// with no file on disk.
func TestWriteAllUnwritable(t *testing.T) {
	cfg := validConfig(t)
	cfg.OutDir = filepath.Join(cfg.OutDir, "readonly")
	if err := os.MkdirAll(cfg.OutDir, 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, which ignores the directory mode")
	}
	root := openOutRoot(t, cfg.OutDir)
	if err := writeAll(root, cfg, map[string][]byte{"DB": []byte("v")}); err == nil {
		t.Fatal("an unwritable directory reported success")
	}
}

func TestWriteAllRejectsBadMode(t *testing.T) {
	cfg := validConfig(t)
	cfg.FileMode = "notamode"
	root := openOutRoot(t, cfg.OutDir)
	if err := writeAll(root, cfg, map[string][]byte{"DB": []byte("v")}); err == nil {
		t.Fatal("a bad file mode was accepted")
	}
}

// The final RAM-backed check returns an open root. Keeping it through the
// write is what prevents an attacker from replacing --out-dir after startup.
func TestWriteAllStaysInVerifiedOutDirAfterPathReplacement(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("RAM-backed output verification is linux-only")
	}
	base, err := os.MkdirTemp("/dev/shm", "c8s-getsecret-")
	if err != nil {
		t.Skipf("cannot create a temporary directory in /dev/shm: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := fileutil.RequireRAMBacked(base); err != nil {
		t.Skipf("/dev/shm is not usable tmpfs: %v", err)
	}

	cfg := validConfig(t)
	cfg.OutDir = filepath.Join(base, "out")
	root, err := prepareOutDir(cfg.OutDir)
	if err != nil {
		t.Fatalf("prepareOutDir: %v", err)
	}
	defer root.Close()

	moved := filepath.Join(base, "moved")
	if err := os.Rename(cfg.OutDir, moved); err != nil {
		t.Fatalf("move verified directory: %v", err)
	}
	trap := t.TempDir()
	if err := os.Symlink(trap, cfg.OutDir); err != nil {
		t.Fatalf("replace verified directory: %v", err)
	}

	if err := writeAll(root, cfg, map[string][]byte{"DB": []byte("secret")}); err != nil {
		t.Fatalf("writeAll: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(moved, "DB")); err != nil || string(got) != "secret" {
		t.Fatalf("original verified directory holds %q, %v; want secret", got, err)
	}
	if _, err := os.Stat(filepath.Join(trap, "DB")); !os.IsNotExist(err) {
		t.Fatalf("write followed replacement --out-dir, stat error = %v", err)
	}
}

func openOutRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open output root: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

// A malformed RTMR pin is a typo in rendered config; pinning nothing is not
// an acceptable fallback for it.
func TestRunRejectsBadRTMRs(t *testing.T) {
	cfg := validConfig(t)
	cfg.RTMRs = []string{"nope"}
	if err := run(cfg); err == nil || !strings.Contains(err.Error(), "--rtmrs") {
		t.Fatalf("err = %v, want an RTMR-parse failure", err)
	}
}
