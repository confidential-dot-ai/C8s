package acme

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validTestConfig() config {
	return config{
		domains:       []string{"lb.example.com", "infer.lb.example.com"},
		directoryURL:  letsEncryptDirectoryURL,
		challengePort: 8402,
		httpPort:      8080,
		certDir:       "/etc/c8s-acme-tls",
	}
}

func TestValidateConfig(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*config)
		wantErr string
	}{
		{"valid", func(*config) {}, ""},
		{"no domains", func(c *config) { c.domains = nil }, "--domains"},
		{"bad domain", func(c *config) { c.domains = []string{"-bad-"} }, "--domains"},
		{"domain with scheme", func(c *config) { c.domains = []string{"https://lb"} }, "--domains"},
		{"empty domain", func(c *config) { c.domains = []string{""} }, "--domains"},
		{"ip domain", func(c *config) { c.domains = []string{"192.0.2.1"} }, "--domains"},
		{"overlong domain", func(c *config) { c.domains = []string{strings.Repeat("a.", 127) + "aa"} }, "--domains"},
		{"duplicate domain", func(c *config) { c.domains = []string{"lb.example.com", "lb.example.com"} }, "twice"},
		{"bad directory url", func(c *config) { c.directoryURL = "acme.example" }, "--acme-directory-url"},
		{"port zero", func(c *config) { c.challengePort = 0 }, "--challenge-port"},
		{"port too large", func(c *config) { c.challengePort = 70000 }, "--challenge-port"},
		{"http port zero", func(c *config) { c.httpPort = 0 }, "--http-port"},
		{"http port equals challenge port", func(c *config) { c.httpPort = c.challengePort }, "--http-port and --challenge-port must differ"},
		{"ready port too large", func(c *config) { c.readyPort = 70000 }, "--ready-port"},
		{"ready port collides with the challenge port", func(c *config) { c.readyPort = c.challengePort }, "--ready-port must differ"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validTestConfig()
			tc.mutate(&cfg)
			err := validateConfig(&cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestNewLogger(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		if _, err := newLogger(level); err != nil {
			t.Fatalf("newLogger(%q): %v", level, err)
		}
	}
	if _, err := newLogger("chatty"); err == nil {
		t.Fatal("invalid level accepted")
	}
}

// The cobra command hands its parsed config to run.
func TestCmdRunEReportsRunError(t *testing.T) {
	cmd := NewCmd()
	cmd.SetArgs([]string{
		"--domains", "lb.example.com",
		"--log-level", "chatty",
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--log-level") {
		t.Fatalf("Execute = %v, want the run error", err)
	}
}

// nginx's startup probe reads this endpoint instead of exec'ing probe-file:
// it must stay 503 until both files exist and carry bytes.
func TestReadyHandler(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "cert.pem")
	key := filepath.Join(dir, "key.pem")
	handler := readyHandler(cert, key)

	get := func() int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		return rec.Code
	}

	if got := get(); got != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz with no certificate = %d, want %d", got, http.StatusServiceUnavailable)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /healthz with no certificate = %d, want %d", rec.Code, http.StatusOK)
	}
	if err := os.WriteFile(cert, []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := get(); got != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz with no key = %d, want %d", got, http.StatusServiceUnavailable)
	}
	if err := os.WriteFile(key, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := get(); got != http.StatusServiceUnavailable {
		t.Errorf("GET /readyz with an empty key = %d, want %d", got, http.StatusServiceUnavailable)
	}
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := get(); got != http.StatusOK {
		t.Errorf("GET /readyz with both files = %d, want %d", got, http.StatusOK)
	}
}
