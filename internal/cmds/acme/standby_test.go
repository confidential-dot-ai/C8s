package acme

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, data string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadFilesAppliesOverridesAndReportsStandby(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name        string
		cfg         config
		wantStandby bool
		wantDomains []string
		wantEmail   string
		wantErr     string
	}{
		{
			name:      "overrides apply without a domains file",
			cfg:       config{email: "flag@example.com", emailFile: writeFile(t, dir, "email", "ops@example.com\n")},
			wantEmail: "ops@example.com",
		},
		{
			name:      "empty override keeps the flag",
			cfg:       config{email: "flag@example.com", emailFile: writeFile(t, dir, "empty-email", "")},
			wantEmail: "flag@example.com",
		},
		{
			name:        "domains file names the set",
			cfg:         config{domainsFile: writeFile(t, dir, "names", "a.example\nb.example\n")},
			wantDomains: []string{"a.example", "b.example"},
		},
		{
			name:        "empty domains file with a standby dir",
			cfg:         config{domainsFile: writeFile(t, dir, "none", ""), standbyCertDir: dir},
			wantStandby: true,
		},
		{
			name:    "empty domains file without a standby dir",
			cfg:     config{domainsFile: writeFile(t, dir, "none2", "\n")},
			wantErr: "--standby-cert-dir",
		},
		{
			name:    "flag and file together",
			cfg:     config{domains: []string{"a.example"}, domainsFile: writeFile(t, dir, "names2", "b.example")},
			wantErr: "mutually exclusive",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			standby, err := loadFiles(&tc.cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("loadFiles() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if standby != tc.wantStandby {
				t.Errorf("loadFiles() standby = %v, want %v", standby, tc.wantStandby)
			}
			if tc.wantEmail != "" && tc.cfg.email != tc.wantEmail {
				t.Errorf("email = %q, want %q", tc.cfg.email, tc.wantEmail)
			}
			if strings.Join(tc.cfg.domains, ",") != strings.Join(tc.wantDomains, ",") {
				t.Errorf("domains = %v, want %v", tc.cfg.domains, tc.wantDomains)
			}
		})
	}
}

func TestRunStandbyReportsReadyOnceTheLeafExists(t *testing.T) {
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runStandby(ctx, config{readyPort: port, standbyCertDir: dir}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	}()
	url := fmt.Sprintf("http://127.0.0.1:%d/readyz", port)
	status := func() int {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			resp, err := http.Get(url)
			if err == nil {
				resp.Body.Close()
				return resp.StatusCode
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("readiness listener never answered at %s", url)
		return 0
	}
	if got := status(); got != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz before the leaf = %d, want %d", got, http.StatusServiceUnavailable)
	}
	writeFile(t, dir, certFile, "cert")
	writeFile(t, dir, keyFile, "key")
	if got := status(); got != http.StatusOK {
		t.Fatalf("GET /readyz with the leaf = %d, want %d", got, http.StatusOK)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("runStandby() = %v", err)
	}
}
