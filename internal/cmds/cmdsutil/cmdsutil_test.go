package cmdsutil

import (
	"bytes"
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

func TestRunMainSuccess(t *testing.T) {
	called := false
	RunMain(func(args []string) error {
		called = true
		return nil
	})
	if !called {
		t.Fatal("run was not called")
	}
}

func TestRunMainHelpDoesNotExit(t *testing.T) {
	// flag.ErrHelp must be swallowed (return, not os.Exit).
	RunMain(func(args []string) error {
		return flag.ErrHelp
	})
}

func TestRequireRAMBackedDir(t *testing.T) {
	dir := t.TempDir()
	err := RequireRAMBackedDir("--out-dir", dir)
	if fileutil.RequireRAMBacked(dir) == nil {
		if err != nil {
			t.Fatalf("RAM-backed dir refused: %v", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "--out-dir") {
		t.Fatalf("want a --out-dir-prefixed refusal, got %v", err)
	}
}

func TestOpenRAMBackedDir(t *testing.T) {
	dir := t.TempDir()
	root, err := OpenRAMBackedDir("--out-dir", dir)
	if fileutil.RequireRAMBacked(dir) == nil {
		if err != nil {
			t.Fatalf("RAM-backed dir refused: %v", err)
		}
		defer root.Close()
		return
	}
	if err == nil || !strings.Contains(err.Error(), "--out-dir") {
		t.Fatalf("want a --out-dir-prefixed refusal, got %v", err)
	}
}

func TestValidateHTTPURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"http://example.com", false},
		{"https://example.com", false},
		{"ftp://example.com", true},
		{"example.com", true},
		{"", true},
	}
	for _, c := range cases {
		err := ValidateHTTPURL("--endpoint", c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateHTTPURL(%q) err = %v, wantErr = %v", c.url, err, c.wantErr)
		}
		if err != nil && !contains(err.Error(), "--endpoint") {
			t.Errorf("error %q should mention flag name", err.Error())
		}
	}
}

func TestParseFlagsSuccess(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	port := fs.Int("port", 0, "")
	if err := ParseFlags(fs, []string{"-port", "8080"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if *port != 8080 {
		t.Errorf("port = %d, want 8080", *port)
	}
}

func TestParseFlagsHelpReturnsErrHelp(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	err := ParseFlags(fs, []string{"-h"})
	if err != flag.ErrHelp {
		t.Errorf("err = %v, want flag.ErrHelp", err)
	}
}

func TestServeInBackground(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok") })
	addr, err := ServeInBackground(ctx, "127.0.0.1:0", handler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("ServeInBackground = %v", err)
	}

	resp, err := http.Get("http://" + addr.String() + "/")
	if err != nil {
		t.Fatalf("GET %s = %v", addr, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Errorf("GET = %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}

	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr.String())
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("listener still accepts connections after context cancel")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A bind failure is the caller's error, not a log line.
func TestServeInBackgroundReportsBindFailure(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	_, err = ServeInBackground(context.Background(), taken.Addr().String(), http.NotFoundHandler(), slog.Default())
	if err == nil {
		t.Fatalf("ServeInBackground(%s) = nil, want an address-in-use error", taken.Addr())
	}
}

func TestShutdownOnDoneTriggersShutdown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	httpSrv := &http.Server{}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		ShutdownOnDone(ctx, httpSrv, time.Second)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ShutdownOnDone did not return after context cancel")
	}
	srv.Close()
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestValidateAttestationAPIURL(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"http://localhost:8400", false},
		{"https://attestation-api:8400", false},
		{"unix:///run/nri-image-policy/attestation-api.sock", false},
		{"unix://relative.sock", true},
		{"unix://", true},
		{"ftp://example.com", true},
		{"", true},
	}
	for _, c := range cases {
		err := ValidateAttestationAPIURL("--attestation-api-url", c.url)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateAttestationAPIURL(%q) err = %v, wantErr = %v", c.url, err, c.wantErr)
		}
		if err != nil && !contains(err.Error(), "--attestation-api-url") {
			t.Errorf("error %q should mention flag name", err.Error())
		}
	}
}

func TestWarnIfCDSUnpinned(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, count := range []int{0, 1, 2} {
		logs.Reset()
		WarnIfCDSUnpinned(count, "unpinned development configuration")
		warned := strings.Contains(logs.String(), "unpinned development configuration")
		if warned != (count == 0) {
			t.Errorf("measurement count %d: warning=%t", count, warned)
		}
	}
}

func TestExpandHostIP(t *testing.T) {
	for _, tc := range []struct {
		name, hostIP, in, want string
		wantErr                bool
	}{
		{name: "reference", hostIP: "192.0.2.7", in: "http://$(HOST_IP):8400", want: "http://192.0.2.7:8400"},
		{name: "IPv6", hostIP: "2001:db8::7", in: "http://$(HOST_IP):8400", want: "http://[2001:db8::7]:8400"},
		{name: "IPv4-mapped IPv6", hostIP: "::ffff:192.0.2.7", in: "http://$(HOST_IP):8400", want: "http://192.0.2.7:8400"},
		{name: "unix socket", in: "unix:///run/attestation-api.sock", want: "unix:///run/attestation-api.sock"},
		{name: "other variable", in: "http://$(POD_IP):8400", want: "http://$(POD_IP):8400"},
		{name: "unset", in: "http://$(HOST_IP):8400", wantErr: true},
		{name: "not an address", hostIP: "node-a", in: "http://$(HOST_IP):8400", wantErr: true},
		{name: "zoned", hostIP: "fe80::1%eth0", in: "http://$(HOST_IP):8400", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOST_IP", tc.hostIP)
			got, err := ExpandHostIP(tc.in)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("ExpandHostIP(%q) = %q, %v, want %q, error %v", tc.in, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

// $(NODE_IP) comes from the node-ip file only: HOST_IP, which a pod sets,
// never reaches it.
func TestExpandNodeIP(t *testing.T) {
	getenv := func(string) string { return "203.0.113.66" }
	for _, tc := range []struct {
		name    string
		file    *string
		in      string
		want    string
		wantErr bool
	}{
		{name: "file", file: ptr("192.0.2.7\n"), in: "http://$(NODE_IP):8400", want: "http://192.0.2.7:8400"},
		{name: "IPv6 file", file: ptr("2001:db8::7"), in: "http://$(NODE_IP):8400", want: "http://[2001:db8::7]:8400"},
		{name: "missing file", in: "http://$(NODE_IP):8400", wantErr: true},
		{name: "empty file", file: ptr(""), in: "http://$(NODE_IP):8400", wantErr: true},
		{name: "not an address", file: ptr("node-a"), in: "http://$(NODE_IP):8400", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "node-ip")
			if tc.file != nil {
				if err := os.WriteFile(path, []byte(*tc.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := expandNodeAddress(tc.in, path, getenv)
			if (err != nil) != tc.wantErr || got != tc.want {
				t.Fatalf("expandNodeAddress(%q) = %q, %v, want %q, error %v", tc.in, got, err, tc.want, tc.wantErr)
			}
		})
	}
}

func ptr(s string) *string { return &s }
