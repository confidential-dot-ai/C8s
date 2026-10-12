package cmdsutil

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
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
		{"unix:///var/run/nri-image-policy/attestation-api.sock", false},
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

func TestRequireCDSPinsRefusesPinsThatNameNoGuest(t *testing.T) {
	digest := make([]byte, 48)
	cases := []struct {
		name    string
		pins    armtls.Pins
		wantErr bool
	}{
		{"no pins", armtls.Pins{}, true},
		{"registers only", armtls.Pins{Registers: map[int][]byte{1: digest}}, true},
		{"vTPM PCRs only", armtls.Pins{PCRs: map[int][]byte{11: digest[:32]}}, true},
		{"launch digest", armtls.Pins{Measurements: [][]byte{digest}}, false},
		{"image", armtls.Pins{Images: []remote.ImagePin{{Name: "node", Digest: digest}}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := RequireCDSPins(c.pins, "--measurements")
			if (err != nil) != c.wantErr {
				t.Fatalf("RequireCDSPins err = %v, wantErr = %t", err, c.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "--measurements") {
				t.Errorf("error %q should name the input that sets the pins", err)
			}
		})
	}
}
