package attestproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveAPI runs handler as a fake attestation-api bound on a 0660 socket, as
// the real one binds it, and returns the socket path.
func serveAPI(t *testing.T, handler http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

// refusingSocket returns a socket file nothing listens on, as a crashed API
// leaves behind.
func refusingSocket(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "api.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return sock
}

func probe(handler http.Handler, path string) int {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code
}

func TestProbes(t *testing.T) {
	worldWritable := serveAPI(t, healthStatus("ok"))
	if err := os.Chmod(worldWritable, 0o666); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		socket    string
		readiness int
		apiLive   int
	}{
		{
			name:      "api ok",
			socket:    serveAPI(t, healthStatus("ok")),
			readiness: http.StatusOK,
			apiLive:   http.StatusOK,
		},
		{
			name:      "api answers 2xx with a status other than ok",
			socket:    serveAPI(t, healthStatus("degraded")),
			readiness: http.StatusServiceUnavailable,
			apiLive:   http.StatusOK,
		},
		{
			name: "api answers 200 without JSON",
			socket: serveAPI(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("not json"))
			})),
			readiness: http.StatusServiceUnavailable,
			apiLive:   http.StatusServiceUnavailable,
		},
		{
			name: "api answers 503",
			socket: serveAPI(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"status":"degraded"}`, http.StatusServiceUnavailable)
			})),
			readiness: http.StatusServiceUnavailable,
			apiLive:   http.StatusServiceUnavailable,
		},
		{
			name:      "socket missing",
			socket:    filepath.Join(t.TempDir(), "gone.sock"),
			readiness: http.StatusServiceUnavailable,
			apiLive:   http.StatusServiceUnavailable,
		},
		{
			name:      "socket refusing connections",
			socket:    refusingSocket(t),
			readiness: http.StatusServiceUnavailable,
			apiLive:   http.StatusServiceUnavailable,
		},
		{
			name:      "socket world-writable",
			socket:    worldWritable,
			readiness: http.StatusServiceUnavailable,
			apiLive:   http.StatusServiceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := probesHandler(tt.socket)
			if got := probe(h, "/livez"); got != http.StatusOK {
				t.Errorf("GET /livez = %d, want %d", got, http.StatusOK)
			}
			if got := probe(h, "/healthz"); got != tt.readiness {
				t.Errorf("GET /healthz = %d, want %d", got, tt.readiness)
			}
			if got := probe(h, "/api/livez"); got != tt.apiLive {
				t.Errorf("GET /api/livez = %d, want %d", got, tt.apiLive)
			}
		})
	}
}

// The client accepts only a socket owned by root or the caller, so a socket
// another user planted fails both API probes.
func TestProbesRejectForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chown to another uid needs root")
	}
	sock := serveAPI(t, healthStatus("ok"))
	if err := os.Chown(sock, 12345, -1); err != nil {
		t.Fatal(err)
	}
	h := probesHandler(sock)
	for _, path := range []string{"/healthz", "/api/livez"} {
		if got := probe(h, path); got != http.StatusServiceUnavailable {
			t.Errorf("GET %s = %d, want %d", path, got, http.StatusServiceUnavailable)
		}
	}
}

// A hung API fails /api/livez on the handler's own budget rather than hanging
// until the kubelet gives up.
func TestAPILivezTimesOut(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	sock := serveAPI(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release) })

	start := time.Now()
	got := probe(probesHandler(sock), "/api/livez")
	elapsed := time.Since(start)
	if got != http.StatusServiceUnavailable {
		t.Errorf("GET /api/livez against a hung API = %d, want %d", got, http.StatusServiceUnavailable)
	}
	// The upper bound only catches a handler that ignores its budget; it is
	// loose so a loaded runner does not trip it.
	if maxElapsed := healthcheckTimeout + 5*time.Second; elapsed < healthcheckTimeout || elapsed >= maxElapsed {
		t.Errorf("GET /api/livez took %s, want between %s and %s", elapsed, healthcheckTimeout, maxElapsed)
	}
}

func TestServeProbes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sock := serveAPI(t, healthStatus("ok"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProbes(ctx, listener, sock) }()

	resp, err := http.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /healthz = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serveProbes after cancel = %v, want nil", err)
	}
}

func TestProbesCmdRejectsBadFlags(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "relative socket",
			args: []string{"--socket=api.sock", "--addr=127.0.0.1:0"},
			want: "--socket",
		},
		{
			name: "taken address",
			args: []string{"--socket=/run/api.sock", "--addr=" + taken.Addr().String()},
			want: "--addr",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newProbesCmd()
			cmd.SetArgs(tc.args)
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("probes %v = %v, want a %s error", tc.args, err, tc.want)
			}
		})
	}
}
