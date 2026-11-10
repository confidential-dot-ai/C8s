package attestproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

// deadUpstream is an upstream URL nothing listens on.
const deadUpstream = "http://127.0.0.1:1"

// startUpstream returns a running fake attestation-api and its URL.
func startUpstream(t *testing.T, handler http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// serveProxy runs the proxy on a temp socket until the test ends.
func serveProxy(t *testing.T, cfg config) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "attest.sock")
	cfg.socket = sock
	if cfg.readHeaderTimeout == 0 {
		cfg.readHeaderTimeout = time.Second
	}
	proxy, err := newProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Bound here, so the socket carries its mode and group before any test
	// looks at it; only the serve loop runs in the background.
	listener, err := workloadclaims.ListenUnix(sock, cfg.socketGID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, proxy, listener) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("proxy serve: %v", err)
		}
	})
	return sock
}

func TestProxyForwardsOverSocket(t *testing.T) {
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/attest" {
			t.Errorf("upstream saw path %s, want /attest", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"platform":"snp","evidence":{}}`))
	}))
	sock := serveProxy(t, config{upstream: upstream, socketGID: 0})

	if _, err := remote.NewClient("unix://"+sock).Attest(context.Background(), remote.AttestRequest{}); err != nil {
		t.Fatalf("Attest over proxy socket: %v", err)
	}
}

func TestProxySocketPermissions(t *testing.T) {
	upstream := startUpstream(t, http.NotFoundHandler())
	sock := serveProxy(t, config{upstream: upstream, socketGID: os.Getegid()})

	fi, err := os.Lstat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("%s is not a socket (mode %s)", sock, fi.Mode())
	}
	if got := fi.Mode().Perm(); got != 0o660 {
		t.Fatalf("socket mode = %#o, want 0660", got)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Gid) != os.Getegid() {
		t.Fatalf("socket gid = %d, want %d", st.Gid, os.Getegid())
	}
}

func TestProxyReportsUpstreamDown(t *testing.T) {
	// Nothing listens on the upstream; the proxy must answer 502, not hang.
	sock := serveProxy(t, config{upstream: "http://127.0.0.1:1", socketGID: 0})
	_, err := remote.NewClient("unix://" + sock).Health(context.Background())
	var unexpErr *remote.UnexpectedError
	if err == nil {
		t.Fatal("Health succeeded against a dead upstream")
	}
	if !errors.As(err, &unexpErr) || unexpErr.Status != http.StatusBadGateway {
		t.Fatalf("err = %v, want 502", err)
	}
}

func TestNewProxyRejectsBadConfig(t *testing.T) {
	upstream := startUpstream(t, http.NotFoundHandler())
	for _, tc := range []struct {
		name string
		cfg  config
	}{
		{"relative socket", config{socket: "rel.sock", upstream: upstream, readHeaderTimeout: time.Second}},
		{"bad upstream scheme", config{socket: "/tmp/x.sock", upstream: "ftp://x", readHeaderTimeout: time.Second}},
		{"nonpositive header timeout", config{socket: "/tmp/x.sock", upstream: upstream}},
		{"health address without a port", config{socket: "/tmp/x.sock", upstream: upstream, readHeaderTimeout: time.Second, healthAddr: "8401"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newProxy(tc.cfg); err == nil {
				t.Fatal("newProxy succeeded, want rejection")
			}
		})
	}
}

// The healthcheck subcommand must succeed against a live proxied upstream and
// fail against a missing socket.
func TestHealthcheckCmd(t *testing.T) {
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	sock := serveProxy(t, config{upstream: upstream, socketGID: 0})

	cmd := newHealthcheckCmd()
	cmd.SetArgs([]string{"--socket", sock})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("healthcheck against live proxied upstream: %v", err)
	}

	starting := newHealthcheckCmd()
	starting.SetArgs([]string{"--socket", serveProxy(t, config{upstream: startUpstream(t, healthStatus("starting")), socketGID: 0})})
	if err := starting.Execute(); err == nil {
		t.Fatal("healthcheck succeeded against a starting upstream")
	}

	missing := newHealthcheckCmd()
	missing.SetArgs([]string{"--socket", filepath.Join(t.TempDir(), "gone.sock")})
	if err := missing.Execute(); err == nil {
		t.Fatal("healthcheck succeeded against a missing socket")
	}
}

// /healthz, the readiness probe, must answer for a live upstream and fail for a
// dead one, matching the healthcheck subcommand.
func TestHealthEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		upstream http.Handler
		want     int
	}{
		{
			name: "live upstream",
			upstream: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"status":"ok"}`))
			}),
			want: http.StatusOK,
		},
		{
			name:     "upstream refusing health",
			upstream: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }),
			want:     http.StatusServiceUnavailable,
		},
		{
			name:     "upstream starting",
			upstream: healthStatus("starting"),
			want:     http.StatusServiceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := startUpstream(t, tt.upstream)
			sock := serveProxy(t, config{upstream: upstream, socketGID: 0})

			rec := httptest.NewRecorder()
			healthHandler(sock, upstream).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

			if rec.Code != tt.want {
				t.Errorf("GET /healthz = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// A probe against a proxy whose socket is gone must fail, not hang.
func TestHealthEndpointWithoutSocket(t *testing.T) {
	rec := httptest.NewRecorder()
	healthHandler(filepath.Join(t.TempDir(), "gone.sock"), deadUpstream).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /healthz with no socket = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
}

// attest-proxy's liveness reports only its own state: a dead upstream keeps it
// live, a socket that does not accept does not.
func TestLivez(t *testing.T) {
	sock := serveProxy(t, config{upstream: deadUpstream, socketGID: 0})
	notSocket := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notSocket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// A listener closed without unlinking leaves a socket file nothing accepts on.
	closed := filepath.Join(t.TempDir(), "closed.sock")
	l, err := net.Listen("unix", closed)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	// A wedged serve loop: the kernel queues the connection, nothing answers.
	wedged := filepath.Join(t.TempDir(), "wedged.sock")
	wl, err := net.Listen("unix", wedged)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wl.Close() })
	tests := []struct {
		name   string
		socket string
		want   int
	}{
		{
			name:   "serve loop wedged",
			socket: wedged,
			want:   http.StatusServiceUnavailable,
		},
		{
			name:   "listener closed",
			socket: closed,
			want:   http.StatusServiceUnavailable,
		},
		{
			name:   "upstream down",
			socket: sock,
			want:   http.StatusOK,
		},
		{
			name:   "socket gone",
			socket: filepath.Join(t.TempDir(), "gone.sock"),
			want:   http.StatusServiceUnavailable,
		},
		{
			name:   "socket replaced by a file",
			socket: notSocket,
			want:   http.StatusServiceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			healthHandler(tt.socket, deadUpstream).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/livez", nil))
			if rec.Code != tt.want {
				t.Errorf("GET /livez = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// /upstream/livez, the attestation-api's liveness, calls the upstream directly,
// so it needs no socket, and passes on any status a 2xx answer reports.
func TestUpstreamLivez(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		want     int
	}{
		{
			name:     "upstream up",
			upstream: startUpstream(t, healthStatus("ok")),
			want:     http.StatusOK,
		},
		{
			name:     "upstream starting",
			upstream: startUpstream(t, healthStatus("starting")),
			want:     http.StatusOK,
		},
		{
			name: "upstream answers 200 without JSON",
			upstream: startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = fmt.Fprint(w, "not json")
			})),
			want: http.StatusServiceUnavailable,
		},
		{
			name: "upstream answers 503",
			upstream: startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"status":"degraded"}`, http.StatusServiceUnavailable)
			})),
			want: http.StatusServiceUnavailable,
		},
		{
			name:     "upstream down",
			upstream: deadUpstream,
			want:     http.StatusServiceUnavailable,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			healthHandler(filepath.Join(t.TempDir(), "gone.sock"), tt.upstream).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/livez", nil))
			if rec.Code != tt.want {
				t.Errorf("GET /upstream/livez = %d, want %d", rec.Code, tt.want)
			}
		})
	}
}

// healthStatus answers GET /health with status.
func healthStatus(status string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":%q}`, status)
	})
}

// A hung upstream fails /upstream/livez on the handler's own budget rather
// than hanging until the kubelet gives up.
func TestUpstreamLivezTimesOut(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	upstream := startUpstream(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(func() { close(release) })

	start := time.Now()
	rec := httptest.NewRecorder()
	healthHandler("/nonexistent.sock", upstream).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/livez", nil))
	elapsed := time.Since(start)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /upstream/livez against a hung upstream = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	// The upper bound only catches a handler that ignores its budget; it is
	// loose so a loaded runner does not trip it.
	if maxElapsed := healthcheckTimeout + 5*time.Second; elapsed < healthcheckTimeout || elapsed >= maxElapsed {
		t.Errorf("GET /upstream/livez took %s, want between %s and %s", elapsed, healthcheckTimeout, maxElapsed)
	}
}

// The health endpoint binds before the proxy serves, and a bind failure is
// a startup error rather than a pod whose probes never pass.
func TestServeHealthAddr(t *testing.T) {
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	serveProxy(t, config{upstream: upstream, healthAddr: "127.0.0.1:0"})

	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	cfg := config{socket: filepath.Join(t.TempDir(), "attest.sock"), upstream: upstream, readHeaderTimeout: time.Second, healthAddr: taken.Addr().String()}
	proxy, err := newProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := workloadclaims.ListenUnix(cfg.socket, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := serve(context.Background(), cfg, proxy, listener); err == nil || !strings.Contains(err.Error(), "--health-addr") {
		t.Fatalf("serve with a taken --health-addr = %v, want a --health-addr error", err)
	}
}

// awaitServerClose fails the test unless the server closes c within wait.
func awaitServerClose(t *testing.T, c net.Conn, wait time.Duration) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(wait)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("connection still open after %s: %v", wait, err)
	}
}

func TestServerBoundsConnections(t *testing.T) {
	const timeout = 300 * time.Millisecond
	upstream := startUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))

	t.Run("stalled body", func(t *testing.T) {
		sock := serveProxy(t, config{upstream: upstream, readTimeout: timeout, writeTimeout: time.Minute, idleTimeout: time.Minute})
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := io.WriteString(c, "POST /attest HTTP/1.1\r\nHost: x\r\nContent-Length: 1024\r\n\r\n{"); err != nil {
			t.Fatal(err)
		}
		awaitServerClose(t, c, 20*timeout)
	})

	t.Run("idle keep-alive", func(t *testing.T) {
		sock := serveProxy(t, config{upstream: upstream, readTimeout: time.Minute, writeTimeout: time.Minute, idleTimeout: timeout})
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := io.WriteString(c, "GET /health HTTP/1.1\r\nHost: x\r\n\r\n"); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || resp.Close {
			t.Fatalf("GET /health = %d (close %t), want 200 on a kept-alive connection", resp.StatusCode, resp.Close)
		}
		awaitServerClose(t, c, 20*timeout)
	})
}

func TestNewProxyCapsUpstreamConns(t *testing.T) {
	h, err := newProxy(config{socket: "/tmp/x.sock", upstream: "http://127.0.0.1:1", readHeaderTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if got := h.(*httputil.ReverseProxy).Transport.(*http.Transport).MaxConnsPerHost; got <= 0 {
		t.Errorf("upstream MaxConnsPerHost = %d, want a positive cap", got)
	}
}
