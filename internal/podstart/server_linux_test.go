package podstart

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires Linux root for the production socket ownership and peer credential checks")
	}
}

func realGate(t *testing.T, consume func(context.Context, Request) error) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	requireRoot(t)
	socket := filepath.Join(socketDir(t), "gate.sock")
	l, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, l, consume)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		select {
		case <-done:
		case <-time.After(Timeout):
			t.Error("Pod start server did not stop")
		}
	})
	return socket, cancel, done
}

func TestServeUnixPermissionIsConsumedOnceAndLostOnShutdown(t *testing.T) {
	var consumed atomic.Bool
	socket, stop, done := realGate(t, func(ctx context.Context, start Request) error {
		if ctx.Err() != nil || start != testStart || !consumed.CompareAndSwap(false, true) {
			return errors.New("no matching unused permission")
		}
		return nil
	})
	wrong := testStart
	wrong.PID++
	if err := Consume(context.Background(), socket, wrong); err == nil {
		t.Fatal("another created process consumed the permission")
	}
	if err := Consume(context.Background(), socket, testStart); err != nil {
		t.Fatalf("matching process could not consume permission: %v", err)
	}
	if err := Consume(context.Background(), socket, testStart); err == nil {
		t.Fatal("the same permission authorized a second start")
	}
	stop()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session cancellation returned an error: %v", err)
		}
	case <-time.After(Timeout):
		t.Fatal("cancelled session kept serving")
	}
	if err := Consume(context.Background(), socket, testStart); err == nil {
		t.Fatal("a stopped session authorized a start")
	}
}

func TestListenProtectsAuthorityAndReplacesOnlyStaleRootSocket(t *testing.T) {
	requireRoot(t)
	socket := filepath.Join(socketDir(t), "gate.sock")
	first, err := Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(socket)
	if err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || !ownedByRoot(info) {
		_ = first.Close()
		t.Fatalf("authority is not a root-only socket: %v", info.Mode())
	}
	first.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Listen(socket)
	if err != nil {
		t.Fatalf("abandoned root-owned socket prevented a fresh listener: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
}

func TestListenRefusesUnsafeAuthorityPaths(t *testing.T) {
	requireRoot(t)
	tests := []struct {
		name    string
		prepare func(*testing.T, string) string
	}{
		{"relative", func(_ *testing.T, _ string) string { return "gate.sock" }},
		{"unclean", func(_ *testing.T, dir string) string { return dir + "/../gate.sock" }},
		{"missing parent", func(_ *testing.T, dir string) string { return filepath.Join(dir, "missing", "gate.sock") }},
		{"writable parent", func(t *testing.T, dir string) string {
			if err := os.Chmod(dir, 0o777); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "gate.sock")
		}},
		{"non-root parent", func(t *testing.T, dir string) string {
			if err := os.Chown(dir, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(dir, "gate.sock")
		}},
		{"symlink parent", func(t *testing.T, dir string) string {
			link := filepath.Join(dir, "link")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "gate.sock")
		}},
		{"existing regular file", func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "gate.sock")
			if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"existing symlink", func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "gate.sock")
			if err := os.Symlink(filepath.Join(dir, "absent"), path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{"non-root socket", func(t *testing.T, dir string) string {
			path := filepath.Join(dir, "gate.sock")
			l, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: path})
			if err != nil {
				t.Fatal(err)
			}
			l.SetUnlinkOnClose(false)
			if err := l.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 65534, 65534); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.prepare(t, socketDir(t))
			before, existed := os.Lstat(path)
			l, err := Listen(path)
			if err == nil {
				_ = l.Close()
				t.Fatal("unsafe authority path was accepted")
			}
			if existed == nil {
				after, err := os.Lstat(path)
				if err != nil || !os.SameFile(before, after) {
					t.Fatalf("refusal replaced or removed an existing path: %v", err)
				}
			}
		})
	}
}

const nonRootSocketEnv = "C8S_TEST_PODSTART_NONROOT_SOCKET"

func TestServeRejectsKernelAuthenticatedNonRootPeer(t *testing.T) {
	var calls atomic.Int32
	socket, _, _ := realGate(t, func(context.Context, Request) error { calls.Add(1); return nil })
	// Only this disposable socket permits access: admission must still require
	// SO_PEERCRED uid 0, even if a filesystem permission is accidentally widened.
	if err := os.Chmod(filepath.Dir(socket), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o666); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/fd/3", "-test.run=^TestNonRootUnixPeerHelper$")
	cmd.ExtraFiles = []*os.File{f}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}}
	cmd.Env = []string{nonRootSocketEnv + "=" + socket}
	cmd.Dir = "/"
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("non-root peer check: %v\n%s", err, out)
	}
	if calls.Load() != 0 {
		t.Fatalf("a non-root peer reached the permission authority %d times", calls.Load())
	}
}

func TestNonRootUnixPeerHelper(t *testing.T) {
	socket := os.Getenv(nonRootSocketEnv)
	if socket == "" {
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("helper did not drop its root identity")
	}
	if err := Consume(context.Background(), socket, testStart); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("non-root peer did not receive an explicit permission refusal: %v", err)
	}
}

func TestServeRejectsNonUnixConnection(t *testing.T) {
	var calls atomic.Int32
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, l, func(context.Context, Request) error { calls.Add(1); return nil }) }()
	t.Cleanup(func() { cancel(); _ = l.Close(); <-done })
	client := &http.Client{Timeout: Timeout}
	resp, err := client.Post("http://"+l.Addr().String()+"/v1/consume", "application/json", strings.NewReader(testBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || calls.Load() != 0 {
		t.Fatalf("non-Unix connection authorized: status=%d calls=%d", resp.StatusCode, calls.Load())
	}
}
