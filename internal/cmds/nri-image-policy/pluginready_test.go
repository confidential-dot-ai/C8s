package nriimagepolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// standInEnv makes the test binary idle as a process with a chosen argv[0].
const standInEnv = "NRI_IMAGE_POLICY_TEST_STANDIN"

func init() {
	if os.Getenv(standInEnv) == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
}

const testPluginPath = "/opt/nri/plugins/10-nri-image-policy"

// fakeProcess is one /proc/<pid> entry.
type fakeProcess struct {
	cmdline string
	comm    string
	ppid    int
}

// fakeProc lays out a procfs with cmdline, comm and stat per pid.
func fakeProc(t *testing.T, procs map[int]fakeProcess) string {
	t.Helper()
	root := t.TempDir()
	for pid, p := range procs {
		dir := filepath.Join(root, fmt.Sprint(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		stat := fmt.Sprintf("%d (%s) S %d 1 1 0 -1\n", pid, p.comm, p.ppid)
		for name, data := range map[string]string{"cmdline": p.cmdline, "comm": p.comm + "\n", "stat": stat} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// Process trees as a node runs them. PID 1 is the init system.
var (
	systemd    = fakeProcess{cmdline: "/sbin/init\x00", comm: "systemd", ppid: 0}
	pluginProc = func(ppid int) fakeProcess {
		return fakeProcess{cmdline: testPluginPath + "\x00", comm: "10-nri-image-po", ppid: ppid}
	}
	containerd = func(ppid int) fakeProcess {
		return fakeProcess{cmdline: "/usr/bin/containerd\x00", comm: "containerd", ppid: ppid}
	}
	kubeadmTree = map[int]fakeProcess{1: systemd, 100: containerd(1), 200: pluginProc(100)}
	rke2Tree    = map[int]fakeProcess{
		1:   systemd,
		50:  {cmdline: "/usr/local/bin/rke2\x00agent\x00", comm: "rke2", ppid: 1},
		100: containerd(50),
		200: pluginProc(100),
	}
)

func with(tree map[int]fakeProcess, extra map[int]fakeProcess) map[int]fakeProcess {
	out := map[int]fakeProcess{}
	for k, v := range tree {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func TestPluginRunning(t *testing.T) {
	shim := fakeProcess{cmdline: "/usr/bin/containerd-shim-runc-v2\x00", comm: "containerd-shim", ppid: 1}
	for _, tc := range []struct {
		name  string
		procs map[int]fakeProcess
		want  bool
	}{
		{"kubeadm containerd", kubeadmTree, true},
		{"rke2 containerd", rke2Tree, true},
		// Any supervisor between containerd and PID 1 is fine.
		{"k3s containerd", map[int]fakeProcess{
			1: systemd, 50: {cmdline: "/usr/local/bin/k3s\x00server\x00", comm: "k3s-server", ppid: 1},
			100: containerd(50), 200: pluginProc(100),
		}, true},
		{"dockerd containerd", map[int]fakeProcess{
			1: systemd, 50: {cmdline: "/usr/bin/dockerd\x00", comm: "dockerd", ppid: 1},
			100: containerd(50), 200: pluginProc(100),
		}, true},
		{"wrapper unit", map[int]fakeProcess{
			1: systemd, 40: {cmdline: "/bin/sh\x00", comm: "sh", ppid: 1},
			50:  {cmdline: "/usr/local/bin/wrap\x00", comm: "wrap", ppid: 40},
			100: containerd(50), 200: pluginProc(100),
		}, true},
		{"supervisor chain too deep", func() map[int]fakeProcess {
			procs := map[int]fakeProcess{1: systemd}
			for i := 10; i < 10+maxSupervisorDepth; i++ {
				procs[i] = fakeProcess{cmdline: "x\x00", comm: "x", ppid: i - 1}
			}
			procs[10] = fakeProcess{cmdline: "x\x00", comm: "x", ppid: 1}
			procs[100] = containerd(9 + maxSupervisorDepth)
			procs[200] = pluginProc(100)
			return procs
		}(), false},
		{"spoof deep under the shim", map[int]fakeProcess{
			1: systemd, 300: shim,
			301: {cmdline: "/pause\x00", comm: "pause", ppid: 300},
			302: {cmdline: "/bin/sh\x00", comm: "sh", ppid: 301},
			303: containerd(302), 304: pluginProc(303),
		}, false},
		{"plugin with args", with(kubeadmTree, map[int]fakeProcess{200: {cmdline: testPluginPath + "\x00--config\x00x\x00", comm: "x", ppid: 100}}), true},
		{"no plugin", map[int]fakeProcess{1: systemd, 100: containerd(1)}, false},
		// A container naming a process after the plugin, under the shim.
		{"spoof under the shim", map[int]fakeProcess{1: systemd, 100: containerd(1), 300: shim, 301: pluginProc(300)}, false},
		// ... or under a binary of its own called containerd, which is not a
		// child of PID 1.
		{"spoof under a fake containerd", map[int]fakeProcess{1: systemd, 300: shim, 301: containerd(300), 302: pluginProc(301)}, false},
		{"spoof under a fake rke2", map[int]fakeProcess{
			1: systemd, 300: shim,
			301: {cmdline: "rke2\x00", comm: "rke2", ppid: 300},
			302: containerd(301), 303: pluginProc(302),
		}, false},
		{"plugin orphaned to init", map[int]fakeProcess{1: systemd, 200: pluginProc(1)}, false},
		{"path as an argument", with(kubeadmTree, map[int]fakeProcess{200: {cmdline: "/usr/local/bin/c8s\x00" + testPluginPath + "\x00", comm: "c8s", ppid: 100}}), false},
		{"prefix only", with(kubeadmTree, map[int]fakeProcess{200: {cmdline: testPluginPath + "-old\x00", comm: "x", ppid: 100}}), false},
		{"argv0 without terminator", with(kubeadmTree, map[int]fakeProcess{200: {cmdline: testPluginPath, comm: "x", ppid: 100}}), false},
		// An exited process awaiting reaping reads back an empty cmdline.
		{"zombie", with(kubeadmTree, map[int]fakeProcess{200: {cmdline: "", comm: "x", ppid: 100}}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pluginRunning(fakeProc(t, tc.procs), testPluginPath)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("pluginRunning = %v, want %v", got, tc.want)
			}
		})
	}
}

// comm may hold spaces and parentheses; ppid is the second field after the
// last ')'.
func TestParentPIDParsesHostileComm(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "7")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte("7 (a) S 1 (b) S 99 7 7 0 -1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := parentPID(root, 7); !ok || got != 99 {
		t.Errorf("parentPID = %d, %v; want 99", got, ok)
	}
}

// The scan reads no more of a cmdline than the plugin path needs: any process
// sets its own, to any length.
func TestArgv0IsBoundedRead(t *testing.T) {
	long := testPluginPath + "\x00" + strings.Repeat("x", 4<<20)
	root := fakeProc(t, map[int]fakeProcess{5: {cmdline: long, comm: "x", ppid: 1}})
	if !argv0Is(root, 5, testPluginPath) {
		t.Error("argv0Is missed argv[0] ahead of a long tail")
	}
}

func TestCachedPluginScan(t *testing.T) {
	root := fakeProc(t, kubeadmTree)
	now := time.Unix(1000, 0)
	scan := cachedPluginScan(root, testPluginPath, time.Second, func() time.Time { return now })
	if ok, err := scan(); err != nil || !ok {
		t.Fatalf("first scan = %v, %v; want true", ok, err)
	}
	if err := os.RemoveAll(filepath.Join(root, "200")); err != nil {
		t.Fatal(err)
	}
	if ok, _ := scan(); !ok {
		t.Error("scan within the TTL walked /proc again")
	}
	now = now.Add(time.Second)
	if ok, _ := scan(); ok {
		t.Error("scan after the TTL kept the stale result")
	}
}

func TestPluginReadyHandler(t *testing.T) {
	for _, tc := range []struct {
		name     string
		procRoot func(t *testing.T) string
		want     int
	}{
		{"running", func(t *testing.T) string { return fakeProc(t, kubeadmTree) }, http.StatusOK},
		{"gone", func(t *testing.T) string { return fakeProc(t, map[int]fakeProcess{1: systemd}) }, http.StatusServiceUnavailable},
		{"unreadable procfs", func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			pluginReadyHandler(tc.procRoot(t), testPluginPath).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rec.Code != tc.want {
				t.Errorf("GET /readyz = %d, want %d (%s)", rec.Code, tc.want, rec.Body)
			}
		})
	}
}

// End to end: the served endpoint answers over TCP.
func TestServePluginReady(t *testing.T) {
	for _, tc := range []struct {
		name  string
		procs map[int]fakeProcess
		want  int
	}{
		{"running", rke2Tree, http.StatusOK},
		{"gone", map[int]fakeProcess{1: systemd}, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Reserve a free port, then hand it to the server.
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			l.Close()

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- servePluginReady(ctx, addr, fakeProc(t, tc.procs), testPluginPath) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Errorf("servePluginReady: %v", err)
				}
			}()

			var resp *http.Response
			for deadline := time.Now().Add(5 * time.Second); ; {
				resp, err = http.Get("http://" + addr + "/readyz")
				if err == nil || time.Now().After(deadline) {
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if err != nil {
				t.Fatalf("GET /readyz: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Errorf("GET /readyz = %d, want %d (%s)", resp.StatusCode, tc.want, body)
			}
		})
	}
}

func TestRunPluginReadyCheck(t *testing.T) {
	running := fakeProc(t, kubeadmTree)
	if err := Run([]string{pluginReadyVerb, "--check", "--plugin-path", testPluginPath, "--proc-root", running}); err != nil {
		t.Errorf("--check with the plugin running = %v, want nil", err)
	}
	gone := fakeProc(t, map[int]fakeProcess{1: systemd})
	if err := Run([]string{pluginReadyVerb, "--check", "--plugin-path", testPluginPath, "--proc-root", gone}); !errors.Is(err, errPluginNotRunning) {
		t.Errorf("--check with the plugin gone = %v, want errPluginNotRunning", err)
	}
}

// Against the real procfs: a process this test starts under the plugin's name
// is not containerd's child, so it does not count — the spoof a container could
// attempt.
func TestPluginRunningRejectsSpoofOnRealProc(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs procfs")
	}
	// Re-exec this test binary as the stand-in: multicall tools (busybox,
	// uutils coreutils) dispatch on argv[0] and exit at once under this name.
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argv0 := filepath.Join(t.TempDir(), "10-nri-image-policy")
	cmd := &exec.Cmd{Path: self, Args: []string{argv0, "-test.run=^$"}, Env: append(os.Environ(), standInEnv+"=1")}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	// Until the child's execve completes its cmdline is still the fork's.
	for deadline := time.Now().Add(5 * time.Second); !argv0Is("/proc", cmd.Process.Pid, argv0); {
		if time.Now().After(deadline) {
			t.Fatal("argv0Is did not see the stand-in's argv[0]")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got, err := pluginRunning("/proc", argv0); err != nil || got {
		t.Errorf("pluginRunning with a stand-in not launched by containerd = %v, %v; want false", got, err)
	}
}

func TestRunPluginReadyRejectsBadFlags(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"--plugin-path", "relative/10-nri-image-policy"},
		{"--plugin-path", "/opt/nri/../nri/plugins/x"},
		{"--plugin-path", testPluginPath, "--addr", "8080"},
	} {
		if err := Run(append([]string{pluginReadyVerb}, args...)); err == nil {
			t.Errorf("Run(%q) = nil, want a flag error", args)
		}
	}
}
