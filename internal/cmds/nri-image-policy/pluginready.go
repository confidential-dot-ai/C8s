package nriimagepolicy

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// pluginReadyVerb selects the installer pod's readiness endpoint instead of the
// plugin daemon.
const pluginReadyVerb = "plugin-ready"

// pluginScanTTL bounds how often the endpoint walks /proc: it answers anyone on
// the pod network, not just the kubelet.
const pluginScanTTL = time.Second

// maxSupervisorDepth bounds the walk from containerd up to PID 1.
const maxSupervisorDepth = 8

var errPluginNotRunning = errors.New("plugin not running")

// runPluginReady serves GET /readyz for the installer DaemonSet's long-running
// container: 200 while the host plugin process exists (see pluginRunning). The
// plugin exits when its NRI connection drops and NRI does not respawn it, so
// without this the pod stays Ready over a node admitting without the plugin.
// With --check it scans once and exits non-zero when the plugin is not running;
// the install script uses that to decide whether containerd needs a restart.
//
// It checks the process, not the plugin's health socket. The pod sees host
// processes through hostPID, while reaching the socket would take a host mount
// that this container's argv-pinned allowlist entry does not admit. So a plugin
// that is alive but hung still reads as ready. An HTTP endpoint rather than an
// exec probe because the locked node image denies every runc exec
// (docs/node-exec-mode.md).
func runPluginReady(args []string) error {
	fs := flag.NewFlagSet("nri-image-policy "+pluginReadyVerb, flag.ContinueOnError)
	pluginPath := fs.String("plugin-path", "", "absolute path containerd launches the plugin from (its argv[0])")
	addr := fs.String("addr", ":8080", "readiness listen address (host:port)")
	check := fs.Bool("check", false, "scan once and exit non-zero if the plugin is not running, instead of serving")
	procRoot := fs.String("proc-root", "/proc", "procfs to scan; the pod must share the host PID namespace")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}
	if !path.IsAbs(*pluginPath) || path.Clean(*pluginPath) != *pluginPath {
		return fmt.Errorf("--plugin-path must be a clean absolute path, got %q", *pluginPath)
	}
	if *check {
		running, err := pluginRunning(*procRoot, *pluginPath)
		if err != nil {
			return err
		}
		if !running {
			return fmt.Errorf("%w: no process launched by containerd from %s", errPluginNotRunning, *pluginPath)
		}
		return nil
	}
	if _, _, err := net.SplitHostPort(*addr); err != nil {
		return fmt.Errorf("--addr %q must be host:port: %w", *addr, err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return servePluginReady(ctx, *addr, *procRoot, *pluginPath)
}

func servePluginReady(ctx context.Context, addr, procRoot, pluginPath string) error {
	bound, err := cmdsutil.ServeInBackground(ctx, addr, pluginReadyHandler(procRoot, pluginPath), slog.Default())
	if err != nil {
		return fmt.Errorf("--addr: %w", err)
	}
	slog.Info("plugin readiness endpoint listening", "addr", bound, "plugin_path", pluginPath)
	<-ctx.Done()
	return nil
}

func pluginReadyHandler(procRoot, pluginPath string) http.Handler {
	scan := cachedPluginScan(procRoot, pluginPath, pluginScanTTL, time.Now)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		running, err := scan()
		if err != nil {
			slog.Warn("plugin readiness scan failed", "proc_root", procRoot, "error", err)
			http.Error(w, "cannot scan processes", http.StatusServiceUnavailable)
			return
		}
		if !running {
			http.Error(w, errPluginNotRunning.Error(), http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintln(w, "ok")
	})
	return mux
}

// cachedPluginScan reuses one scan for ttl. Callers queue on the lock rather
// than each starting a walk of their own.
func cachedPluginScan(procRoot, pluginPath string, ttl time.Duration, now func() time.Time) func() (bool, error) {
	var (
		mu      sync.Mutex
		at      time.Time
		running bool
		err     error
	)
	return func() (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		if at.IsZero() || now().Sub(at) >= ttl {
			running, err = pluginRunning(procRoot, pluginPath)
			at = now()
		}
		return running, err
	}
}

// pluginRunning reports whether procRoot holds the plugin: a process whose
// argv[0] is argv0 (containerd launches a pre-registered NRI plugin by its full
// path) and whose parent is a host containerd.
//
// argv[0] alone is not enough: any container on a hostPID-visible node can
// exec a process under that name and hold the pod Ready over a dead plugin.
// The parent's comm alone is not enough either, since a container can name a
// binary containerd too. What a container cannot arrange is an ancestry that
// reaches host PID 1 without passing through its shim: every process it starts
// descends from the shim (comm containerd-shim*, set by the host), and its
// orphans are reparented to its own init or to the shim, a subreaper. So the
// walk up from containerd must reach PID 1 within maxSupervisorDepth steps and
// meet no shim. Whatever supervises containerd in between (systemd directly,
// rke2, k3s, dockerd, a wrapper) does not matter.
//
// A process that exits mid-scan is skipped, and one awaiting reaping has an
// empty cmdline, so neither counts.
func pluginRunning(procRoot, argv0 string) (bool, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if argv0Is(procRoot, pid, argv0) && launchedByContainerd(procRoot, pid) {
			return true, nil
		}
	}
	return false, nil
}

// argv0Is reads at most len(argv0)+1 bytes of the cmdline, which any process
// sets to whatever length it likes.
func argv0Is(procRoot string, pid int, argv0 string) bool {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, len(argv0)+1)
	if _, err := io.ReadFull(f, buf); err != nil {
		return false
	}
	return buf[len(argv0)] == 0 && string(buf[:len(argv0)]) == argv0
}

func launchedByContainerd(procRoot string, pid int) bool {
	parent, ok := parentPID(procRoot, pid)
	if !ok || comm(procRoot, parent) != "containerd" {
		return false
	}
	ancestor := parent
	for range maxSupervisorDepth {
		next, ok := parentPID(procRoot, ancestor)
		if !ok || next <= 0 {
			return false
		}
		if next == 1 {
			return true
		}
		if strings.HasPrefix(comm(procRoot, next), "containerd-shim") {
			return false
		}
		ancestor = next
	}
	return false
}

// parentPID reads field 4 of /proc/<pid>/stat. The comm in field 2 is
// parenthesized but may itself hold spaces and parentheses, so the fields are
// taken after the last ')'.
func parentPID(procRoot string, pid int) (int, bool) {
	stat, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return 0, false
	}
	fields := strings.Fields(string(stat[i+1:]))
	if len(fields) < 2 {
		return 0, false
	}
	ppid, err := strconv.Atoi(fields[1])
	return ppid, err == nil
}

func comm(procRoot string, pid int) string {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(string(b), "\n")
}
