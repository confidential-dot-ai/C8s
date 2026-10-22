package getvolume

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/volume"
	"github.com/confidential-dot-ai/c8s/internal/cmds/volumed"
	"github.com/confidential-dot-ai/c8s/internal/testutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const e2ePodUID = "3f4a1b2c-5d6e-7f80-9a0b-1c2d3e4f5061"

// recordingOps stands in for cryptsetup, veritysetup and mount(2).
type recordingOps struct {
	mu      sync.Mutex
	calls   []string
	mounted []string
	key     []byte
	verity  volume.Verity
	mounts  []recordedMount
}

// recordedMount is what one Mount was asked to do.
type recordedMount struct {
	fsType   string
	readOnly bool
}

func (o *recordingOps) CryptOpen(_ context.Context, device, mapper string, key []byte, readOnly bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "CryptOpen "+device+" "+mapper)
	o.key = append([]byte(nil), key...)
	return nil
}

func (o *recordingOps) CryptClose(context.Context, string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "CryptClose")
	return nil
}

func (o *recordingOps) VerityOpen(_ context.Context, _, mapper string, v volume.Verity) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "VerityOpen "+mapper)
	o.verity = v
	return nil
}

func (o *recordingOps) VerityClose(context.Context, string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "VerityClose")
	return nil
}

func (o *recordingOps) MountRO(_ context.Context, _ string, target *os.File, fsType string) error {
	return o.recordMount("MountRO", target, fsType, true)
}

func (o *recordingOps) MountRW(_ context.Context, _ string, target *os.File, fsType string) error {
	return o.recordMount("MountRW", target, fsType, false)
}

func (o *recordingOps) recordMount(op string, target *os.File, fsType string, readOnly bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, op)
	o.mounted = append(o.mounted, target.Name())
	o.mounts = append(o.mounts, recordedMount{fsType: fsType, readOnly: readOnly})
	return nil
}

func (o *recordingOps) Unmount(context.Context, string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "Unmount")
	return nil
}

// This path never sweeps: the daemon under test is already serving.
func (o *recordingOps) ListMappings(context.Context) ([]string, error) { return nil, nil }

func (o *recordingOps) Blank(context.Context, string) (bool, error)   { return false, nil }
func (o *recordingOps) HasExt4(context.Context, string) (bool, error) { return true, nil }
func (o *recordingOps) MakeExt4(context.Context, string, string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, "MakeExt4")
	return nil
}

// fixedIdentity stands in for the kernel peer-credential lookup, which needs a
// real pod cgroup. Everything downstream of it is the production path.
type fixedIdentity struct{ pod volumed.PodCgroup }

func (f fixedIdentity) Resolve(workloadclaims.Peer) (volumed.PodCgroup, error) {
	return f.pod, nil
}

type fixedDevices struct{}

func (fixedDevices) Device(name string) (string, error) {
	return "/dev/disk/by-id/virtio-" + volumed.SerialPrefix + name, nil
}

// startDaemon runs a real volumed server on a unix socket in dir, over a
// kubelet tree with the pod's emptyDir already materialised, and returns the
// ops it drove.
func startDaemon(t *testing.T, dir string) *recordingOps {
	t.Helper()
	kubeletRoot := t.TempDir()
	emptyDir := filepath.Join(kubeletRoot, "pods", e2ePodUID, "volumes/kubernetes.io~empty-dir", volumed.KubeVolumeName("weights"))
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatalf("mkdir emptyDir: %v", err)
	}

	ops := &recordingOps{}
	srv := &volumed.Server{
		Identity: fixedIdentity{pod: volumed.PodCgroup{UID: e2ePodUID, Path: "/kubepods.slice/pod"}},
		Opener:   &volumed.Opener{Ops: ops, Targets: volumed.KubeletTargets{Root: kubeletRoot}},
		Devices:  fixedDevices{},
	}

	l, err := net.Listen("unix", filepath.Join(dir, volumed.SocketName))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })
	return ops
}

// The whole delivery path in one test: the sidecar redeems a token from a real
// inventory, reads the blob from CDS, and hands it to a real volumed, which
// opens the device and mounts it into the pod's own emptyDir.
func TestSidecarOpensAVolumeEndToEnd(t *testing.T) {
	endpoint := "unix://" + testutil.StartInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusOK, value: testBlobJSON(t)}},
	})

	socketDir := t.TempDir()
	ops := startDaemon(t, socketDir)

	cfg := flowConfig(t, url)
	cfg.SocketDir = socketDir
	daemon, daemonBase := daemonClient(cfg)
	if err := openAllWith(context.Background(), cfg, http.DefaultClient, testKey(t), endpoint, daemon, daemonBase); err != nil {
		t.Fatalf("open: %v", err)
	}

	ops.mu.Lock()
	defer ops.mu.Unlock()
	want := []string{
		"CryptOpen /dev/disk/by-id/virtio-c8s-vol-weights c8s-crypt-" + e2ePodUID + "-weights",
		"VerityOpen c8s-verity-" + e2ePodUID + "-weights",
		"MountRO",
	}
	for i, w := range want {
		if i >= len(ops.calls) || ops.calls[i] != w {
			t.Fatalf("calls = %v, want %v", ops.calls, want)
		}
	}

	// The key that reached dm-crypt is the one the store held.
	stored, err := testBlob(t).DecodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if string(ops.key) != string(stored) {
		t.Error("the key handed to dm-crypt is not the one CDS released")
	}
	if ops.verity.RootHash != testBlob(t).Verity.RootHash {
		t.Error("the verity anchor did not come from the blob")
	}
	if len(ops.mounts) != 1 || ops.mounts[0].fsType != "erofs" || !ops.mounts[0].readOnly {
		t.Errorf("mount = %+v, want read-only erofs", ops.mounts)
	}

	// It landed in this pod's own emptyDir for this volume, and nowhere else.
	if len(ops.mounted) != 1 {
		t.Fatalf("mounted %v, want exactly one target", ops.mounted)
	}
	if !filepath.IsAbs(ops.mounted[0]) ||
		filepath.Base(ops.mounted[0]) != volumed.KubeVolumeName("weights") ||
		!containsDir(ops.mounted[0], e2ePodUID) {
		t.Errorf("mounted at %q, want this pod's %s emptyDir", ops.mounted[0], volumed.KubeVolumeName("weights"))
	}
}

// A restarted sidecar re-sends its request; the daemon must not open a second
// mapping for it.
func TestSidecarRepeatIsIdempotent(t *testing.T) {
	endpoint := "unix://" + testutil.StartInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {
			{status: http.StatusOK, value: testBlobJSON(t)},
			{status: http.StatusOK, value: testBlobJSON(t)},
		},
	})

	socketDir := t.TempDir()
	ops := startDaemon(t, socketDir)

	cfg := flowConfig(t, url)
	cfg.SocketDir = socketDir
	for i := range 2 {
		daemon, daemonBase := daemonClient(cfg)
		if err := openAllWith(context.Background(), cfg, http.DefaultClient, testKey(t), endpoint, daemon, daemonBase); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}

	ops.mu.Lock()
	defer ops.mu.Unlock()
	if len(ops.mounted) != 1 {
		t.Fatalf("mounted %d times, want 1", len(ops.mounted))
	}
}

// The daemon's refusal reaches the sidecar as a failure rather than being
// mistaken for success.
func TestSidecarReportsADaemonRefusal(t *testing.T) {
	endpoint := "unix://" + testutil.StartInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusOK, value: testBlobJSON(t)}},
	})

	socketDir := t.TempDir()
	startDaemon(t, socketDir)

	cfg := flowConfig(t, url)
	cfg.SocketDir = socketDir
	// A volume the pod has no emptyDir for: the daemon has nowhere to mount it.
	cfg.Volumes = []volumeRequest{{Name: "absent", Path: "/tenant-a/volumes/weights"}}
	daemon, daemonBase := daemonClient(cfg)
	if err := openAllWith(context.Background(), cfg, http.DefaultClient, testKey(t), endpoint, daemon, daemonBase); err == nil {
		t.Fatal("a refused open was reported as success")
	}
}

// A mutable blob travels the same delivery path and skips verity: the daemon
// mounts the crypt device itself, writable ext4.
func TestSidecarOpensAMutableVolumeEndToEnd(t *testing.T) {
	endpoint := "unix://" + testutil.StartInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusOK, value: testMutableBlobJSON(t)}},
	})

	socketDir := t.TempDir()
	ops := startDaemon(t, socketDir)

	cfg := flowConfig(t, url)
	cfg.SocketDir = socketDir
	daemon, daemonBase := daemonClient(cfg)
	if err := openAllWith(context.Background(), cfg, http.DefaultClient, testKey(t), endpoint, daemon, daemonBase); err != nil {
		t.Fatalf("open: %v", err)
	}

	ops.mu.Lock()
	defer ops.mu.Unlock()
	want := []string{
		"CryptOpen /dev/disk/by-id/virtio-c8s-vol-weights c8s-crypt-" + e2ePodUID + "-weights",
		"MountRW",
	}
	if len(ops.calls) != len(want) {
		t.Fatalf("calls = %v, want %v", ops.calls, want)
	}
	for i, w := range want {
		if ops.calls[i] != w {
			t.Fatalf("calls = %v, want %v", ops.calls, want)
		}
	}
	if len(ops.mounts) != 1 || ops.mounts[0].fsType != "ext4" || ops.mounts[0].readOnly {
		t.Errorf("mount = %+v, want writable ext4", ops.mounts)
	}
}

// containsDir reports whether want is one of path's components.
func containsDir(path, want string) bool {
	for path != "/" && path != "." {
		if filepath.Base(path) == want {
			return true
		}
		path = filepath.Dir(path)
	}
	return false
}

// At termination the sidecar posts a close — with the run context already gone,
// as SIGTERM leaves it — and the daemon unwinds the pod's whole stack.
func TestSidecarClosesItsVolumesAtTermination(t *testing.T) {
	endpoint := "unix://" + testutil.StartInventory(t)
	_, url := newFakeCDS(t, map[string][]reply{
		"GET /secrets/tenant-a/volumes/weights": {{status: http.StatusOK, value: testBlobJSON(t)}},
	})

	socketDir := t.TempDir()
	ops := startDaemon(t, socketDir)

	cfg := flowConfig(t, url)
	cfg.SocketDir = socketDir
	daemon, daemonBase := daemonClient(cfg)
	runCtx, cancel := context.WithCancel(context.Background())
	if err := openAllWith(runCtx, cfg, http.DefaultClient, testKey(t), endpoint, daemon, daemonBase); err != nil {
		t.Fatalf("open: %v", err)
	}
	cancel()

	closeCtx, done := context.WithTimeout(context.Background(), closeTimeout)
	defer done()
	if err := closeWith(closeCtx, daemon, daemonBase); err != nil {
		t.Fatalf("close: %v", err)
	}

	ops.mu.Lock()
	defer ops.mu.Unlock()
	got := strings.Join(ops.calls, ",")
	if !strings.HasSuffix(got, "Unmount,VerityClose,CryptClose") {
		t.Fatalf("calls = %q, want the close to unwind mount, verity, then crypt", got)
	}
}
