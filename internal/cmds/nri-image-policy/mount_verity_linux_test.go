//go:build linux

package nriimagepolicy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
)

func TestEnforcesFSVerity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fsType uint32
		want   bool
	}{
		{"ext4", unix.EXT4_SUPER_MAGIC, true},
		{"f2fs", unix.F2FS_SUPER_MAGIC, true},
		{"btrfs", unix.BTRFS_SUPER_MAGIC, true},
		{"fuse", unix.FUSE_SUPER_MAGIC, false},
		{"overlayfs", unix.OVERLAYFS_SUPER_MAGIC, false},
		{"tmpfs", unix.TMPFS_MAGIC, false},
		{"nfs", unix.NFS_SUPER_MAGIC, false},
		{"erofs", unix.EROFS_SUPER_MAGIC_V1, false},
	} {
		if got := enforcesFSVerity(tc.fsType); got != tc.want {
			t.Errorf("enforcesFSVerity(%s) = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestOpenVerityFileRefusesUnsafeTargets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "binary"), []byte("operator bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(t.TempDir(), "host")
	if err := os.WriteFile(host, []byte("host bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"absolute": host, "relative": "../../../../../../" + host} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	notify, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(notify)
	if _, err := unix.InotifyAddWatch(notify, fifo, unix.IN_OPEN); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, tc := range []struct {
		path string
		want error
	}{
		{"/binary", errVerityNotBind},
		{"/absolute", fs.ErrNotExist},
		{"/relative", fs.ErrNotExist},
		{"/fifo", nil},
		{"/", nil},
		{"binary", nil},
		{"/../binary", nil},
	} {
		file, err := openVerityFile(root, tc.path)
		if err == nil {
			file.Close()
			t.Errorf("openVerityFile(%s) succeeded, want refusal", tc.path)
			continue
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Errorf("openVerityFile(%s) = %v, want %v", tc.path, err, tc.want)
		}
	}
	if n, _ := unix.Read(notify, make([]byte, 4096)); n > 0 {
		t.Fatal("opened the FIFO while checking its type")
	}
}

func TestContainerFileDigestRefusesOtherProcesses(t *testing.T) {
	exited := exec.Command("true")
	if err := exited.Run(); err != nil {
		t.Skipf("cannot run true: %v", err)
	}
	for _, tc := range []struct {
		name string
		pid  int
	}{
		{"exited process", exited.Process.Pid},
		{"process outside the container's cgroup", os.Getpid()},
	} {
		if _, err := containerFileDigest(uint32(tc.pid), randomContainerID(t), "/usr/bin/tool"); !errors.Is(err, errNotContainerInit) {
			t.Errorf("containerFileDigest(%s) = %v, want %v", tc.name, err, errNotContainerInit)
		}
	}
}

func randomContainerID(t *testing.T) string {
	t.Helper()
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(id)
}

// Run explicitly as root, in a private mount namespace, with
// C8S_TEST_FS_VERITY_DIR on a verity-enabled ext4 filesystem
// (images/node-guest/tests/mount-verity-test.sh). It starts a process in a
// container-like root, its own cgroup and a chroot holding a read-only bind of
// a verity file, and measures the file through that process.
func TestFSVerityContainerRootIntegration(t *testing.T) {
	dir := os.Getenv("C8S_TEST_FS_VERITY_DIR")
	if dir == "" {
		t.Skip("requires root, a private mount namespace and verity-enabled ext4")
	}
	source := filepath.Join(dir, "binary")
	digest := enableVerity(t, source, "approved executable")
	rootfs := filepath.Join(dir, "rootfs")
	containerLikeRoot(t, rootfs)

	bindFile(t, source, filepath.Join(rootfs, "opt/tool"), true)
	bindFile(t, source, filepath.Join(rootfs, "opt/writable"), false)
	enableVerity(t, filepath.Join(rootfs, "opt/unbound"), "image bytes")
	if err := os.Symlink(source, filepath.Join(rootfs, "opt/escape")); err != nil {
		t.Fatal(err)
	}
	shm := filepath.Join(t.TempDir(), "tmpfs")
	if err := os.Mkdir(shm, 0700); err != nil {
		t.Fatal(err)
	}
	mount(t, "tmpfs", shm, "tmpfs", 0)
	if err := os.WriteFile(filepath.Join(shm, "file"), []byte("tmpfs bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	bindFile(t, filepath.Join(shm, "file"), filepath.Join(rootfs, "opt/tmpfs"), true)

	id := randomContainerID(t)
	pid := startContained(t, rootfs, id)

	if got, err := containerFileDigest(pid, id, "/opt/tool"); err != nil || got != digest {
		t.Fatalf("containerFileDigest(/opt/tool) = %q, %v, want %s", got, err, digest)
	}
	for _, tc := range []struct {
		id, destination string
		want            error
	}{
		{id, "/opt/writable", errVerityWritable},
		{id, "/opt/unbound", errVerityNotBind},
		{id, "/opt/tmpfs", errVerityFilesystem},
		{id, "/opt/escape", fs.ErrNotExist},
		{randomContainerID(t), "/opt/tool", errNotContainerInit},
	} {
		if got, err := containerFileDigest(pid, tc.id, tc.destination); !errors.Is(err, tc.want) {
			t.Errorf("containerFileDigest(%s) = %q, %v, want %v", tc.destination, got, err, tc.want)
		}
	}

	// The production checks: validation judges the source, the start check
	// measures through the process, and the inventory carries the digest.
	for _, tc := range []struct {
		name   string
		pinned string
		want   bool
	}{
		{"pinned digest", digest, true},
		{"other digest", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := allowlist.MountRule{Destination: "/opt/tool", Kind: allowlist.MountFSVerityFile, Source: source, ReadOnly: true, VerityDigest: tc.pinned}
			al := workloadAllowlist(t, pushDigestA, pushDigestB, []string{"/bin/app"})
			al.Workloads["w"].Containers[0].Mounts = allowlist.MountPolicy{Policy: allowlist.PolicyExact, Rules: []allowlist.MountRule{rule}}
			if err := al.Normalize(); err != nil {
				t.Fatal(err)
			}
			p, _ := newCachedPlugin(&config{Policy: policyConfig{Mode: ModeFailClosed}, Allowlist: allowlistConfig{Pull: pullConfig{URL: "https://cds"}}}, al)
			p.inventory = newAdmissionInventory(t.TempDir())
			p.SetReady()
			pod := makePod("default", "pod")
			pod.Uid = "pod-uid"
			ctr := makeCtrWithImage(pod.Id, "app", "registry/repo@"+pushDigestB)
			ctr.Id = id
			ctr.Args = []string{"/bin/app"}
			ctr.Mounts = []*api.Mount{{Type: "bind", Source: source, Destination: "/opt/tool", Options: []string{"rbind", "rprivate", "ro"}}}
			if err := p.ValidateContainerAdjustment(t.Context(), &api.ValidateContainerAdjustmentRequest{Pod: pod, Container: ctr}); err != nil {
				t.Fatalf("ValidateContainerAdjustment = %v, want the source admitted", err)
			}
			ctr.Pid = pid
			err := p.StartContainer(t.Context(), pod, ctr)
			if (err == nil) != tc.want {
				t.Fatalf("StartContainer = %v, want admitted %t", err, tc.want)
			}
			if !tc.want {
				return
			}
			_, containers, ok, err := p.inventory.DigestsForSandbox(pod.Id)
			if err != nil || !ok || len(containers) != 1 {
				t.Fatalf("inventory = %v, %t, %v, want one container", containers, ok, err)
			}
			running := allowlist.RunningContainer{Digest: containers[0].Digest, Argv: containers[0].Argv, Env: containers[0].Env, Mounts: containers[0].Mounts}
			if name, _, err := al.MatchWorkload([]allowlist.RunningContainer{running}); err != nil || name != "w" {
				t.Fatalf("MatchWorkload(recorded launch) = %q, %v, want w", name, err)
			}
		})
	}
}

// enableVerity writes content to path and enables fs-verity on it.
func enableVerity(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// struct fsverity_enable_arg from the Linux UAPI.
	enable := struct {
		Version, Algorithm, BlockSize, SaltSize uint32
		SaltPtr                                 uint64
		SigSize, Reserved                       uint32
		SigPtr                                  uint64
		Reserved2                               [11]uint64
	}{Version: 1, Algorithm: 1, BlockSize: 4096}
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), unix.FS_IOC_ENABLE_VERITY, uintptr(unsafe.Pointer(&enable))); errno != 0 {
		t.Fatalf("enable fs-verity on %s: %v", path, errno)
	}
	digest := fsVerityDigest(file)
	if digest == "" {
		t.Fatalf("no fs-verity digest for %s", path)
	}
	return digest
}

// containerLikeRoot builds a root holding the node's binaries and libraries,
// as an image would.
func containerLikeRoot(t *testing.T, rootfs string) {
	t.Helper()
	for _, top := range []string{"usr", "bin", "sbin", "lib", "lib64", "lib32"} {
		host := "/" + top
		info, err := os.Lstat(host)
		if err != nil {
			continue
		}
		target := filepath.Join(rootfs, top)
		if info.Mode()&fs.ModeSymlink != 0 {
			link, err := os.Readlink(host)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(rootfs, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(link, target); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.MkdirAll(target, 0755); err != nil {
			t.Fatal(err)
		}
		mount(t, host, target, "", unix.MS_BIND|unix.MS_REC)
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "opt"), 0755); err != nil {
		t.Fatal(err)
	}
}

// bindFile binds source at target, as runc binds a file mount.
func bindFile(t *testing.T, source, target string, readOnly bool) {
	t.Helper()
	if err := os.WriteFile(target, nil, 0644); err != nil {
		t.Fatal(err)
	}
	mount(t, source, target, "", unix.MS_BIND)
	if readOnly {
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func mount(t *testing.T, source, target, fsType string, flags uintptr) {
	t.Helper()
	if err := unix.Mount(source, target, fsType, flags, ""); err != nil {
		t.Fatalf("mount %s at %s: %v", source, target, err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(target, unix.MNT_DETACH); err != nil {
			t.Errorf("unmount %s: %v", target, err)
		}
	})
}

// startContained starts a process chrooted into rootfs, in a new cgroup named
// after container id, as runc leaves a container's init before its start.
func startContained(t *testing.T, rootfs, id string) uint32 {
	t.Helper()
	cgroup := filepath.Join("/sys/fs/cgroup", id)
	if err := os.Mkdir(cgroup, 0755); err != nil {
		t.Fatalf("create a cgroup for the container: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cgroup); err != nil {
			t.Errorf("remove the container's cgroup: %v", err)
		}
	})
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command("/usr/bin/sleep", "600")
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: rootfs, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start a process in the container root: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck // The wait below reports nothing useful either.
		cmd.Wait()         //nolint:errcheck // Killed on purpose.
	})
	return uint32(cmd.Process.Pid)
}
