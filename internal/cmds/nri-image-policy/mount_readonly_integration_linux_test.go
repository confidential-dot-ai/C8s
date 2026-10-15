package nriimagepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/nri/pkg/api"
	"golang.org/x/sys/unix"
)

// TestRecursiveReadOnlyRetainedMount reproduces, in a disposable private mount
// namespace, the stale host tree an rbind leaves behind: the container's copy
// keeps a writable submount after the host unmounts its source.
//
// It pins what observeHostMount guarantees: "ro" makes only the top mount
// read-only, so the observer reports a read-only host mount even though a
// submount the rbind copied stays writable. A host rule's readOnly therefore
// covers the top mount only; a host source that may carry submounts is not
// confined by it. Under "rro" the observer withholds the source digest, so no
// host rule admits the mount, although the kernel makes the whole copy
// read-only.
func TestRecursiveReadOnlyRetainedMount(t *testing.T) {
	if os.Getenv("C8S_TEST_PRIVATE_MOUNTS") != "1" {
		t.Skip("requires a disposable private mount namespace")
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 || self == init {
		t.Fatal("must run as root in a private mount namespace")
	}
	root := t.TempDir()
	source, target := filepath.Join(root, "source"), filepath.Join(root, "target")
	for _, path := range []string{source, target} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount("tmpfs", source, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Best effort: the namespace is discarded when the test binary exits.
		_ = unix.Unmount(target, unix.MNT_DETACH)
		_ = unix.Unmount(source, unix.MNT_DETACH)
	})
	child := filepath.Join(source, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", child, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", target, "", unix.MS_PRIVATE|unix.MS_REC, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unmount(child, 0); err != nil {
		t.Fatal(err)
	}
	retained := filepath.Join(target, "child", "retained")
	if err := os.WriteFile(retained, []byte("writable"), 0o600); err != nil {
		t.Fatalf("fixture did not retain a writable child: %v", err)
	}
	plain := observeHostMount(&api.Mount{Destination: "/host", Source: source, Type: "bind", Options: []string{"rbind", "ro", "rprivate"}})
	if !plain.ReadOnly || plain.HostSourceDigest == "" {
		t.Fatalf("observeHostMount(rbind, ro) = %+v, want read-only with a source digest", plain)
	}

	if err := unix.MountSetattr(unix.AT_FDCWD, target, unix.AT_RECURSIVE, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retained, []byte("changed"), 0o600); !errors.Is(err, unix.EROFS) {
		t.Fatalf("recursive read-only child write = %v, want EROFS", err)
	}
	recursive := observeHostMount(&api.Mount{Destination: "/host", Source: source, Type: "bind", Options: []string{"rbind", "rro", "rprivate"}})
	if recursive.HostSourceDigest != "" {
		t.Fatalf("observeHostMount(rbind, rro) = %+v, want no source digest", recursive)
	}

	// A host mount made later does not propagate into the private copy.
	later := filepath.Join(source, "later")
	if err := os.Mkdir(later, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", later, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(later, "host-only"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "later", "host-only")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host mount reached the private copy: %v", err)
	}
	if err := unix.Unmount(later, 0); err != nil {
		t.Fatal(err)
	}
}
