package nriimagepolicy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Run in a disposable private mount namespace on the buildbox. This recreates
// the stale-host-tree race: an rbind retains a writable child after its source
// mount disappears, whereas recursive read-only protects that retained child.
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
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount("tmpfs", source, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(target, unix.MNT_DETACH); _ = unix.Unmount(source, unix.MNT_DETACH) })
	child := filepath.Join(source, "child")
	if err := os.Mkdir(child, 0700); err != nil {
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
	// The source no longer shows the child mount, but the container copy does.
	retained := filepath.Join(target, "child", "retained")
	if err := os.WriteFile(retained, []byte("writable"), 0600); err != nil {
		t.Fatalf("race fixture did not retain writable child: %v", err)
	}
	if hostReadOnly([]string{"rbind", "ro", "rprivate"}) {
		t.Fatal("plain ro rbind reported read-only")
	}
	if err := unix.MountSetattr(unix.AT_FDCWD, target, unix.AT_RECURSIVE, &unix.MountAttr{Attr_set: unix.MOUNT_ATTR_RDONLY}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(retained, []byte("changed"), 0600); !errors.Is(err, unix.EROFS) {
		t.Fatalf("recursive read-only child write = %v, want EROFS", err)
	}
	if !hostReadOnly([]string{"rbind", "rro", "rprivate"}) {
		t.Fatal("recursive read-only private bind refused")
	}
	// A host-side mount created later cannot propagate into the private copy.
	later := filepath.Join(source, "later")
	// The source tree is still writable; the readonly attribute belongs to the copy.
	if err := os.Mkdir(later, 0700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", later, "tmpfs", 0, "size=1m"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(later, "host-only"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(target, "later", "host-only")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host mount reached private copy: %v", err)
	}
	if err := unix.Unmount(later, 0); err != nil {
		t.Fatal(err)
	}
}
