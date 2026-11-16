package fileutil

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func ramBacked(dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return RequireRAMBackedRoot(root)
}

// Pins the sign of the check without using RequireRAMBackedRoot as its own
// oracle: /proc is procfs on every Linux, so an inverted check fails here
// deterministically.
func TestRequireRAMBackedRejectsProcfs(t *testing.T) {
	if err := ramBacked("/proc"); err == nil {
		t.Fatal("procfs accepted as RAM-backed")
	}
}

// Accept path against a real tmpfs mount, as volumed's tests do; skipped
// without mount privileges.
func TestRequireRAMBackedAcceptsTmpfs(t *testing.T) {
	dir := t.TempDir()
	if err := unix.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
		t.Skipf("cannot mount tmpfs here (needs CAP_SYS_ADMIN in a mount namespace): %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	if err := ramBacked(dir); err != nil {
		t.Fatalf("tmpfs refused: %v", err)
	}
}

// The pathname can change after it is opened but before the filesystem check.
// Verification must inspect the held directory, not look the name up again.
func TestRequireRAMBackedRootSurvivesPathReplacementBeforeVerification(t *testing.T) {
	base := ramBackedTempDir(t)
	out := filepath.Join(base, "out")
	if err := os.Mkdir(out, 0o750); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(out)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	moved := filepath.Join(base, "moved")
	if err := os.Rename(out, moved); err != nil {
		t.Fatalf("move opened directory: %v", err)
	}
	if err := os.Symlink("/proc", out); err != nil {
		t.Fatalf("replace opened directory with procfs symlink: %v", err)
	}

	if err := RequireRAMBackedRoot(root); err != nil {
		t.Fatalf("opened tmpfs directory refused after its pathname changed: %v", err)
	}
	if err := ramBacked(out); err == nil {
		t.Fatal("replacement procfs path accepted as RAM-backed")
	}
}

func ramBackedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/dev/shm", "c8s-rambacked-")
	if err != nil {
		t.Skipf("cannot create a temporary directory in /dev/shm: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := ramBacked(dir); err != nil {
		t.Skipf("/dev/shm is not usable tmpfs: %v", err)
	}
	return dir
}
