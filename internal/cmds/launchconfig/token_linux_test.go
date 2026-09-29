package launchconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

func TestServerCredentialRequiresRealRAMFilesystem(t *testing.T) {
	dir, err := os.MkdirTemp("/dev/shm", "c8s-launch-token-")
	if err != nil {
		t.Skipf("tmpfs unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	path := filepath.Join(dir, "agent-token")
	if err := initializeAgentToken(path); err != nil {
		t.Fatal(err)
	}
	if err := initializeAgentToken(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("credential missing or not private")
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := fileutil.RequireRAMBackedRoot(root); err == nil {
		t.Skip("test temporary directory is also RAM-backed")
	}
	diskPath := filepath.Join(root.Name(), "agent-token")
	if err := initializeAgentToken(diskPath); err == nil {
		t.Fatal("accepted non-RAM token storage")
	}
	requireAbsent(t, diskPath)
}
