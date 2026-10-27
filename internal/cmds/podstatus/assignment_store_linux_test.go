//go:build linux

package podstatus

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAssignmentStoreRequiresProtectedRAMAndSurvivesReopen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned guest filesystem test")
	}
	dir, err := os.MkdirTemp("/dev/shm", "assignment-")
	if err != nil {
		t.Skipf("RAM fixture unavailable: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "state")
	first, err := openAssignmentStoreAt(path)
	if err != nil {
		t.Fatal(err)
	}
	record := &assignmentRecord{Version: 1, Request: []byte("{}"), ServingKey: []byte("original")}
	if err := first.Commit(record); err != nil {
		t.Fatal(err)
	}
	if _, err := openAssignmentStoreAt(path); err == nil {
		t.Fatal("second process obtained assignment ownership")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := openAssignmentStoreAt(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	loaded, err := second.Load()
	if err != nil || loaded.Version != 1 {
		t.Fatalf("restart lost committed assignment: %v", err)
	}
	if err := os.Chmod(path, 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := openAssignmentStoreAt(path); err == nil {
		t.Fatal("writable assignment directory trusted")
	}
}
