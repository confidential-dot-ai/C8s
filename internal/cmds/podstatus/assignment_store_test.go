package podstatus

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

// A directory not owned by root is never trusted, and the store cannot be
// opened over a missing or non-directory path.
func TestAssignmentStoreRefusesUnprotectedDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("ownership refusal needs an unprivileged user")
	}
	dir := t.TempDir()
	if _, err := openAssignmentStoreAt(filepath.Join(dir, "state")); err == nil || !strings.Contains(err.Error(), "not protected by root ownership") {
		t.Fatalf("user-owned assignment directory: %v", err)
	}
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openAssignmentStoreAt(filepath.Join(file, "state")); err == nil {
		t.Fatal("assignment directory created below a file")
	}
	if _, err := openAssignmentRoot(filepath.Join(dir, "absent")); !os.IsNotExist(err) {
		t.Fatalf("missing assignment directory: %v", err)
	}
}

// A store whose lock path is not a file is refused.
func TestAssignmentStoreLockMustBeAFile(t *testing.T) {
	root := assignmentTestRoot(t)
	if err := root.Mkdir("service.lock", 0o700); err != nil {
		t.Fatal(err)
	}
	if store, err := lockAssignmentStore(root); err == nil || store != nil {
		t.Fatal("directory accepted as the service lock")
	}
}

// No record loads as none; a record that is not a private regular file, not
// strict JSON, followed by data, or over the size limit is refused.
func TestAssignmentStoreLoadRefusesMalformedRecords(t *testing.T) {
	root := assignmentTestRoot(t)
	store, err := lockAssignmentStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := store.Load(); err != nil || record != nil {
		t.Fatalf("empty store loaded %v, %v", record, err)
	}
	for _, tc := range []struct {
		name string
		data []byte
		dir  bool
		want string
	}{
		{name: "directory", dir: true, want: "private regular file"},
		{name: "truncated", data: []byte(`{"version":`), want: "invalid assignment record"},
		{name: "unknown member", data: []byte(`{"version":1,"extra":true}`), want: "invalid assignment record"},
		{name: "trailing", data: []byte(`{"version":1}{}`), want: "trailing assignment record data"},
		{name: "oversized", data: bytes.Repeat([]byte(" "), podassign.MaxBody+16385), want: "exceeds size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.dir {
				err = root.Mkdir(assignmentRecordName, 0o700)
			} else {
				err = os.WriteFile(filepath.Join(root.Name(), assignmentRecordName), tc.data, 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.RemoveAll(assignmentRecordName) })
			if record, err := store.Load(); err == nil || record != nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("loaded %v, %v; want %q", record, err, tc.want)
			}
		})
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
