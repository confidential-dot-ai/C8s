package nriimagepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// grantStore is what admission does with a container's grant record.
type grantStore interface {
	note(containerID string, grants [][]string) error
	remove(containerID string)
}

var grantStores = []struct {
	name   string
	open   func(dir string) grantStore
	grants [][]string
	record string
}{
	{
		name:   "execs",
		open:   func(dir string) grantStore { return newExecGrantRecords(dir) },
		grants: [][]string{{"kubectl"}},
		record: `{"execs":[["kubectl"]]}`,
	},
	{
		name:   "capabilities",
		open:   func(dir string) grantStore { return newCapabilityGrantRecords(dir) },
		grants: [][]string{{"SYS_PTRACE"}},
		record: `{"capabilities":[["SYS_PTRACE"]]}`,
	},
}

// A record is the runtime wrapper's input: one JSON key, in a file and
// directory only their owner may open.
func TestGrantRecordIsWrittenOwnerOnly(t *testing.T) {
	for _, tc := range grantStores {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(privateDir(t), "grants")
			if err := tc.open(dir).note(grantContainerID, tc.grants); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, grantContainerID)
			requireMode(t, dir, 0o700)
			requireMode(t, path, 0o600)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != tc.record {
				t.Fatalf("record = %s, want %s", data, tc.record)
			}
		})
	}
}

// A container id that is a path names no record: noting it writes nothing
// and removing it deletes nothing.
func TestGrantRecordRefusesAPathLikeID(t *testing.T) {
	for _, tc := range grantStores {
		t.Run(tc.name, func(t *testing.T) {
			parent := privateDir(t)
			store := tc.open(filepath.Join(parent, "grants"))
			outside := filepath.Join(parent, grantContainerID)
			if err := store.note("../"+grantContainerID, tc.grants); err == nil {
				t.Fatal("noting a path-like id succeeded")
			}
			if _, err := os.Lstat(outside); !os.IsNotExist(err) {
				t.Fatalf("noting a path-like id wrote %s: %v", outside, err)
			}
			if err := os.WriteFile(outside, []byte(tc.record), 0o600); err != nil {
				t.Fatal(err)
			}
			store.remove("../" + grantContainerID)
			if _, err := os.Lstat(outside); err != nil {
				t.Fatalf("removing a path-like id deleted %s: %v", outside, err)
			}
		})
	}
}

// A node that has never recorded a capability grant grants none.
func TestReadCapabilityGrantWithoutARecordDirectory(t *testing.T) {
	granted, err := ReadCapabilityGrant(filepath.Join(t.TempDir(), "absent"), grantContainerID)
	if err != nil || granted != nil {
		t.Fatalf("ReadCapabilityGrant = %v, %v, want no grant", granted, err)
	}
}

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}
