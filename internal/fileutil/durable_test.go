package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestWriteAtomicDurableSyncFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires directory syncing and unprivileged symlinks")
	}
	// failAt counts syncs: 0 is the temporary file, 1 its directory, 2 the parent.
	for _, tc := range []struct {
		name      string
		failAt    int
		wantAfter string
	}{
		{name: "success", failAt: -1, wantAfter: "new"},
		{name: "file", failAt: 0, wantAfter: "old"},
		{name: "directory", failAt: 1, wantAfter: "new"},
		{name: "parent", failAt: 2, wantAfter: "new"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(base, "parent", "state")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			// The parent synced is the physical one, not the symlink's.
			alias := filepath.Join(base, "alias")
			if err := os.Symlink(dir, alias); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(alias, "record")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			synced := []string{dir, filepath.Dir(dir)}
			injected := errors.New("sync failed")
			// syncSpy checks each sync's target and the destination: atFileSync until the rename.
			syncSpy := func(failAt int, atFileSync string, calls *int) func(*os.File) error {
				return func(f *os.File) error {
					step := *calls
					*calls++
					info, err := f.Stat()
					if err != nil {
						t.Fatal(err)
					}
					want := "new"
					switch {
					case step == 0:
						want = atFileSync
						if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 3 {
							t.Fatal("file sync did not cover the complete, permissioned temporary file")
						}
					case step > len(synced):
						t.Fatal("synced beyond the destination directory's parent")
					default:
						expected, err := os.Stat(synced[step-1])
						if err != nil || !os.SameFile(info, expected) {
							t.Fatalf("sync step %d reached the wrong directory", step)
						}
					}
					got, err := os.ReadFile(path)
					if err != nil || string(got) != want {
						t.Fatalf("sync step %d: destination %q, error %v; want %q", step, got, err, want)
					}
					if step == failAt {
						return injected
					}
					return f.Sync()
				}
			}
			var calls int
			err = writeAtomicDurable(path, []byte("new"), 0o600, syncSpy(tc.failAt, "old", &calls))
			if (tc.failAt >= 0 && !errors.Is(err, injected)) || (tc.failAt < 0 && err != nil) {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != tc.wantAfter {
				t.Fatal("failed write left unexpected contents")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "record" {
				t.Fatal("temporary file was not cleaned up")
			}
			calls = 0
			if err := writeAtomicDurable(path, []byte("new"), 0o600, syncSpy(-1, tc.wantAfter, &calls)); err != nil {
				t.Fatal(err)
			}
			if calls != 3 {
				t.Fatal("retry did not sync the file, its directory and the parent")
			}
		})
	}
}

func TestWriteAtomicDurableRejectsTrailingSeparator(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAtomicDurable(dir+string(os.PathSeparator), []byte("record"), 0o600); err == nil {
		t.Fatal("accepted a trailing directory separator")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid path created a nested output")
	}
}

// Only the directory and its parent are opened: one the caller can traverse
// but not read, further up, does not fail the write.
func TestWriteAtomicDurableLeavesHigherAncestorsAlone(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires a directory the caller can traverse but not read")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(base, "ancestor")
	dir := filepath.Join(ancestor, "parent", "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(ancestor, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0o700) })
	if err := WriteAtomicDurable(filepath.Join(dir, "record"), []byte("new"), 0o600); err != nil {
		t.Fatalf("traverse-only ancestor: %v", err)
	}
	if err := SyncDirWithParent(dir); err != nil {
		t.Fatalf("traverse-only ancestor: %v", err)
	}
}

func TestSyncDirWithParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires directory syncing")
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("sync failed")
	for failAt, name := range []string{"directory", "parent"} {
		var synced []string
		err := syncDirWithParent(dir, func(f *os.File) error {
			synced = append(synced, f.Name())
			if len(synced)-1 == failAt {
				return injected
			}
			return f.Sync()
		})
		if !errors.Is(err, injected) || !slices.Equal(synced, []string{dir, base}[:failAt+1]) {
			t.Fatalf("%s sync failure: %v after syncing %v", name, err, synced)
		}
	}
	if err := SyncDirWithParent(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing directory: %v", err)
	}
}

func TestMkdirAllDurableSyncsEveryDirectoryItAddsTo(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var synced []string
	record := func(f *os.File) error {
		synced = append(synced, f.Name())
		return nil
	}
	dir := filepath.Join(base, "a", "b", "c")
	if err := mkdirAllDurable(dir, 0o700, record); err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(base, "a", "b"), filepath.Join(base, "a"), base}
	if !slices.Equal(synced, want) {
		t.Fatalf("synced %v, want %v", synced, want)
	}
	synced = nil
	if err := mkdirAllDurable(dir, 0o700, record); err != nil || synced != nil {
		t.Fatalf("existing directory: synced %v, %v", synced, err)
	}
	failed := errors.New("sync failed")
	err = mkdirAllDurable(filepath.Join(dir, "d"), 0o700, func(*os.File) error { return failed })
	if !errors.Is(err, failed) {
		t.Fatalf("sync failure: %v", err)
	}
}
