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
	// failAt counts syncs: 0 is the temporary file, 1 its directory.
	for _, tc := range []struct {
		name      string
		failAt    int
		wantAfter string
	}{
		{
			name:      "success",
			failAt:    -1,
			wantAfter: "new",
		},
		{
			name:      "file",
			failAt:    0,
			wantAfter: "old",
		},
		{
			name:      "directory",
			failAt:    1,
			wantAfter: "new",
		},
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
			alias := filepath.Join(base, "alias")
			if err := os.Symlink(dir, alias); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(alias, "record")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
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
					case step > 1:
						t.Fatal("synced beyond the destination directory")
					default:
						expected, err := os.Stat(dir)
						if err != nil || !os.SameFile(info, expected) {
							t.Fatal("synced the wrong directory")
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
			if calls != 2 {
				t.Fatal("retry did not sync the file and its directory")
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

func TestWriteAtomicDurableLeavesAncestorsAlone(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires a directory the caller can traverse but not read")
	}
	parent := filepath.Join(t.TempDir(), "parent")
	dir := filepath.Join(parent, "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	if err := WriteAtomicDurable(filepath.Join(dir, "record"), []byte("new"), 0o600); err != nil {
		t.Fatalf("traverse-only ancestor: %v", err)
	}
}

func TestMkdirAllDurable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires directory syncing")
	}
	base := t.TempDir()
	existing := filepath.Join(base, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	created := filepath.Join(existing, "new")
	path := filepath.Join(created, "state")
	injected := errors.New("sync failed")
	var synced []string
	spy := func(fail bool) func(*os.File) error {
		synced = nil
		return func(f *os.File) error {
			synced = append(synced, f.Name())
			if fail {
				return injected
			}
			return f.Sync()
		}
	}
	if err := mkdirAllDurable(path, 0o700, spy(true)); !errors.Is(err, injected) {
		t.Fatalf("hid the sync failure: %v", err)
	}
	if _, err := os.Stat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a failed sync left a directory a retry would take as durable")
	}
	if err := mkdirAllDurable(path, 0o700, spy(false)); err != nil {
		t.Fatal(err)
	}
	slices.Sort(synced)
	if !slices.Equal(synced, []string{existing, created}) {
		t.Fatalf("synced %v, want the parents of the created directories", synced)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("created directory is not 0700")
	}
	if err := mkdirAllDurable(path, 0o700, spy(false)); err != nil || len(synced) != 0 {
		t.Fatalf("existing path: synced %v, error %v", synced, err)
	}
}
