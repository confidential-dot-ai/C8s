package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteAtomicDurableSyncFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires directory syncing and unprivileged symlinks")
	}
	for _, failure := range []int{-1, 0, 1, 2} {
		t.Run(
			map[int]string{
				-1: "success",
				0:  "file",
				1:  "directory",
				2:  "ancestor",
			}[failure],
			func(t *testing.T) {
				base, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				dir := filepath.Join(
					base,
					"parent",
					"state",
				)
				if err := os.MkdirAll(
					dir,
					0o700,
				); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(
					base,
					"alias",
				)
				if err := os.Symlink(
					dir,
					alias,
				); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(
					alias,
					"record",
				)
				if err := os.WriteFile(
					path,
					[]byte("old"),
					0o600,
				); err != nil {
					t.Fatal(err)
				}
				var ancestors []string
				for p := dir; ; p = filepath.Dir(p) {
					ancestors = append(
						ancestors,
						p,
					)
					if filepath.Dir(p) == p {
						break
					}
				}
				injected := errors.New("sync failed")
				calls, before := 0, "old"
				syncFile := func(f *os.File) error {
					step := calls
					calls++
					want := "new"
					if step == 0 {
						want = before
						info, err := f.Stat()
						if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 3 {
							t.Fatal("file sync did not cover the complete, permissioned temporary file")
						}
					} else {
						info, err := f.Stat()
						if err != nil {
							t.Fatal(err)
						}
						if step > len(ancestors) {
							t.Fatal("unexpected extra directory sync")
						}
						expected, err := os.Stat(ancestors[step-1])
						if err != nil || !os.SameFile(
							info,
							expected,
						) {
							t.Fatal("synced the wrong directory or skipped an ancestor")
						}
					}
					got, err := os.ReadFile(path)
					if err != nil || string(got) != want {
						t.Fatalf(
							"sync step %d: destination %q, error %v; want %q",
							step,
							got,
							err,
							want,
						)
					}
					if step == failure {
						return injected
					}
					return f.Sync()
				}
				err = writeAtomicDurable(
					path,
					[]byte("new"),
					0o600,
					syncFile,
				)
				if (failure >= 0 && !errors.Is(
					err,
					injected,
				)) || (failure < 0 && err != nil) {
					t.Fatal(err)
				}
				if failure == 0 {
					before = "old"
				} else {
					before = "new"
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != before {
					t.Fatal("failed write left unexpected contents")
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 1 || entries[0].Name() != "record" {
					t.Fatal("temporary file was not cleaned up")
				}
				failure, calls = -1, 0
				if err := writeAtomicDurable(
					path,
					[]byte("new"),
					0o600,
					syncFile,
				); err != nil {
					t.Fatal(err)
				}
				if calls != len(ancestors)+1 {
					t.Fatal("retry did not sync the file and every ancestor")
				}
			},
		)
	}
}

func TestWriteAtomicDurableRejectsTrailingSeparator(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAtomicDurable(
		dir+string(os.PathSeparator),
		[]byte("record"),
		0o600,
	); err == nil {
		t.Fatal("accepted a trailing directory separator")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid path created a nested output")
	}
}
