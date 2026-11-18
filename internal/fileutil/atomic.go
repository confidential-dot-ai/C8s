// Package fileutil holds small filesystem helpers shared across c8s commands.
package fileutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// WriteAtomic writes data to path via a same-directory temp file plus
// os.Rename. The Chmod is performed on the temp file before the rename so
// the destination never appears with the wrong permissions. The temp file
// is cleaned up on any error path.
//
// Same-directory tmpfile is required for os.Rename to be a true atomic
// replace on POSIX filesystems; a /tmp tmp would silently degrade to a
// copy+remove on cross-mount writes.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	if err := rejectTrailingSeparator("write atomically", path); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return WriteAtomicRoot(root, base, data, mode)
}

// WriteAtomicRoot writes data to a file directly beneath root via a
// same-directory temp file plus root.Rename. Keeping the directory handle
// through the rename prevents a later replacement of its pathname from
// redirecting the write.
func WriteAtomicRoot(root *os.Root, name string, data []byte, mode os.FileMode) error {
	return writeAtomicRoot(
		root,
		name,
		data,
		mode,
		nil,
	)
}

// WriteAtomicDurable syncs the temporary file before replacement, then the
// destination directory and that directory's parent, which holds its entry.
// Both must exist and be readable; directories above them are not opened.
// An error after replacement can leave the new contents visible.
func WriteAtomicDurable(path string, data []byte, mode os.FileMode) error {
	return writeAtomicDurable(
		path,
		data,
		mode,
		(*os.File).Sync,
	)
}

func writeAtomicDurable(path string, data []byte, mode os.FileMode, syncFile func(*os.File) error) error {
	if err := rejectTrailingSeparator("write durably", path); err != nil {
		return err
	}
	dir, err := physicalDir(filepath.Dir(path))
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := writeAtomicRoot(
		root,
		filepath.Base(path),
		data,
		mode,
		syncFile,
	); err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := syncAndClose(directory, syncFile); err != nil {
		return err
	}
	return syncParent(dir, syncFile)
}

// SyncDirWithParent syncs dir and its parent, as WriteAtomicDurable does
// after a write. It tells a caller whether dir can hold a durable file.
func SyncDirWithParent(dir string) error {
	return syncDirWithParent(dir, (*os.File).Sync)
}

func syncDirWithParent(dir string, syncFile func(*os.File) error) error {
	dir, err := physicalDir(dir)
	if err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := syncAndClose(directory, syncFile); err != nil {
		return err
	}
	return syncParent(dir, syncFile)
}

// physicalDir resolves symlinks, so that the parent is the directory that
// holds dir's entry.
func physicalDir(dir string) (string, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(dir)
}

func syncParent(dir string, syncFile func(*os.File) error) error {
	parent := filepath.Dir(dir)
	if parent == dir {
		return nil
	}
	directory, err := os.Open(parent)
	if err != nil {
		return err
	}
	return syncAndClose(directory, syncFile)
}

func syncAndClose(directory *os.File, syncFile func(*os.File) error) error {
	if err := errors.Join(syncFile(directory), directory.Close()); err != nil {
		return fmt.Errorf("sync directory %s: %w", directory.Name(), err)
	}
	return nil
}

func rejectTrailingSeparator(op, path string) error {
	if path != "" && os.IsPathSeparator(path[len(path)-1]) {
		return fmt.Errorf("%s: path %q ends in a path separator", op, path)
	}
	return nil
}

func writeAtomicRoot(root *os.Root, name string, data []byte, mode os.FileMode, syncFile func(*os.File) error) error {
	if root == nil {
		return fmt.Errorf("write atomically: nil directory root")
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\`) {
		return fmt.Errorf("write atomically: %q is not a file name directly beneath the directory root", name)
	}

	tmpName, err := atomicTempName(name)
	if err != nil {
		return err
	}
	tmp, err := root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = tmp.Close()
			_ = root.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if syncFile != nil {
		if err := syncFile(tmp); err != nil {
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmpName, name); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func atomicTempName(name string) (string, error) {
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate atomic-write temp name: %w", err)
	}
	return "." + name + "." + hex.EncodeToString(suffix[:]) + ".tmp", nil
}

// WriteTemp writes data to a new temp file matching pattern and returns its
// path. The caller removes the file.
func WriteTemp(pattern string, data []byte) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	_, werr := f.Write(data)
	if err := errors.Join(werr, f.Close()); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
