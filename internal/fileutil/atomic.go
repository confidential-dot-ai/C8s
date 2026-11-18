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
// destination directory. The directory must exist and already be durable:
// MkdirAllDurable creates one that is. An error after replacement can leave
// the new contents visible.
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
	root, err := os.OpenRoot(filepath.Dir(path))
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
	return syncAndClose(directory, syncFile)
}

// MkdirAllDurable creates path like os.MkdirAll and syncs the parent of each
// directory it created. Directories that already exist are taken as durable.
// A failed sync removes the created directories, so a retry syncs them again.
func MkdirAllDurable(path string, perm os.FileMode) error {
	return mkdirAllDurable(
		path,
		perm,
		(*os.File).Sync,
	)
}

func mkdirAllDurable(path string, perm os.FileMode, syncFile func(*os.File) error) error {
	var created []string
	for dir := filepath.Clean(path); ; dir = filepath.Dir(dir) {
		_, err := os.Stat(dir)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		created = append(created, dir)
	}
	if err := os.MkdirAll(path, perm); err != nil {
		return err
	}
	for _, dir := range created {
		parent, err := os.Open(filepath.Dir(dir))
		if err == nil {
			err = syncAndClose(parent, syncFile)
		}
		if err != nil {
			// Deepest first, so each is empty when its turn comes.
			for _, dir := range created {
				_ = os.Remove(dir)
			}
			return err
		}
	}
	return nil
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
