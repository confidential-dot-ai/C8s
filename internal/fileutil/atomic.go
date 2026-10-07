// Package fileutil holds small filesystem helpers shared across c8s commands.
package fileutil

import (
	"crypto/rand"
	"encoding/hex"
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
	if path != "" && os.IsPathSeparator(path[len(path)-1]) {
		return fmt.Errorf("write atomically: path %q ends in a path separator", path)
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
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := root.Rename(tmpName, name); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ReplaceSymlink points path at target in one rename, so a reader following
// path resolves either the old target or the new one and never nothing.
func ReplaceSymlink(path, target string) error {
	tmpName, err := atomicTempName(filepath.Base(path))
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), tmpName)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func atomicTempName(name string) (string, error) {
	var suffix [12]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate atomic-write temp name: %w", err)
	}
	return "." + name + "." + hex.EncodeToString(suffix[:]) + ".tmp", nil
}
