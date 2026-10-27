package getcert

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

const guestMeshGID = int(workloadclaims.MeshUID)

func requireGuestRoot(root *os.Root) error {
	if err := fileutil.RequireRAMBackedRoot(root); err != nil {
		return err
	}
	info, err := root.Stat(".")
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("guest credentials require a root-owned, non-writable volume")
	}
	return nil
}

// publishRootGeneration is the rooted form of publishGeneration. All names
// stay relative to the verified directory handle, including link replacement
// and cleanup. No pathname re-resolution can redirect private material.
func publishRootGeneration(v credentialVolume, g *generation) error {
	if err := requireGuestRoot(v.root); err != nil {
		return err
	}
	if err := v.root.Mkdir(generationsSubdir, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := v.root.Chown(generationsSubdir, 0, guestMeshGID); err != nil {
		return err
	}
	if err := v.root.Chmod(generationsSubdir, 0o750); err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	target := filepath.Join(generationsSubdir, hex.EncodeToString(random[:]))
	if err := v.root.Mkdir(target, 0o750); err != nil {
		return err
	}
	if err := v.root.Chown(target, 0, guestMeshGID); err != nil {
		return err
	}
	dir, err := v.root.OpenRoot(target)
	if err != nil {
		return err
	}
	defer dir.Close()
	for _, file := range []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{v.keyName, g.KeyPEM, 0o640}, {v.caName, g.CAPEM, 0o644}, {v.leafName, g.ChainPEM, 0o644},
	} {
		if err := fileutil.WriteAtomicRoot(dir, file.name, file.data, file.mode); err != nil {
			return err
		}
		if err := dir.Chown(file.name, 0, guestMeshGID); err != nil {
			return err
		}
	}
	previous, err := v.root.Readlink(pointerName)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp := ".current-" + hex.EncodeToString(random[:])
	if err := v.root.Symlink(target, tmp); err != nil {
		return err
	}
	defer func() { _ = v.root.Remove(tmp) }()
	if err := v.root.Rename(tmp, pointerName); err != nil {
		return err
	}
	for _, name := range v.names() {
		tmp := "." + name + "-" + hex.EncodeToString(random[:])
		if err := v.root.Link(filepath.Join(target, name), tmp); err != nil {
			return err
		}
		if err := v.root.Rename(tmp, name); err != nil {
			_ = v.root.Remove(tmp)
			return err
		}
	}
	// Retain current and the immediately previous generation for readers
	// that resolved current just before the flip.
	parent, err := v.root.Open(generationsSubdir)
	if err != nil {
		return err
	}
	entries, readErr := parent.ReadDir(-1)
	closeErr := parent.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(generationsSubdir, entry.Name())
		if path == target || path == previous {
			continue
		}
		if err := v.root.RemoveAll(path); err != nil {
			return err
		}
	}
	return nil
}

func withdrawRootGeneration(v credentialVolume) error {
	for _, name := range append(v.names(), pointerName) {
		if err := v.root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
