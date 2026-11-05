//go:build linux

package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

var startupPIDNamespace = sync.OnceValues(func() ([2]uint64, error) {
	device, inode, err := PIDNamespaceIdentity("/proc/self/ns/pid")
	return [2]uint64{device, inode}, err
})

var pidNamespacePins sync.Mutex

// InitializePIDNamespaceProof must run before any enforcer thread enters a namespace.
func InitializePIDNamespaceProof() error {
	_, err := startupPIDNamespace()
	return err
}

// PIDNamespaceIdentity refuses other namespace types and ordinary files.
func PIDNamespaceIdentity(path string) (uint64, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	return pidNamespaceFDIdentity(f)
}

func pidNamespaceFDIdentity(f *os.File) (uint64, uint64, error) {
	kind, err := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	if err != nil || kind != unix.CLONE_NEWPID {
		return 0, 0, fmt.Errorf("%s is not a PID namespace", f.Name())
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &stat); err != nil {
		return 0, 0, err
	}
	return uint64(stat.Dev), stat.Ino, nil
}

// ProvePIDNamespace binds a namespace to the reported sandbox and excludes the node.
func ProvePIDNamespace(
	path string,
	sandboxPID uint32,
) (uint64, uint64, error) {
	if sandboxPID == 0 {
		return 0, 0, fmt.Errorf("the runtime reports no sandbox process")
	}
	device, inode, err := PIDNamespaceIdentity(path)
	if err != nil {
		return 0, 0, err
	}
	node, err := startupPIDNamespace()
	if err != nil {
		return 0, 0, err
	}
	if device == node[0] && inode == node[1] {
		return 0, 0, fmt.Errorf("the sandbox uses the node PID namespace")
	}
	sandboxDevice, sandboxInode, err := PIDNamespaceIdentity(fmt.Sprintf("/proc/%d/ns/pid", sandboxPID))
	if err != nil {
		return 0, 0, err
	}
	if device != sandboxDevice || inode != sandboxInode {
		return 0, 0, fmt.Errorf("the PID namespace does not belong to the sandbox process")
	}
	return device, inode, nil
}

// EnsurePIDNamespace pins one namespace for the sandbox lifetime and never replaces it.
func EnsurePIDNamespace(
	dir string,
	sandboxID string,
	sandboxPID uint32,
) (string, uint64, uint64, error) {
	pidNamespacePins.Lock()
	defer pidNamespacePins.Unlock()
	path, err := pidNamespacePath(dir, sandboxID)
	if err != nil {
		return "", 0, 0, err
	}
	for _, parent := range []string{dir, filepath.Dir(path)} {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", 0, 0, err
		}
		if err := requireOwnerOnly(parent, true); err != nil {
			return "", 0, 0, err
		}
	}
	if _, err := os.Lstat(path); err == nil {
		if err := requireOwnerOnly(path, false); err != nil {
			return "", 0, 0, err
		}
		device, inode, err := ProvePIDNamespace(path, sandboxPID)
		return path, device, inode, err
	} else if !os.IsNotExist(err) {
		return "", 0, 0, err
	}
	source, err := os.Open(fmt.Sprintf("/proc/%d/ns/pid", sandboxPID))
	if err != nil {
		return "", 0, 0, err
	}
	defer source.Close()
	sourcePath := fmt.Sprintf("/proc/self/fd/%d", source.Fd())
	device, inode, err := ProvePIDNamespace(sourcePath, sandboxPID)
	if err != nil {
		return "", 0, 0, err
	}
	target, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", 0, 0, err
	}
	_ = target.Close()
	if err := unix.Mount(sourcePath, path, "", unix.MS_BIND, ""); err != nil {
		_ = os.Remove(path)
		return "", 0, 0, err
	}
	return path, device, inode, nil
}

// RemovePIDNamespace runs only after the sandbox and its containers are removed.
func RemovePIDNamespace(
	dir string,
	sandboxID string,
) error {
	pidNamespacePins.Lock()
	defer pidNamespacePins.Unlock()
	path, err := pidNamespacePath(dir, sandboxID)
	if err != nil {
		return err
	}
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil && err != unix.ENOENT && err != unix.EINVAL {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return RemovePIDNamespaceGrant(filepath.Join(dir, "groups"), sandboxID)
}
