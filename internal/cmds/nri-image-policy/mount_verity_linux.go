//go:build linux

package nriimagepolicy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// enforcesFSVerity reports whether the kernel driver for a filesystem of this
// type verifies every read against the fs-verity Merkle tree. FUSE forwards
// the verity ioctls to its server (Linux 6.10 and later), which can report any
// digest while serving any bytes; overlayfs and other stacking filesystems
// report a digest they do not enforce. Only these native drivers qualify.
func enforcesFSVerity(fsType uint32) bool {
	switch fsType {
	case unix.EXT4_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC:
		return true
	}
	return false
}

// openVerityFile opens source without following symlinks, and only when it is
// a regular file on a filesystem that enforces fs-verity. It resolves the path
// with O_PATH first, so it never opens a device node, a FIFO, or a file on a
// filesystem that would hand the open to a user-space server.
func openVerityFile(source string) (*os.File, unix.Statfs_t, error) {
	var st unix.Statfs_t
	if !cleanAbsolute(source) {
		return nil, st, fmt.Errorf("source is not a clean absolute path")
	}
	pathFD, err := unix.Openat2(unix.AT_FDCWD, source, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, st, err
	}
	defer unix.Close(pathFD) //nolint:errcheck // O_PATH descriptor.
	var stat unix.Stat_t
	if err := unix.Fstat(pathFD, &stat); err != nil {
		return nil, st, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, st, fmt.Errorf("source is not a regular file")
	}
	if err := unix.Fstatfs(pathFD, &st); err != nil {
		return nil, st, err
	}
	if !enforcesFSVerity(uint32(st.Type)) {
		return nil, st, fmt.Errorf("%w: type %#x", errVerityFilesystem, uint32(st.Type))
	}
	// Reopening the descriptor's magic link reaches the same inode.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pathFD), unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, err
	}
	return os.NewFile(uintptr(fd), source), st, nil
}

// fsVerityDigest returns FS_IOC_MEASURE_VERITY: the enforced Merkle/descriptor
// digest, not a SHA-256 of the file bytes. It returns "" when fs-verity is off
// or uses an algorithm other than SHA-256.
func fsVerityDigest(file *os.File) string {
	data := struct {
		Algorithm, Size uint16
		Digest          [64]byte
	}{Size: 64}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), unix.FS_IOC_MEASURE_VERITY, uintptr(unsafe.Pointer(&data)))
	if errno != 0 || data.Algorithm != 1 || data.Size != 32 {
		return ""
	}
	return hex.EncodeToString(data.Digest[:32])
}

// pinFSVerityFile stages source when its fs-verity digest is accepted. A
// non-empty path with an error is a staging mount it could not detach. The
// caller reserves registry capacity first.
func pinFSVerityFile(source string, accepted []string) (string, string, error) {
	file, _, err := openVerityFile(source)
	if err != nil {
		return "", "", err
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	digest := fsVerityDigest(file)
	if digest == "" {
		return "", "", errVerityUnavailable
	}
	if !slices.Contains(accepted, digest) {
		return "", "", errVerityNotPinned
	}
	if err := prepareStagingRoot(); err != nil {
		return "", "", err
	}
	path, err := bindStaging(file)
	if err != nil {
		return path, "", err
	}
	return path, digest, nil
}

// Tests replace these to inject partial mount failures.
var (
	mountSyscall   = unix.Mount
	unmountSyscall = unix.Unmount
)

// stagingRoot records which root is already a private mount point. Its lock
// serializes the first pins: each would otherwise self-bind the root, and the
// second bind would hide the first one's staging mount.
var stagingRoot struct {
	sync.Mutex
	isolated string
}

// prepareStagingRoot checks that verifiedMountRoot is a root-only directory and
// isolates it.
func prepareStagingRoot() error {
	if err := os.MkdirAll(verifiedMountRoot, 0700); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(verifiedMountRoot, &st); err != nil || st.Uid != 0 || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("unsafe verified mount directory")
	}
	return isolateStagingRoot()
}

// isolateStagingRoot makes verifiedMountRoot a private mount point once per
// process.
func isolateStagingRoot() error {
	stagingRoot.Lock()
	defer stagingRoot.Unlock()
	if stagingRoot.isolated == verifiedMountRoot {
		return nil
	}
	if err := privateMountRoot(verifiedMountRoot); err != nil {
		return fmt.Errorf("isolate verified mount directory: %w", err)
	}
	stagingRoot.isolated = verifiedMountRoot
	return nil
}

// privateMountRoot makes dir a private mount point. /run is usually shared, so
// a staging bind created under it would first propagate into every service
// namespace that is a slave of it, where a later detach never reaches.
func privateMountRoot(dir string) error {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, dir, unix.AT_SYMLINK_NOFOLLOW, 0, &stx); err != nil {
		return err
	}
	if stx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return errors.New("kernel does not report mount points")
	}
	if stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		if err := mountSyscall(dir, dir, "", unix.MS_BIND, ""); err != nil {
			return err
		}
	}
	return mountSyscall("", dir, "", unix.MS_PRIVATE, "")
}

// bindStaging bind-mounts the opened file into a new staging directory. On
// failure it returns a non-empty path only when a mount stays attached there;
// the caller must track that path until a later unpin detaches it.
func bindStaging(file *os.File) (string, error) {
	staging, err := os.MkdirTemp(verifiedMountRoot, "file-")
	if err != nil {
		return "", err
	}
	target := filepath.Join(staging, "inode")
	targetFile, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0600)
	if err != nil {
		os.Remove(staging) //nolint:errcheck // Best effort; a restart releases it.
		return "", err
	}
	targetFile.Close() //nolint:errcheck // No writes to flush.
	// Mount the opened inode, never reopen the operator-controlled path.
	if err := mountSyscall("/proc/self/fd/"+strconv.Itoa(int(file.Fd())), target, "", unix.MS_BIND, ""); err != nil {
		os.Remove(target)  //nolint:errcheck // Best effort; a restart releases it.
		os.Remove(staging) //nolint:errcheck // Best effort; a restart releases it.
		return "", err
	}
	err = mountSyscall("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
	if err == nil {
		err = mountSyscall("", target, "", unix.MS_PRIVATE, "")
	}
	if err == nil {
		return target, nil
	}
	if unpinErr := unpinFSVerityFile(target); errors.Is(unpinErr, errStillMounted) {
		return target, err
	}
	return "", err
}

// stagedDigest measures the staging mount at path. It returns "" unless the
// mount is read-only on a filesystem that enforces fs-verity.
func stagedDigest(path string) string {
	file, st, err := openVerityFile(path)
	if err != nil {
		return ""
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	if st.Flags&unix.ST_RDONLY == 0 {
		return ""
	}
	return fsVerityDigest(file)
}

// unpinFSVerityFile detaches and removes the staging at path. EINVAL and
// ENOENT mean nothing is mounted there.
func unpinFSVerityFile(path string) error {
	if err := unmountSyscall(path, unix.MNT_DETACH); err != nil && err != unix.EINVAL && err != unix.ENOENT {
		return fmt.Errorf("%w: %w", errStillMounted, err)
	}
	return removeStaging(path)
}
