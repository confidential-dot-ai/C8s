//go:build linux

package nriimagepolicy

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

var verifiedMountRoot = "/run/c8s/verity-mounts"

// FS_IOC_MEASURE_VERITY returns the enforced Merkle/descriptor digest, not a
// conventional SHA-256 of file bytes. Unsupported kernels/algorithms fail closed.
func fsVerityDigest(file *os.File) string {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
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

func openVeritySource(source string) (*os.File, error) {
	if !cleanAbsolute(source) {
		return nil, fmt.Errorf("source is not a clean absolute path")
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, source, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), source), nil
}

func pinFSVerityFile(source string, capacity bool, accepted []string) (string, string, error) {
	file, err := openVeritySource(source)
	if err != nil {
		return "", "", nil
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	digest := fsVerityDigest(file)
	if digest == "" {
		return "", "", nil
	}
	if !slices.Contains(accepted, digest) {
		return "", "", fmt.Errorf("fs-verity digest is not pinned in workload policy")
	}
	if !capacity {
		return "", "", fmt.Errorf("verified mount limit reached")
	}
	if err := os.MkdirAll(verifiedMountRoot, 0700); err != nil {
		return "", "", err
	}
	dir, err := openVeritySource(verifiedMountRoot)
	if err != nil {
		return "", "", err
	}
	var st unix.Stat_t
	err = unix.Fstat(int(dir.Fd()), &st)
	dir.Close() //nolint:errcheck // No writes to flush.
	if err != nil || st.Uid != 0 || st.Mode&0077 != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", "", fmt.Errorf("unsafe verified mount directory")
	}
	staging, err := os.MkdirTemp(verifiedMountRoot, "file-")
	if err != nil {
		return "", "", err
	}
	target := filepath.Join(staging, "inode")
	targetFile, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0600)
	if err != nil {
		os.Remove(staging)
		return "", "", err
	}
	targetFile.Close() //nolint:errcheck // No writes to flush.
	// Mount the opened inode, never reopen the operator-controlled path.
	err = unix.Mount("/proc/self/fd/"+strconv.Itoa(int(file.Fd())), target, "", unix.MS_BIND, "")
	if err == nil {
		err = unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
	}
	if err == nil {
		err = unix.Mount("", target, "", unix.MS_PRIVATE, "")
	}
	if err != nil {
		_ = unpinFSVerityFile(target)
		return "", "", err
	}
	return target, digest, nil
}

func pinnedFSVerityFile(source, digest string) bool {
	file, err := openVeritySource(source)
	if err != nil {
		return false
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	var fs unix.Statfs_t
	return unix.Fstatfs(int(file.Fd()), &fs) == nil && fs.Flags&unix.ST_RDONLY != 0 && fsVerityDigest(file) == digest
}

func unpinFSVerityFile(path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil && err != unix.EINVAL {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Remove(filepath.Dir(path))
}
