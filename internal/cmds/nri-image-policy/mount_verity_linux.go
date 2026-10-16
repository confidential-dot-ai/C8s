//go:build linux

package nriimagepolicy

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
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

// pinFSVerityFile stages source when its fs-verity digest is accepted. A
// non-empty path with an error is a staging mount it could not detach.
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
		return "", "", errVerityNotPinned
	}
	if !capacity {
		return "", "", errVerityCapacity
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
		os.Remove(staging) //nolint:errcheck // Best effort; the startup sweep retries.
		return "", err
	}
	targetFile.Close() //nolint:errcheck // No writes to flush.
	// Mount the opened inode, never reopen the operator-controlled path.
	if err := mountSyscall("/proc/self/fd/"+strconv.Itoa(int(file.Fd())), target, "", unix.MS_BIND, ""); err != nil {
		os.Remove(target)  //nolint:errcheck // Best effort; the startup sweep retries.
		os.Remove(staging) //nolint:errcheck // Best effort; the startup sweep retries.
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
	if err := unmountSyscall(path, unix.MNT_DETACH); err != nil && err != unix.EINVAL {
		return fmt.Errorf("%w: %w", errStillMounted, err)
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return os.Remove(filepath.Dir(path))
}

// sweepVerifiedMounts detaches staging left by an earlier process, whose
// registry died with it. Running containers keep their own bind of each inode.
// Call it before registering with the runtime, while the registry is empty.
func sweepVerifiedMounts(logger *slog.Logger) {
	stale, err := filepath.Glob(filepath.Join(verifiedMountRoot, "file-*"))
	if err != nil {
		logger.Warn("cannot list stale fs-verity staging", "error", err)
		return
	}
	for _, dir := range stale {
		if err := unpinFSVerity(filepath.Join(dir, "inode")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			logger.Warn("cannot remove stale fs-verity staging", "path", dir, "error", err)
		}
		// Also clears a directory a crash left before its inode file existed.
		os.Remove(dir) //nolint:errcheck // Already gone after a successful unpin.
	}
}
