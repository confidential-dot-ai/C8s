//go:build linux

package nriimagepolicy

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/workloadclaims"
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

// containerFileDigest measures the file that container id sees at
// destination, through the root of its process pid.
func containerFileDigest(pid uint32, id, destination string) (string, error) {
	pidfd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNotContainerInit, err)
	}
	defer unix.Close(pidfd) //nolint:errcheck // Read-only descriptor.
	root, err := containerRoot(pidfd, pid, id)
	if err != nil {
		return "", err
	}
	defer root.Close() //nolint:errcheck // O_PATH descriptor.
	file, err := openVerityFile(root, destination)
	if err != nil {
		return "", err
	}
	defer file.Close() //nolint:errcheck // No writes to flush.
	digest := fsVerityDigest(file)
	if digest == "" {
		return "", errVerityUnavailable
	}
	return digest, nil
}

// containerRoot opens the root of process pid, which pidfd pins, once its
// cgroup names container id. The process is alive after both reads, so they
// describe it and not a later process that reused its PID.
func containerRoot(pidfd int, pid uint32, id string) (*os.File, error) {
	ids, err := workloadclaims.ContainerIDCandidatesForPID("/proc", int(pid))
	// The shallowest ID is the runtime's: a process can only nest deeper.
	if err != nil || ids[0] != id {
		return nil, fmt.Errorf("%w: cgroup names %v, %v", errNotContainerInit, ids, err)
	}
	fd, err := unix.Open("/proc/"+strconv.FormatUint(uint64(pid), 10)+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), "root")
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		root.Close() //nolint:errcheck // O_PATH descriptor.
		return nil, fmt.Errorf("%w: %w", errNotContainerInit, err)
	}
	return root, nil
}

// openVerityFile opens path beneath root, never leaving it, and only when it
// is a regular file mounted on its own, read-only, on a filesystem that
// enforces fs-verity. It resolves the path with O_PATH first, so it never
// opens a device node, a FIFO, or a file on a filesystem that would hand the
// open to a user-space server.
func openVerityFile(root *os.File, path string) (*os.File, error) {
	if !cleanAbsolute(path) {
		return nil, fmt.Errorf("destination is not a clean absolute path")
	}
	pathFD, err := unix.Openat2(int(root.Fd()), path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, err
	}
	defer unix.Close(pathFD) //nolint:errcheck // O_PATH descriptor.
	var stx unix.Statx_t
	if err := unix.Statx(pathFD, "", unix.AT_EMPTY_PATH, unix.STATX_TYPE, &stx); err != nil {
		return nil, err
	}
	if stx.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("destination is not a regular file")
	}
	if stx.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || stx.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 {
		return nil, errVerityNotBind
	}
	var st unix.Statfs_t
	if err := unix.Fstatfs(pathFD, &st); err != nil {
		return nil, err
	}
	if !enforcesFSVerity(uint32(st.Type)) {
		return nil, fmt.Errorf("%w: type %#x", errVerityFilesystem, uint32(st.Type))
	}
	if st.Flags&unix.ST_RDONLY == 0 {
		return nil, errVerityWritable
	}
	// Reopening the descriptor's magic link reaches the same inode.
	fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(pathFD), unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
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
