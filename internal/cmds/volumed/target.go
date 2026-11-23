package volumed

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/volume"
)

// emptyDirSubdir is where kubelet materializes an emptyDir volume under a pod's
// directory. The mount target is built from this shape and the resolved pod
// UID, never from anything the caller sends.
const emptyDirSubdir = "volumes/kubernetes.io~empty-dir"

// KubeVolumePrefix precedes a volume's name in the Kubernetes volume the
// webhook injects, and so in the directory this mounts into. The webhook
// reserves the whole prefix; both sides must spell it the same.
const KubeVolumePrefix = volume.KubeVolumePrefix

// KubeVolumeName is the Kubernetes volume carrying the named volume.
func KubeVolumeName(name string) string { return volume.KubeVolumeName(name) }

var (
	podUIDRE     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	volumeNameRE = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
)

// Targets resolves the directory a volume must be mounted at, where kubelet
// owns the pod's emptyDir.
type Targets interface {
	Dir(podUID, volumeName string) (*os.File, error)
}

// KubeletTargets resolves under kubelet's per-pod directory on node-CVM.
type KubeletTargets struct {
	// Root is kubelet's root directory; empty means DefaultKubeletRoot.
	Root string
}

// DefaultKubeletRoot is kubelet's root directory when Root is unset.
const DefaultKubeletRoot = "/var/lib/kubelet"

// Dir opens the mount target for the pod the kernel says is calling.
//
// The placeholder is a default-medium emptyDir — a plain directory on the pod
// directory's filesystem — so resolution can additionally refuse to cross a
// mount point.
func (k KubeletTargets) Dir(podUID, volumeName string) (*os.File, error) {
	if !podUIDRE.MatchString(podUID) {
		return nil, fmt.Errorf("volumed: pod uid %q is not a uuid", podUID)
	}
	return resolveBeneath(filepath.Join(k.root(), "pods", podUID, emptyDirSubdir), volumeName, unix.RESOLVE_NO_XDEV)
}

func (k KubeletTargets) root() string {
	if k.Root != "" {
		return k.Root
	}
	return DefaultKubeletRoot
}

// resolveBeneath opens volumeName directly beneath base, with extraResolve
// added to the mandatory hardening flags.
//
// The returned file is an O_PATH handle; mount through /proc/self/fd/<n> rather
// than re-resolving the path, so nothing can be swapped between the check and
// the mount.
//
// Two properties this has to hold in both shapes, because the calling pod owns
// the contents of its own emptyDir and can write into it:
//
//   - resolution stops at the pod's emptyDir directory (RESOLVE_BENEATH), so a
//     name cannot climb out with "..";
//   - no component may be a symlink (RESOLVE_NO_SYMLINKS), so a link planted
//     inside the emptyDir cannot redirect the mount somewhere else — the pod's
//     own rootfs, or another pod's directory.
func resolveBeneath(base, volumeName string, extraResolve uint64) (*os.File, error) {
	if !volumeNameRE.MatchString(volumeName) {
		return nil, fmt.Errorf("volumed: volume name %q is not a dns-1123 label", volumeName)
	}

	baseFD, err := os.OpenFile(base, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("volumed: open pod volume dir: %w", err)
	}
	defer baseFD.Close()

	fd, err := unix.Openat2(int(baseFD.Fd()), volumeName, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | extraResolve,
	})
	if err != nil {
		return nil, fmt.Errorf("volumed: resolve mount target %s/%s: %w", base, volumeName, err)
	}
	f := os.NewFile(uintptr(fd), filepath.Join(base, volumeName))

	// O_DIRECTORY already refuses a non-directory, but the error it returns is
	// ENOTDIR with no context; say which path and why.
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("volumed: stat mount target: %w", err)
	}
	if !info.IsDir() {
		f.Close()
		return nil, fmt.Errorf("volumed: mount target %s is not a directory", f.Name())
	}
	return f, nil
}

// ProcPath is the stable reference to an open handle. Mounting through this
// rather than the resolved name is what closes the window between resolving a
// path and using it.
func ProcPath(f *os.File) string {
	return fmt.Sprintf("/proc/self/fd/%d", f.Fd())
}
