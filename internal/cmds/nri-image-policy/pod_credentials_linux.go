//go:build linux

package nriimagepolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var openPodCredentialRoot = openVerifiedPodCredentialRoot

// The held root survives pathname replacement. Unlike volumed's disk-volume
// placeholder, this target must cross into the kubelet's tmpfs mount.
func openVerifiedPodCredentialRoot(source string) (*os.Root, error) {
	return openPodCredentialRootBeneath(kubeletRoot, source)
}

func openPodCredentialRootBeneath(kubeletDir, source string) (*os.Root, error) {
	root, err := openPodCredentialDirectory(kubeletDir, source)
	if err != nil {
		return nil, err
	}
	if err := root.Chown(".", 0, int(workloadclaims.MeshUID)); err != nil {
		root.Close()
		return nil, err
	}
	if err := root.Chmod(".", 0750); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

// openPodCredentialDirectory proves custody without repairing ownership.
func openPodCredentialDirectory(kubeletDir, source string) (*os.Root, error) {
	relative, err := filepath.Rel(kubeletDir, source)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, "../") {
		return nil, fmt.Errorf("credential source is outside the kubelet root")
	}
	base, err := os.OpenFile(kubeletDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer base.Close()
	fd, err := unix.Openat2(int(base.Fd()), relative, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open Pod credential volume: %w", err)
	}
	defer unix.Close(fd)
	root, err := os.OpenRoot(fmt.Sprintf("/proc/self/fd/%d", fd))
	if err != nil {
		return nil, err
	}
	if err := fileutil.RequireRAMBackedRoot(root); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

func samePodCredentialRoot(held *os.Root, source string) error {
	identity, err := podRootIdentity(held)
	if err != nil {
		return err
	}
	current, err := openRetainedPodCredentialRoot(source, identity)
	if err != nil {
		return err
	}
	return current.Close()
}
