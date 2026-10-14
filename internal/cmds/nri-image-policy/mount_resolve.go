package nriimagepolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/nri/pkg/api"

	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// criNamespace is the containerd namespace the CRI plugin runs pods in.
const criNamespace = "k8s.io"

// maxSymlinks matches the kernel's limit on symlinks in one path walk.
const maxSymlinks = 40

// containerRootfs returns the root filesystem the runtime shim mounted for a
// created container, under the containerd state directory that holds it.
func containerRootfs(id string) (string, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/\x00") {
		return "", fmt.Errorf("container id %q is not a path component", id)
	}
	for _, root := range containerdRoots {
		rootfs := filepath.Join(root, "io.containerd.runtime.v2.task", criNamespace, id, "rootfs")
		if info, err := os.Lstat(rootfs); err == nil && info.IsDir() {
			return rootfs, nil
		}
	}
	return "", fmt.Errorf("no rootfs found for container %s", id)
}

// withholdAliasedMounts returns mounts, or nil (evidence unavailable) when a
// destination cannot be resolved inside the container's root filesystem or
// resolves into another mount, platform mounts such as /dev/shm included, that
// it does not lexically sit in. The runtime
// follows symlinks in the image and in volumes mounted earlier when it creates
// a mount, so an image alias such as /var/run -> /run hides a mount nested in
// a volume from the lexical check, and a symlink in that volume carries it
// anywhere, a denied path included.
func withholdAliasedMounts(rootfs func(string) (string, error), ctr *api.Container, mounts []allowlist.ObservedMount) []allowlist.ObservedMount {
	if len(mounts) < 2 || !slices.ContainsFunc(mounts, func(m allowlist.ObservedMount) bool { return m.Class != allowlist.MountPlatform }) {
		return mounts
	}
	root, err := rootfs(ctr.GetId())
	if err != nil {
		return nil
	}
	lexical := make([]string, len(mounts))
	resolved := make([]string, len(mounts))
	for i, m := range mounts {
		if !path.IsAbs(m.Destination) {
			return nil
		}
		lexical[i] = path.Clean(m.Destination)
		if resolved[i], err = resolveDestination(root, lexical[i]); err != nil {
			return nil
		}
	}
	for i := range mounts {
		for j := range mounts {
			if i != j && within(resolved[i], resolved[j]) && !within(lexical[i], lexical[j]) {
				return nil
			}
		}
	}
	return mounts
}

// resolveDestination resolves a clean absolute destination inside rootfs the
// way the runtime does when it creates the mount: symlinks are followed and
// kept inside rootfs, and a missing remainder is created as written. After a
// symlink, the walk may not pass through another mount: in a rootfs that
// already shows the container's volumes, that is an alias into a volume.
func resolveDestination(rootfs, destination string) (string, error) {
	pending := strings.Split(destination, "/")
	resolved, followed, links := "/", false, 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			resolved = path.Dir(resolved)
			continue
		}
		next := path.Join(resolved, name)
		host := filepath.Join(rootfs, next)
		info, err := os.Lstat(host)
		if errors.Is(err, fs.ErrNotExist) {
			return path.Join(append([]string{next}, pending...)...), nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			if links++; links > maxSymlinks {
				return "", fmt.Errorf("%s: too many symlinks", destination)
			}
			target, err := os.Readlink(host)
			if err != nil {
				return "", err
			}
			if path.IsAbs(target) {
				resolved = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
			followed = true
			continue
		}
		if followed && !lastComponent(pending) {
			crossed, err := crossesMount(filepath.Join(rootfs, resolved), host)
			if err != nil {
				return "", err
			}
			if crossed {
				return "", fmt.Errorf("%s leads through a symlink into the mount at %s", destination, next)
			}
		}
		resolved = next
	}
	return resolved, nil
}

func lastComponent(pending []string) bool {
	for _, name := range pending {
		if name != "" && name != "." {
			return false
		}
	}
	return true
}

// within reports whether clean absolute path p is dir or below it.
func within(p, dir string) bool {
	return p == dir || dir == "/" || strings.HasPrefix(p, dir+"/")
}
