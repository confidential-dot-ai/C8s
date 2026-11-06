package nriimagepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

// ExecGrantDir holds one file per started container the measured base grants
// execs (allowlist.Container.Execs), named by container ID and listing those
// commands. Only this plugin writes it; the runtime wrapper reads it to learn
// what admission matched, which the bundle cannot tell it: the bundle carries
// the image name, not the digest admitted (internal/cmds/c8srunc).
//
// INVARIANT: not under workload_claims.socket_dir, which pods mount.
const ExecGrantDir = "/run/nri-image-policy-exec"

// execGrant is one record's content.
type execGrant struct {
	Execs [][]string `json:"execs"`
}

// execGrants writes and removes those records.
type execGrants struct {
	dir string
}

// grantsExecs reports whether a base allowlist grants any container execs,
// which is when the plugin keeps records at all.
func grantsExecs(base *allowlist.Allowlist) bool {
	if base == nil {
		return false
	}
	for _, workload := range base.Workloads {
		if slices.ContainsFunc(slices.Concat(workload.InitContainers, workload.Containers), func(c allowlist.Container) bool {
			return len(c.Execs) > 0
		}) {
			return true
		}
	}
	return false
}

// note records the execs granted to a started container and removes any
// stale record when it holds none, so a record exists exactly while admission
// last granted that container execs.
func (g *execGrants) note(containerID string, execs [][]string) error {
	if g == nil {
		return nil
	}
	if len(execs) == 0 {
		g.remove(containerID)
		return nil
	}
	if !validContainerID(containerID) {
		return fmt.Errorf("container id %q is not a runtime container id", containerID)
	}
	data, err := json.Marshal(execGrant{Execs: execs})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.dir, 0o700); err != nil {
		return err
	}
	return fileutil.WriteAtomic(filepath.Join(g.dir, containerID), data, 0o600)
}

func (g *execGrants) remove(containerID string) {
	if g == nil || !validContainerID(containerID) {
		return
	}
	_ = os.Remove(filepath.Join(g.dir, containerID))
}

// ReadExecGrant returns the commands admission granted a container, or an
// error when there is no grant or the record is not one this plugin wrote: a
// regular file in a directory, both owned by the reader (root on a node) and
// writable by nobody else.
func ReadExecGrant(dir, containerID string) ([][]string, error) {
	if !validContainerID(containerID) {
		return nil, fmt.Errorf("container id %q is not a runtime container id", containerID)
	}
	if err := requireOwnerOnly(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, containerID)
	if err := requireOwnerOnly(path, false); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var grant execGrant
	if err := json.Unmarshal(data, &grant); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(grant.Execs) == 0 || slices.ContainsFunc(grant.Execs, func(argv []string) bool { return len(argv) == 0 }) {
		return nil, errors.New(path + " grants no command")
	}
	return grant.Execs, nil
}

// requireOwnerOnly refuses a path that is a symlink, of the wrong kind, not
// owned by this process's user, or writable by group or others.
func requireOwnerOnly(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	switch {
	case dir && !info.IsDir():
		return fmt.Errorf("%s is not a directory", path)
	case !dir && !info.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by group or others", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("%s is not owned by uid %d", path, os.Geteuid())
	}
	return nil
}

// validContainerID accepts the 64 lowercase hex digits containerd's CRI
// generates, so an id can never name a path outside the record directory.
func validContainerID(id string) bool {
	return len(id) == 64 && strings.Trim(id, "0123456789abcdef") == ""
}
