//go:build linux

package nriimagepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/pkg/workloadclaims"
)

var podProcessBirth = readPodProcessBirth
var podProcessIdentity = readPodProcessIdentity

// A process number alone is reusable. Pin the current process while reading
// its kernel birth time, then confirm it did not exit during the read.
func readPodProcessBirth(pid uint32) (uint64, error) {
	if pid == 0 {
		return 0, errors.New("pod process has no PID")
	}
	fd, err := unix.PidfdOpen(int(pid), 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := bytes.LastIndexByte(raw, ')')
	if end < 0 {
		return 0, errors.New("invalid Pod process stat")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) <= 19 {
		return 0, errors.New("missing Pod process birth time")
	}
	birth, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || birth == 0 {
		return 0, errors.New("invalid Pod process birth time")
	}
	polls := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(polls, 0); err != nil || n != 0 {
		return 0, errors.New("pod process exited during verification")
	}
	return birth, nil
}

func readPodProcessIdentity(pid uint32, containerID string) (uint64, error) {
	before, err := readPodProcessBirth(pid)
	if err != nil {
		return 0, err
	}
	ids, err := workloadclaims.ContainerIDCandidatesForPID("/proc", int(pid))
	if err != nil {
		return 0, err
	}
	// The first runtime container scope is authoritative; a nested cgroup
	// named after a different container cannot claim that other identity.
	if len(ids) == 0 || ids[0] != containerID {
		return 0, errors.New("pod process cgroup differs from its runtime container")
	}
	after, err := readPodProcessBirth(pid)
	if err != nil || after != before {
		return 0, errors.New("pod process changed during identity verification")
	}
	return before, nil
}

func podRootIdentity(root *os.Root) (fileID, error) {
	info, err := root.Stat(".")
	if err != nil {
		return fileID{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || stat.Uid != 0 || stat.Gid != uint32(workloadclaims.MeshUID) || info.Mode().Perm() != 0750 {
		return fileID{}, errors.New("pod credential root lost its protected ownership")
	}
	return fileID{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

func openRetainedPodCredentialRoot(source string, want fileID) (*os.Root, error) {
	root, err := openPodCredentialDirectory(kubeletRoot, source)
	if err != nil {
		return nil, err
	}
	identity, err := podRootIdentity(root)
	if err != nil || identity != want {
		root.Close()
		return nil, errors.New("retained Pod credential volume was replaced or changed permissions")
	}
	return root, nil
}
