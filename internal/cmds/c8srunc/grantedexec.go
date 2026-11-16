package c8srunc

// The execs a locked build lets through: the commands the measured base
// allowlist grants a container (allowlist.Container.Execs), which admission
// records per container. Why, and what it leaves: docs/node-exec-mode.md,
// "Granted execs".

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
)

// execRequest is a `runc exec` in the one form containerd's shim sends:
// --process, with only --detach and --pid-file beside it, and the container
// id last (containerd/go-runc Exec and ExecOpts).
type execRequest struct {
	processPath string
	// processAt is the index in the exec arguments of the token carrying the
	// process path.
	processAt   int
	containerID string
}

func parseExec(rest []string) (execRequest, error) {
	req := execRequest{processAt: -1}
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		if !isFlag(arg) {
			if i != len(rest)-1 {
				return req, errors.New("the exec names a command after the container id")
			}
			req.containerID = arg
			break
		}
		name, value, hasValue := splitFlag(arg)
		switch name {
		case "detach", "d":
			if hasValue {
				return req, fmt.Errorf("exec option %q carries a value", arg)
			}
		case "process", "p", "pid-file":
			at := i
			if !hasValue {
				if i+1 >= len(rest) {
					return req, fmt.Errorf("exec option %q has no value", arg)
				}
				i++
				at, value = i, rest[i]
			}
			if name != "pid-file" {
				if req.processAt >= 0 {
					return req, errors.New("the exec names its process twice")
				}
				req.processPath, req.processAt = value, at
			}
		default:
			return req, fmt.Errorf("exec option %q is not one the granted form uses", arg)
		}
	}
	switch {
	case req.containerID == "":
		return req, errors.New("the exec names no container")
	case !filepath.IsAbs(req.processPath):
		return req, errors.New("the exec names no absolute process file")
	}
	return req, nil
}

// grantedExec checks a locked-build exec and returns the arguments to hand to
// the real runtime, or why it is denied. It allows the exec only when
// admission recorded a grant for the container naming the exec's command, and
// the process is otherwise the container's own; the arguments it returns name
// a private copy of the process it checked.
func (w Wrapper) grantedExec(g globals, args []string) ([]string, error) {
	req, err := parseExec(g.rest)
	if err != nil {
		return nil, err
	}
	granted, err := nriimagepolicy.ReadExecGrant(w.ExecGrantDir, req.containerID)
	if err != nil {
		return nil, fmt.Errorf("admission granted the container no execs: %w", err)
	}
	process, err := readProcess(req.processPath)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(granted, func(argv []string) bool { return slices.Equal(argv, process.Args) }) {
		return nil, fmt.Errorf("the exec command %q is not one admission granted the container", process.Args)
	}
	container, err := containerProcess(g.root, req.containerID)
	if err != nil {
		return nil, err
	}
	if err := requireContainerProcess(container, process); err != nil {
		return nil, err
	}
	// The runtime gets what was checked: a field the decode dropped is gone.
	checked, err := json.Marshal(process)
	if err != nil {
		return nil, err
	}
	private, err := privateCopy(w.CopyDir, checked)
	if err != nil {
		return nil, err
	}
	handoff := slices.Clone(args)
	at := len(args) - len(g.rest) + req.processAt
	handoff[at] = strings.TrimSuffix(handoff[at], req.processPath) + private
	return handoff, nil
}

// maxProcessSize bounds the exec process file; containerd's are a few KB.
const maxProcessSize = 1 << 20

// readProcess reads the exec process file, which must be a regular file of at
// most maxProcessSize bytes, so a FIFO or a device cannot stall the wrapper.
func readProcess(path string) (*specs.Process, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("read the exec process: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("the exec process is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxProcessSize+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("read the exec process: %w", err)
	case len(data) > maxProcessSize:
		return nil, errors.New("the exec process file is too large")
	}
	var process specs.Process
	if err := json.Unmarshal(data, &process); err != nil {
		return nil, fmt.Errorf("parse the exec process: %w", err)
	}
	return &process, nil
}

// containerProcess reads the process the container was created with, from
// the bundle runc's own state names.
func containerProcess(root, containerID string) (*specs.Process, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("the exec names no absolute runc root")
	}
	path := filepath.Join(root, containerID, "state.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the container's runc state: %w", err)
	}
	var state struct {
		Config struct {
			Labels []string `json:"labels"`
		} `json:"config"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var bundle string
	for _, label := range state.Config.Labels {
		if value, ok := strings.CutPrefix(label, "bundle="); ok {
			bundle = value
		}
	}
	if !filepath.IsAbs(bundle) {
		return nil, fmt.Errorf("%s names no absolute bundle directory", path)
	}
	spec, err := readSpec(bundle)
	if err != nil {
		return nil, err
	}
	if spec.Process == nil {
		return nil, errors.New("the container's bundle describes no process")
	}
	return spec.Process, nil
}

// requireContainerProcess requires the exec to be what containerd builds for
// ExecSync: the container's own process with only the command replaced and no
// terminal (containerd internal/cri/server/container_execsync.go).
func requireContainerProcess(container, exec *specs.Process) error {
	want := *container
	want.Args, want.CommandLine, want.Terminal = exec.Args, "", false
	if !reflect.DeepEqual(&want, exec) {
		return errors.New("the exec process differs from the container's own beyond its command")
	}
	return nil
}

// privateCopy puts the checked process where only this process and the real
// runtime it becomes can read it: an unlinked file whose descriptor survives
// the handoff. The real runtime reads the copy, not the file the caller can
// still rewrite.
func privateCopy(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, "c8s-runc-process-*")
	if err != nil {
		return "", fmt.Errorf("copy the exec process: %w", err)
	}
	defer f.Close() //nolint:errcheck // the duplicate below is what the runtime reads
	if err := os.Remove(f.Name()); err != nil {
		return "", fmt.Errorf("unlink the exec process copy: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return "", fmt.Errorf("copy the exec process: %w", err)
	}
	// dup clears close-on-exec, so the descriptor outlives syscall.Exec.
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		return "", fmt.Errorf("keep the exec process copy open: %w", err)
	}
	return fmt.Sprintf("/proc/self/fd/%d", fd), nil
}
