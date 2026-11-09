package nriimagepolicy

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

// pluginRunningVerb selects the removers' question in place of the plugin
// daemon: does containerd still run an image-policy plugin on this node.
const pluginRunningVerb = "plugin-running"

// The statuses the verb answers with, which the removers branch on: anything
// else is an unknown answer, which they count as a running plugin.
const (
	pluginNotRunningStatus = 1
	pluginUnknownStatus    = 2
)

// pluginBinarySuffix ends the name of every plugin binary an install writes.
const pluginBinarySuffix = "-nri-image-policy"

// maxArgv0 bounds the cmdline bytes read per process.
const maxArgv0 = 4096

// runPluginRunning exits 0 while containerd runs a plugin on this node.
func runPluginRunning(args []string) error {
	fs := flag.NewFlagSet("nri-image-policy "+pluginRunningVerb, flag.ContinueOnError)
	procRoot := fs.String("proc-root", "/proc", "procfs to scan; the pod must share the host PID namespace")
	if err := cmdsutil.ParseFlags(fs, args); err != nil {
		return err
	}
	running, err := anyPluginRunning(*procRoot)
	if err != nil {
		return &cmdsutil.ExitStatusError{
			Status: pluginUnknownStatus,
			Err:    fmt.Errorf("scan %s for the plugin: %w", *procRoot, err),
		}
	}
	if !running {
		return &cmdsutil.ExitStatusError{
			Status: pluginNotRunningStatus,
			Err:    fmt.Errorf("%w under containerd on this node", errPluginNotRunning),
		}
	}
	return nil
}

// anyPluginRunning reports whether containerd runs a plugin binary from any
// directory and under any prefix, deleted from disk or not.
func anyPluginRunning(procRoot string) (bool, error) {
	pids, err := processIDs(procRoot)
	if err != nil {
		return false, err
	}
	for _, pid := range pids {
		named, err := namedAsPlugin(procRoot, pid)
		if err != nil {
			return false, err
		}
		if named && launchedByContainerd(procRoot, pid) {
			return true, nil
		}
	}
	return false, nil
}

func processIDs(procRoot string) ([]int, error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

// namedAsPlugin reports whether pid's argv[0] names a plugin binary. A
// process that has exited, and a kernel thread, carry no argv and are not it;
// a cmdline that cannot be read whole leaves the answer unknown.
func namedAsPlugin(procRoot string, pid int) (bool, error) {
	f, err := os.Open(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	cmdline, err := io.ReadAll(io.LimitReader(f, maxArgv0))
	if err != nil {
		return false, err
	}
	if len(cmdline) == 0 {
		return false, nil
	}
	argv0, _, terminated := bytes.Cut(cmdline, []byte{0})
	if !terminated {
		return false, fmt.Errorf("process %d: no argv[0] within the first %d bytes of its cmdline", pid, maxArgv0)
	}
	return strings.HasSuffix(path.Base(string(argv0)), pluginBinarySuffix), nil
}
