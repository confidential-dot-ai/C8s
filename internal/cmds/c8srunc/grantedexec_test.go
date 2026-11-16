package c8srunc

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const grantContainerID = "4a2dbd89094511041afa94178b0fdcc06e40ab3b44c014a89d84ce9c13367c27"

// grantedProbes are the commands admission granted the container in these tests.
var grantedProbes = [][]string{
	{"kubectl", "get", "--raw=/livez"},
	{"kubectl", "get", "--raw=/readyz"},
}

// grantNode is a node where admission recorded a grant of grantedProbes for
// the container, whose runc state names a bundle created with apiserverProcess.
type grantNode struct {
	grants, root string
}

func apiserverProcess() *specs.Process {
	return &specs.Process{
		Args: []string{"kube-apiserver", "--secure-port=6443"},
		Env:  []string{"PATH=/usr/local/bin:/usr/bin"},
		Cwd:  "/",
		Capabilities: &specs.LinuxCapabilities{
			Bounding: []string{"CAP_NET_BIND_SERVICE"},
		},
		NoNewPrivileges: true,
	}
}

func newGrantNode(t *testing.T, granted bool) grantNode {
	t.Helper()
	n := grantNode{grants: t.TempDir(), root: t.TempDir()}
	// The record directory is the reader's alone, whatever the umask made it.
	if err := os.Chmod(n.grants, 0o700); err != nil {
		t.Fatal(err)
	}
	if granted {
		grant, err := json.Marshal(map[string]any{"execs": grantedProbes})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(n.grants, grantContainerID), grant, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bundle := bundleDirWith(t, &specs.Spec{Process: apiserverProcess()})
	state, err := json.Marshal(map[string]any{
		"id":     grantContainerID,
		"config": map[string]any{"labels": []string{"bundle=" + bundle}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(n.root, grantContainerID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(n.root, grantContainerID, "state.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	return n
}

// execProcess is what containerd builds for an ExecSync running argv.
func execProcess(argv []string) *specs.Process {
	p := apiserverProcess()
	p.Args = argv
	return p
}

func writeProcess(t *testing.T, p *specs.Process) string {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "process.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// shimExec is the argv containerd's runc shim sends for an exec.
func (n grantNode) shimExec(process string) []string {
	return []string{
		"c8s-runc", "--root", n.root, "--log", "/run/log.json", "--log-format", "json", "--systemd-cgroup",
		"exec", "--process", process, "--detach", "--pid-file", "/run/exec.pid", grantContainerID,
	}
}

func (n grantNode) run(t *testing.T, argv []string) (*recorder, int, string) {
	t.Helper()
	rec := &recorder{}
	var stderr bytes.Buffer
	w := lockedWrapper(rec, &stderr)
	w.ExecGrantDir = n.grants
	return rec, w.Run(argv), stderr.String()
}

// Each command admission granted the container reaches the real runtime,
// reading a private copy of the process that was checked.
func TestGrantedExecReachesTheRuntime(t *testing.T) {
	for _, argv := range grantedProbes {
		t.Run(argv[len(argv)-1], func(t *testing.T) {
			n := newGrantNode(t, true)
			process := writeProcess(t, execProcess(argv))
			argvIn := n.shimExec(process)
			rec, _, stderr := n.run(t, argvIn)
			if !rec.called {
				t.Fatalf("granted exec denied: %s", stderr)
			}
			at := slices.Index(argvIn, "--process") + 1
			copied := rec.argv[at]
			if copied == process || !strings.HasPrefix(copied, "/proc/self/fd/") {
				t.Fatalf("handoff process = %q, want a private descriptor in place of %q", copied, process)
			}
			for i := range argvIn[1:] {
				if i+1 != at && rec.argv[i+1] != argvIn[i+1] {
					t.Errorf("handoff argv[%d] = %q, want %q unchanged", i+1, rec.argv[i+1], argvIn[i+1])
				}
			}
			// The caller rewriting its file after the check reaches nothing.
			if err := os.WriteFile(process, []byte(`{"args":["sh"]}`), 0o600); err != nil {
				t.Fatal(err)
			}
			var got specs.Process
			if err := json.Unmarshal(readCopy(t, copied), &got); err != nil {
				t.Fatalf("parse the private copy: %v", err)
			}
			if !slices.Equal(got.Args, argv) {
				t.Errorf("private copy runs %q, want %q", got.Args, argv)
			}
		})
	}
}

// readCopy reads and closes the private copy a handoff token names.
func readCopy(t *testing.T, token string) []byte {
	t.Helper()
	fd, err := strconv.Atoi(token[strings.LastIndex(token, "/")+1:])
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "copy")
	defer f.Close()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The runtime reads the process as checked, so a member the wrapper's spec
// does not model is not handed on, and the copy replaces the path in the
// joined --process= spelling too.
func TestGrantedExecHandsOnOnlyWhatWasChecked(t *testing.T) {
	n := newGrantNode(t, true)
	data, err := json.Marshal(execProcess(grantedProbes[0]))
	if err != nil {
		t.Fatal(err)
	}
	process := filepath.Join(t.TempDir(), "process.json")
	if err := os.WriteFile(process, append(data[:len(data)-1], `,"unmodelled":true}`...), 0o600); err != nil {
		t.Fatal(err)
	}
	rec, _, stderr := n.run(t, []string{"c8s-runc", "--root", n.root, "exec", "--process=" + process, grantContainerID})
	if !rec.called {
		t.Fatalf("granted exec denied: %s", stderr)
	}
	copied, ok := strings.CutPrefix(rec.argv[4], "--process=/proc/self/fd/")
	if !ok {
		t.Fatalf("handoff process option = %q, want --process= naming a private descriptor", rec.argv[4])
	}
	if got := readCopy(t, copied); bytes.Contains(got, []byte("unmodelled")) {
		t.Fatalf("the private copy carries a member the check did not read: %s", got)
	}
}

// Everything short of that exact form stays the locked build's denial.
func TestGrantedExecDeniesEverythingElse(t *testing.T) {
	probe := grantedProbes[0]
	tests := []struct {
		name    string
		noGrant bool
		process func(*specs.Process)
		argv    func(n grantNode, process string) []string
	}{
		{name: "no grant", noGrant: true},
		{name: "another command", process: func(p *specs.Process) { p.Args = []string{"sh", "-c", "id"} }},
		{name: "granted command with an extra argument", process: func(p *specs.Process) { p.Args = append(p.Args, "-v=9") }},
		{name: "another endpoint", process: func(p *specs.Process) { p.Args[len(p.Args)-1] = "--raw=/api/v1/secrets" }},
		{name: "different user", process: func(p *specs.Process) { p.User.UID = 1000 }},
		{name: "added capability", process: func(p *specs.Process) {
			p.Capabilities.Bounding = append(p.Capabilities.Bounding, "CAP_SYS_ADMIN")
		}},
		{name: "changed environment", process: func(p *specs.Process) { p.Env = append(p.Env, "HTTPS_PROXY=http://x") }},
		{name: "other working directory", process: func(p *specs.Process) { p.Cwd = "/tmp" }},
		{name: "no_new_privs dropped", process: func(p *specs.Process) { p.NoNewPrivileges = false }},
		{name: "terminal", process: func(p *specs.Process) { p.Terminal = true }},
		{name: "command after the id", argv: func(n grantNode, process string) []string {
			return append(n.shimExec(process), "sh")
		}},
		{name: "exec option outside the granted form", argv: func(n grantNode, process string) []string {
			return []string{"c8s-runc", "--root", n.root, "exec", "--process", process, "--user", "0", grantContainerID}
		}},
		{name: "console socket", argv: func(n grantNode, process string) []string {
			return []string{"c8s-runc", "--root", n.root, "exec", "--process", process, "--console-socket", "/run/s", grantContainerID}
		}},
		{name: "process given twice", argv: func(n grantNode, process string) []string {
			return []string{"c8s-runc", "--root", n.root, "exec", "--process", process, "-p=" + process, grantContainerID}
		}},
		{name: "process file is a FIFO", argv: func(n grantNode, _ string) []string {
			fifo := filepath.Join(t.TempDir(), "process.json")
			if err := syscall.Mkfifo(fifo, 0o600); err != nil {
				t.Fatal(err)
			}
			return n.shimExec(fifo)
		}},
		{name: "grant record writable by others", argv: func(n grantNode, process string) []string {
			if err := os.Chmod(filepath.Join(n.grants, grantContainerID), 0o666); err != nil {
				t.Fatal(err)
			}
			return n.shimExec(process)
		}},
		{name: "no runc root", argv: func(_ grantNode, process string) []string {
			return []string{"c8s-runc", "exec", "--process", process, grantContainerID}
		}},
		{name: "container id naming a path", argv: func(n grantNode, process string) []string {
			return []string{"c8s-runc", "--root", n.root, "exec", "--process", process, "../" + grantContainerID}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := newGrantNode(t, !tt.noGrant)
			p := execProcess(append([]string(nil), probe...))
			if tt.process != nil {
				tt.process(p)
			}
			process := writeProcess(t, p)
			argv := n.shimExec(process)
			if tt.argv != nil {
				argv = tt.argv(n, process)
			}
			rec, code, stderr := n.run(t, argv)
			t.Log(stderr)
			if rec.called {
				t.Fatalf("Run(%q) reached the real runtime; want denial", argv)
			}
			if code != exitDenied || !strings.Contains(stderr, DenyMessage) {
				t.Errorf("Run = %d with stderr %q, want %d and %q", code, stderr, exitDenied, DenyMessage)
			}
		})
	}
}
