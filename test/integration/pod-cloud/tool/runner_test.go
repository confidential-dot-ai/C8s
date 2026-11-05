//go:build !race

package main

// Run the actual live-lane shell driver against local process doubles only.
//
// run.sh executes this test binary as its process doubles dozens of times per
// run. Under the race detector each of those starts costs seconds, so these
// tests are excluded from the race build and `make test` runs the package
// without it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var toolPath string

func TestMain(m *testing.M) {
	switch name := filepath.Base(os.Args[0]); name {
	case "docker", "go", "git", "timeout":
		os.Exit(double(name, os.Args[1:]))
	}
	dir, err := os.MkdirTemp("", "podcloud-tool-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	toolPath = filepath.Join(dir, "tool")
	build := exec.Command("go", "build", "-o", toolPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building the runner tool:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type harness struct {
	t                                        *testing.T
	root, repo, runner, schema, input, state string
	config                                   map[string]any
	env                                      []string
}

// newHarness exercises the actual v2 driver against isolated source and
// process doubles without an override of the production compatibility guard.
func newHarness(t *testing.T) *harness {
	t.Helper()
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is required for runner tests")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, root: root, repo: filepath.Join(root, "source")}
	for _, relative := range []string{"test/integration/pod-cloud/run.sh", "test/integration/cluster/lib.sh"} {
		data, err := os.ReadFile(filepath.Join("../../../..", relative))
		if err != nil {
			t.Fatal(err)
		}
		h.write(filepath.Join(h.repo, relative), string(data))
	}
	h.runner = filepath.Join(h.repo, "test/integration/pod-cloud/run.sh")
	h.schema = filepath.Join(h.repo, "internal/cmds/launchconfig/config.go")
	h.write(h.schema, "package launchconfig\nconst (\nSchemaVersion = \"c8s-launch/v2\"\n)\n")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"docker", "go", "git", "timeout"} {
		if err := os.Symlink(self, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	h.config = map[string]any{
		"source": strings.Repeat("a", 40), "image": "c8s-pod@2026.10.27-1",
		"cdsImage": "c8s-cds@2026.10.27-1", "cliSHA256": strings.Repeat("b", 64),
		"manifestDigest":    "sha256:" + strings.Repeat("c", 64),
		"diskDigest":        "sha256:" + strings.Repeat("1", 64),
		"cdsManifestDigest": "sha256:" + strings.Repeat("2", 64),
		"cdsDiskDigest":     "sha256:" + strings.Repeat("3", 64),
		"meshImage":         "example.invalid/mesh@sha256:" + strings.Repeat("d", 64),
	}
	for _, key := range []string{"tokenFile", "manifestFile", "cdsManifestFile", "cliFile", "probeFile"} {
		path := filepath.Join(root, key)
		h.write(path, "offline fixture")
		h.config[key] = path
	}
	h.input = filepath.Join(root, "input.json")
	h.writeInput()
	h.state = filepath.Join(root, "run")
	h.env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"C8S_PODCLOUD_LIVE=1",
		"PODCLOUD_DOUBLE_ROOT="+root, "PODCLOUD_DIRTY=0", "PODCLOUD_TOOL="+toolPath)
	return h
}

func (h *harness) write(path, content string) {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) read(path string) string {
	h.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatal(err)
	}
	return string(data)
}

func (h *harness) exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func (h *harness) writeInput() {
	h.t.Helper()
	data, err := json.Marshal(h.config)
	if err != nil {
		h.t.Fatal(err)
	}
	h.write(h.input, string(data))
}

func (h *harness) readJSON(path string, v any) {
	h.t.Helper()
	if err := json.Unmarshal([]byte(h.read(path)), v); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) saveJSON(path string, v any) {
	h.t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		h.t.Fatal(err)
	}
	h.write(path, string(data))
}

func (h *harness) command(mode, scenario string) *exec.Cmd {
	args := []string{h.runner, mode}
	if mode == "run" {
		args = append(args, h.input)
	}
	args = append(args, h.state)
	cmd := exec.Command("bash", args...)
	cmd.Env = append(append([]string(nil), h.env...), "PODCLOUD_SCENARIO="+scenario)
	return cmd
}

type result struct {
	code           int
	stdout, stderr string
}

func (h *harness) run(mode, scenario string) result {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := h.command(mode, scenario)
	// run.sh forks jq and the process doubles; after a kill, do not wait on
	// the pipes those children still hold.
	cmd.WaitDelay = 5 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Start()
	if err != nil {
		h.t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err = <-done:
	case <-ctx.Done():
		cmd.Process.Kill()
		<-done
		h.t.Fatalf("%s did not finish within 60s\n%s", mode, stderr.String())
	}
	r := result{stdout: stdout.String(), stderr: stderr.String()}
	if exit, ok := err.(*exec.ExitError); ok {
		r.code = exit.ExitCode()
	} else if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *harness) pass(mode, scenario string) {
	h.t.Helper()
	if r := h.run(mode, scenario); r.code != 0 {
		h.t.Fatalf("%s exited %d: %s", mode, r.code, r.stderr)
	}
}

func (h *harness) refuse(mode, scenario, message string) result {
	h.t.Helper()
	r := h.run(mode, scenario)
	if r.code == 0 {
		h.t.Fatalf("%s succeeded; expected a refusal mentioning %q", mode, message)
	}
	if !strings.Contains(r.stderr, message) {
		h.t.Fatalf("%s refusal %q does not mention %q", mode, r.stderr, message)
	}
	return r
}

func (h *harness) calls() [][]string {
	h.t.Helper()
	data, err := os.ReadFile(filepath.Join(h.root, "calls.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		h.t.Fatal(err)
	}
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var call []string
		if err := json.Unmarshal([]byte(line), &call); err != nil {
			h.t.Fatal(err)
		}
		calls = append(calls, call)
	}
	return calls
}

// toolBuilds reports whether a call built the runner tool, which every
// invocation does before taking the lock.
func toolBuild(call []string) bool {
	return len(call) >= 2 && call[0] == "go" && call[1] == "build"
}

func anyCall(calls [][]string, match func([]string) bool) bool {
	for _, call := range calls {
		if match(call) {
			return true
		}
	}
	return false
}

func prefix(words ...string) func([]string) bool {
	return func(call []string) bool {
		if len(call) < len(words) {
			return false
		}
		return strings.Join(call[:len(words)], " ") == strings.Join(words, " ")
	}
}

// liveExecution reports a docker run of the acceptance binary, as opposed to
// the shell mount probe.
func liveExecution(call []string) bool {
	return prefix("docker", "run")(call) && index(call, "/bin/sh") < 0
}

func (h *harness) ledgerExists() bool { return h.exists(filepath.Join(h.state, "ledger.json")) }

func TestCompleteReceiptUsesDisposableReadOnlyContainers(t *testing.T) {
	h := newHarness(t)
	h.pass("run", "pass")
	var runs int
	for _, call := range h.calls() {
		if !prefix("docker", "run")(call) {
			continue
		}
		runs++
		if index(call, "--rm") < 0 || index(call, "--read-only") < 0 || index(call, "--mount") < 0 || call[index(call, "--mount")+1] != "type=bind,source="+h.state+",target=/podcloud" {
			t.Fatalf("docker run is not a disposable read-only container over the private state: %v", call)
		}
		if liveExecution(call) && (index(call, "--label") < 0 || !strings.HasPrefix(call[index(call, "--label")+1], "c8s.podcloud.run=c8s-podcloud-")) {
			t.Fatalf("acceptance container carries no run label: %v", call)
		}
	}
	if runs != 2 {
		t.Fatalf("expected the mount probe and one acceptance run, got %d docker runs", runs)
	}
	var runner map[string]any
	h.readJSON(filepath.Join(h.state, "runner.json"), &runner)
	if image, _ := runner["image"].(string); !strings.Contains(image, "@sha256:") {
		t.Fatalf("runner.json does not pin the container image: %v", runner)
	}
}

func TestHistoricCleanupDoesNotRequireScenarioOrBuildProvenance(t *testing.T) {
	h := newHarness(t)
	h.refuse("run", "missing", "Missing matching complete acceptance receipt")
	var config map[string]any
	h.readJSON(filepath.Join(h.state, "config.json"), &config)
	delete(config, "scenario")
	h.saveJSON(filepath.Join(h.state, "config.json"), config)
	if err := os.Remove(filepath.Join(h.state, "acceptance-build.json")); err != nil {
		t.Fatal(err)
	}
	h.pass("cleanup", "pass")
}

func TestPartialSetupCleanupIsLocalOnly(t *testing.T) {
	h := newHarness(t)
	if r := h.run("run", "partial"); r.code == 0 {
		t.Fatal("a failed Docker setup passed")
	}
	for _, marker := range []string{"ledger.json", "acceptance.test", "runner.json", "execution-started"} {
		if h.exists(filepath.Join(h.state, marker)) {
			t.Fatalf("%s exists after a failed setup", marker)
		}
	}
	before := len(h.calls())
	h.pass("cleanup", "pass")
	if anyCall(h.calls()[before:], prefix("docker", "run")) {
		t.Fatal("partial cleanup started a container")
	}
}

func TestCleanupCannotRaceRunBeforeLedger(t *testing.T) {
	h := newHarness(t)
	cmd := h.command("run", "blocked")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	release := func() {
		h.write(filepath.Join(h.root, "release-exec"), "")
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			t.Fatalf("run did not finish after release\n%s", output.String())
		}
	}
	deadline := time.Now().Add(10 * time.Second)
	for !h.exists(filepath.Join(h.root, "exec-paused")) {
		select {
		case err := <-done:
			t.Fatalf("run exited before the simulated pre-ledger pause: %v\n%s", err, output.String())
		default:
		}
		if time.Now().After(deadline) {
			release()
			t.Fatal("run did not reach pre-ledger pause")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if h.ledgerExists() {
		release()
		t.Fatal("a ledger exists before execution")
	}
	before := len(h.calls())
	r := h.run("cleanup", "pass")
	if r.code == 0 || !strings.Contains(r.stderr, "exclusive Cloud runner lock") {
		release()
		t.Fatalf("cleanup during a run: %d %s", r.code, r.stderr)
	}
	for _, call := range h.calls()[before:] {
		if !toolBuild(call) {
			release()
			t.Fatalf("cleanup acted while the run held the lock: %v", call)
		}
	}
	release()
	if cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("run exited %d\n%s", cmd.ProcessState.ExitCode(), output.String())
	}
}

func TestOrphanedPreledgerProcessRequiresLocalStopProof(t *testing.T) {
	h := newHarness(t)
	if r := h.run("run", "orphan"); r.code == 0 {
		t.Fatal("an orphaned run passed")
	}
	if !h.exists(filepath.Join(h.state, "execution-started")) || h.ledgerExists() {
		t.Fatal("unexpected markers after an orphaned run")
	}
	before := len(h.calls())
	if r := h.run("cleanup", "orphan-busy"); r.code == 0 || !strings.Contains(r.stderr, "still present") {
		t.Fatalf("cleanup proceeded beside the orphan's container: %d %s", r.code, r.stderr)
	}
	if anyCall(h.calls()[before:], prefix("docker", "run")) {
		t.Fatal("cleanup started a container beside the orphan")
	}
	if r := h.run("cleanup", "orphan-locked"); r.code == 0 {
		t.Fatal("cleanup proceeded while the orphan held the state lock")
	}
	before = len(h.calls())
	h.pass("cleanup", "orphan-closed")
	var executed [][]string
	for _, call := range h.calls()[before:] {
		if liveExecution(call) {
			executed = append(executed, call)
		}
	}
	if len(executed) != 1 || index(executed[0], "^TestPodCloudLocalCleanup$") < 0 {
		t.Fatalf("cleanup executed %v", executed)
	}
}
