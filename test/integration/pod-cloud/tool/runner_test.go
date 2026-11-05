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

func TestUnsupportedSourceStopsBeforeStateCredentialsOrTools(t *testing.T) {
	h := newHarness(t)
	for _, source := range []string{
		"SchemaVersion = \"c8s-launch/v1\"\n",
		"SchemaVersion = \"c8s-launch/v99\"\n",
		"SchemaVersion = \"c8s-launch/v1\"\nSchemaVersion = \"c8s-launch/v2\"\n",
		"// SchemaVersion = \"c8s-launch/v1\"\n", "",
	} {
		h.write(h.schema, source)
		h.refuse("run", "pass", "requires c8s-launch/v2 and a dedicated")
		if h.exists(h.state) || h.calls() != nil {
			t.Fatalf("%q: state or tool calls exist", source)
		}
		if locks, _ := filepath.Glob(filepath.Join(h.root, ".podcloud-lock-*")); len(locks) != 0 {
			t.Fatalf("%q: lock files %v", source, locks)
		}
	}
}

func TestV2SourceCanCleanExistingRunWithOriginalRunner(t *testing.T) {
	h := newHarness(t)
	h.refuse("run", "missing", "Missing matching complete acceptance receipt")
	original := h.read(filepath.Join(h.state, "acceptance.test"))
	before := len(h.calls())
	// A historical ledger does not have v2 artifact fields. Cleanup must
	// not rebuild or reinterpret it through the current source schema.
	var oldConfig map[string]any
	h.readJSON(filepath.Join(h.state, "config.json"), &oldConfig)
	for _, key := range []string{"cdsManifestFile", "cdsManifestDigest", "cdsDiskDigest"} {
		delete(oldConfig, key)
	}
	oldConfig["cdsImage"] = "c8s-pod-cds@2026.10.27-1"
	h.saveJSON(filepath.Join(h.state, "config.json"), oldConfig)
	h.write(h.schema, "SchemaVersion = \"c8s-launch/v99\"\n")
	h.pass("cleanup", "missing")
	if h.read(filepath.Join(h.state, "acceptance.test")) != original {
		t.Fatal("cleanup replaced the original runner")
	}
	later := h.calls()[before:]
	if anyCall(later, prefix("go", "test")) {
		t.Fatalf("cleanup rebuilt the runner: %v", later)
	}
	if !anyCall(later, liveExecution) {
		t.Fatalf("cleanup did not execute the original runner: %v", later)
	}
}

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

func TestResolvedScenariosAndAcceptanceBuildProvenance(t *testing.T) {
	h := newHarness(t)
	scenarios := []any{nil, ""}
	for name := range scenarioAssertions {
		scenarios = append(scenarios, name)
	}
	for _, scenario := range scenarios {
		for _, dirty := range []bool{false, true} {
			label, _ := scenario.(string)
			if scenario == nil {
				label = "None"
			}
			h.state = filepath.Join(h.root, fmt.Sprintf("%s%v", label, dirty))
			h.config["scenario"] = scenario
			h.writeInput()
			h.env[len(h.env)-2] = fmt.Sprintf("PODCLOUD_DIRTY=%d", map[bool]int{false: 0, true: 1}[dirty])
			h.pass("run", "pass")
			var receipt, build map[string]any
			h.readJSON(filepath.Join(h.state, "result.json"), &receipt)
			h.readJSON(filepath.Join(h.state, "acceptance-build.json"), &build)
			expected, _ := scenario.(string)
			if expected == "" {
				expected = "connected"
			}
			if receipt["scenario"] != expected || receipt["source"] != h.config["source"] {
				t.Fatalf("%v/%v: receipt %v", scenario, dirty, receipt)
			}
			runner := h.read(filepath.Join(h.state, "acceptance.test"))
			if build["source"] != acceptanceSource || build["dirty"] != dirty || build["acceptanceBinarySHA256"] != sha256Hex([]byte(runner)) || len(build) != 3 {
				t.Fatalf("%v/%v: build receipt %v", scenario, dirty, build)
			}
			if receipt["acceptanceBinarySHA256"] != build["acceptanceBinarySHA256"] {
				t.Fatalf("%v/%v: receipt binary differs from the build receipt", scenario, dirty)
			}
			assertions, _ := receipt["assertions"].(map[string]any)
			if len(assertions) != len(scenarioAssertions[expected]) {
				t.Fatalf("%v/%v: assertions %v", scenario, dirty, assertions)
			}
			for _, key := range scenarioAssertions[expected] {
				if assertions[key] != true {
					t.Fatalf("%v/%v: assertion %s = %v", scenario, dirty, key, assertions[key])
				}
			}
		}
	}
}

func TestInvalidScenarioIsRejectedBeforeBuildOrProvisioning(t *testing.T) {
	h := newHarness(t)
	for i, scenario := range []any{"typo", "CONNECTED", " connected", "verification-timeout", false, true, 1, []any{}, map[string]any{}} {
		h.state = filepath.Join(h.root, fmt.Sprint(i))
		h.config["scenario"] = scenario
		h.writeInput()
		h.refuse("run", "pass", "scenario must be connected, warm-assignment, cds-outage, cds-renewal-outage or cds-decree")
		for _, call := range h.calls() {
			if !toolBuild(call) {
				t.Fatalf("%v: tool call before the scenario check: %v", scenario, call)
			}
		}
		if h.exists(filepath.Join(h.state, "execution-started")) {
			t.Fatalf("%v: execution started", scenario)
		}
	}
}

func TestScenarioAssertionsAndBinaryProvenanceMustMatch(t *testing.T) {
	h := newHarness(t)
	refusals := []string{"wrong-scenario", "missing-scenario", "wrong-assertions", "missing-proof",
		"false-proof", "extra-proof", "wrong-binary", "missing-binary",
		"changed-binary", "wrong-build", "wrong-cds-manifest", "wrong-cds-disk",
		"wrong-cds-config", "wrong-launch-format"}
	// Every refusal is exercised once, against the connected scenario; the
	// other scenarios check only the two refusals whose data differs per
	// scenario. Each run forks run.sh and its process doubles, which is slow
	// under the race detector.
	for requested := range scenarioAssertions {
		h.config["scenario"] = requested
		h.writeInput()
		scenarios := refusals
		if requested != "connected" {
			scenarios = []string{"wrong-scenario", "wrong-assertions"}
		}
		for _, scenario := range scenarios {
			h.state = filepath.Join(h.root, requested+"-"+scenario)
			h.refuse("run", scenario, "Missing matching complete acceptance receipt")
			if !h.ledgerExists() {
				t.Fatalf("%s/%s: the ledger was discarded without acceptance", requested, scenario)
			}
		}
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

func TestMountProofRefusesEmptyOrDifferentStateBeforeExecution(t *testing.T) {
	h := newHarness(t)
	for _, scenario := range []string{"empty-mount", "wrong-mount", "wrong-runner"} {
		h.state = filepath.Join(h.root, scenario)
		h.refuse("run", scenario, "Docker cannot see the exact host state and runner")
		for _, marker := range []string{"execution-started", "ledger.json", "cloud-authority-issued.json"} {
			if h.exists(filepath.Join(h.state, marker)) {
				t.Fatalf("%s: %s exists", scenario, marker)
			}
		}
		if anyCall(h.calls(), liveExecution) {
			t.Fatalf("%s: the runner executed", scenario)
		}
		before := len(h.calls())
		h.pass("cleanup", scenario)
		if anyCall(h.calls()[before:], prefix("docker", "run")) {
			t.Fatalf("%s: cleanup started a container", scenario)
		}
	}
}

func TestMissingOrIncompleteAcceptanceNeverPasses(t *testing.T) {
	h := newHarness(t)
	for _, scenario := range []string{"missing", "stale", "cleanup-only", "wrong-source"} {
		h.state = filepath.Join(h.root, scenario)
		h.refuse("run", scenario, "Missing matching complete acceptance receipt")
		if !h.ledgerExists() {
			t.Fatalf("%s: the ledger was discarded without acceptance", scenario)
		}
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
