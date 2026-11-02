package main

// Run the actual live-lane shell driver against local process doubles only.

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
	case "docker", "kind", "go", "git", "timeout":
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
	normalKubeconfig                         string
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
	for _, tool := range []string{"docker", "kind", "go", "git", "timeout"} {
		if err := os.Symlink(self, filepath.Join(bin, tool)); err != nil {
			t.Fatal(err)
		}
	}
	h.normalKubeconfig = filepath.Join(root, "user-kubeconfig")
	h.write(h.normalKubeconfig, "user context must stay unchanged")
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
		"C8S_PODCLOUD_LIVE=1", "KUBECONFIG="+h.normalKubeconfig,
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
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := h.command(mode, scenario)
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
		h.t.Fatalf("%s did not finish within 20s\n%s", mode, stderr.String())
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

func liveExecution(call []string) bool {
	return prefix("docker", "exec")(call) || prefix("docker", "run")(call)
}

func (h *harness) nodeExists() bool { return h.exists(filepath.Join(h.root, "node.json")) }

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
		if h.read(h.normalKubeconfig) != "user context must stay unchanged" {
			t.Fatal("the user's kubeconfig changed")
		}
	}
}

func TestV2SourceCanCleanExistingV1RunWithOriginalRunner(t *testing.T) {
	h := newHarness(t)
	h.refuse("run", "missing", "Missing matching complete acceptance receipt")
	original := h.read(filepath.Join(h.state, "provider.test"))
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
	if h.read(filepath.Join(h.state, "provider.test")) != original {
		t.Fatal("cleanup replaced the original runner")
	}
	if h.nodeExists() {
		t.Fatal("the owned cluster was not deleted")
	}
	later := h.calls()[before:]
	if anyCall(later, prefix("go", "test")) || anyCall(later, prefix("kind", "create")) {
		t.Fatalf("cleanup rebuilt or re-provisioned: %v", later)
	}
}

func TestCompleteReceiptAndPrivateKubeconfig(t *testing.T) {
	h := newHarness(t)
	h.pass("run", "pass")
	if h.nodeExists() {
		t.Fatal("the owned cluster was not deleted")
	}
	for _, call := range h.calls() {
		if prefix("kind", "create")(call) || prefix("kind", "delete")(call) {
			if call[index(call, "--kubeconfig")+1] != filepath.Join(h.state, "kubeconfig") {
				t.Fatalf("kind used a kubeconfig outside the state: %v", call)
			}
		}
		if prefix("docker", "exec")(call) && index(call, strings.Repeat("a", 64)) < 0 {
			t.Fatalf("docker exec did not address the owned node by ID: %v", call)
		}
	}
	if h.read(h.normalKubeconfig) != "user context must stay unchanged" {
		t.Fatal("the user's kubeconfig changed")
	}
}

func TestResolvedScenariosAndProviderBuildProvenance(t *testing.T) {
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
			h.readJSON(filepath.Join(h.state, "provider-build.json"), &build)
			expected, _ := scenario.(string)
			if expected == "" {
				expected = "connected"
			}
			if receipt["scenario"] != expected || receipt["source"] != h.config["source"] {
				t.Fatalf("%v/%v: receipt %v", scenario, dirty, receipt)
			}
			runner := h.read(filepath.Join(h.state, "provider.test"))
			if build["source"] != providerSource || build["dirty"] != dirty || build["providerBinarySHA256"] != sha256Hex([]byte(runner)) || len(build) != 3 {
				t.Fatalf("%v/%v: build receipt %v", scenario, dirty, build)
			}
			if receipt["providerBinarySHA256"] != build["providerBinarySHA256"] {
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
	for i, scenario := range []any{"typo", "CONNECTED", " connected", false, true, 1, []any{}, map[string]any{}} {
		h.state = filepath.Join(h.root, fmt.Sprint(i))
		h.config["scenario"] = scenario
		h.writeInput()
		h.refuse("run", "pass", "scenario must be connected, verification-timeout, warm-assignment, cds-outage, cds-renewal-outage or cds-decree")
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
	for requested := range scenarioAssertions {
		h.config["scenario"] = requested
		h.writeInput()
		for _, scenario := range []string{"wrong-scenario", "missing-scenario", "wrong-assertions", "missing-proof",
			"false-proof", "extra-proof", "wrong-binary", "missing-binary",
			"changed-binary", "wrong-build", "wrong-cds-manifest", "wrong-cds-disk",
			"wrong-cds-config", "wrong-launch-format"} {
			h.state = filepath.Join(h.root, requested+"-"+scenario)
			h.refuse("run", scenario, "Missing matching complete acceptance receipt")
			if !h.nodeExists() {
				t.Fatalf("%s/%s: the cluster was deleted without acceptance", requested, scenario)
			}
		}
	}
}

func TestHistoricCleanupDoesNotRequireScenarioOrProviderProvenance(t *testing.T) {
	h := newHarness(t)
	h.refuse("run", "missing", "Missing matching complete acceptance receipt")
	var config map[string]any
	h.readJSON(filepath.Join(h.state, "config.json"), &config)
	delete(config, "scenario")
	h.saveJSON(filepath.Join(h.state, "config.json"), config)
	if err := os.Remove(filepath.Join(h.state, "provider-build.json")); err != nil {
		t.Fatal(err)
	}
	h.pass("cleanup", "pass")
	if h.nodeExists() {
		t.Fatal("the owned cluster was not deleted")
	}
}

func TestPartialCreationCleanupIsLocalOnly(t *testing.T) {
	h := newHarness(t)
	if r := h.run("run", "partial"); r.code == 0 {
		t.Fatal("a partial creation passed")
	}
	if h.exists(filepath.Join(h.state, "ledger.json")) {
		t.Fatal("a ledger exists after partial creation")
	}
	h.pass("cleanup", "pass")
	if h.nodeExists() {
		t.Fatal("the owned cluster was not deleted")
	}
	if anyCall(h.calls(), liveExecution) {
		t.Fatal("partial cleanup executed the runner")
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
		if anyCall(h.calls(), func(call []string) bool { return prefix("docker", "exec")(call) && index(call, "/bin/sh") < 0 }) {
			t.Fatalf("%s: the runner executed", scenario)
		}
		before := len(h.calls())
		h.pass("cleanup", scenario)
		if h.nodeExists() {
			t.Fatalf("%s: the owned cluster was not deleted", scenario)
		}
		if anyCall(h.calls()[before:], liveExecution) {
			t.Fatalf("%s: cleanup executed the runner", scenario)
		}
	}
}

func TestMissingOrIncompleteAcceptanceNeverPasses(t *testing.T) {
	h := newHarness(t)
	for _, scenario := range []string{"missing", "stale", "cleanup-only", "wrong-source"} {
		h.state = filepath.Join(h.root, scenario)
		h.refuse("run", scenario, "Missing matching complete acceptance receipt")
		if !h.nodeExists() {
			t.Fatalf("%s: the cluster was deleted without acceptance", scenario)
		}
	}
}

func TestReplacementContainerOrMountRefusesExecAndDelete(t *testing.T) {
	h := newHarness(t)
	for _, field := range []string{"id", "mount"} {
		h.state = filepath.Join(h.root, field)
		h.refuse("run", "missing", "Missing matching complete acceptance receipt")
		path := filepath.Join(h.root, "node.json")
		var node []map[string]any
		h.readJSON(path, &node)
		if field == "id" {
			node[0]["Id"] = strings.Repeat("e", 64)
		} else {
			node[0]["Mounts"].([]any)[0].(map[string]any)["Source"] = filepath.Join(h.root, "foreign")
		}
		h.saveJSON(path, node)
		before := len(h.calls())
		if r := h.run("cleanup", "pass"); r.code == 0 {
			t.Fatalf("%s: cleanup adopted a replacement container", field)
		}
		later := h.calls()[before:]
		if anyCall(later, liveExecution) || anyCall(later, prefix("kind", "delete")) {
			t.Fatalf("%s: cleanup executed or deleted: %v", field, later)
		}
		if !h.exists(path) {
			t.Fatalf("%s: the replacement container was deleted", field)
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
	if h.exists(filepath.Join(h.state, "ledger.json")) {
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
	if !h.nodeExists() {
		release()
		t.Fatal("cleanup deleted the cluster while the run held the lock")
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
	if !h.exists(filepath.Join(h.state, "execution-started")) || h.exists(filepath.Join(h.state, "ledger.json")) {
		t.Fatal("unexpected markers after an orphaned run")
	}
	if r := h.run("cleanup", "orphan-busy"); r.code == 0 {
		t.Fatal("cleanup proceeded while the orphan was busy")
	}
	if !h.nodeExists() {
		t.Fatal("the cluster was deleted while the orphan was busy")
	}
	before := len(h.calls())
	h.pass("cleanup", "orphan-closed")
	if h.nodeExists() {
		t.Fatal("the owned cluster was not deleted")
	}
	var executed [][]string
	for _, call := range h.calls()[before:] {
		if prefix("docker", "exec")(call) {
			executed = append(executed, call)
		}
	}
	if len(executed) != 1 || index(executed[0], "^TestPodProviderCloudLocalCleanup$") < 0 {
		t.Fatalf("cleanup executed %v", executed)
	}
}
