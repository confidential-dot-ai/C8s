package allowlist

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

const testDigest = "sha256:effd250754b8a70517c27eab8f18463b395a7b2a8e868fd919226c3180636939"
const testImage = "nvcr.io/nvidia/ai-dynamo/vllm-runtime@" + testDigest

// deployJSON is a Deployment carrying an init container, a container with a
// command and no args, and a container with both. That combination is what a
// hand-written entry gets wrong in practice.
func deployJSON() string {
	return `{
      "kind": "Deployment",
      "spec": {"template": {"spec": {
        "initContainers": [
          {"name": "seed", "image": "` + testImage + `",
           "command": ["sh", "-c", "cp -an /a/. /seed/"]}
        ],
        "containers": [
          {"name": "frontend", "image": "` + testImage + `",
           "command": ["python3", "-m", "dynamo.frontend"]},
          {"name": "worker", "image": "` + testImage + `",
           "command": ["sh"], "args": ["-c", "exec python3 -m dynamo.vllm"]}
        ]}}}}`
}

func runDerive(t *testing.T, stdin string, args ...string) (map[string]pkgallowlist.Workload, error) {
	t.Helper()
	got, _, err := runDeriveStderr(t, stdin, args...)
	return got, err
}

// The entry goes to stdout and the dropped-container report to stderr, so the
// two are kept apart here as they are when piping derive into apply.
func runDeriveStderr(t *testing.T, stdin string, args ...string) (map[string]pkgallowlist.Workload, string, error) {
	t.Helper()
	cmd := newDeriveCmd(&options{})
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	if err := cmd.Execute(); err != nil {
		return nil, errOut.String(), err
	}
	var got map[string]pkgallowlist.Workload
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("derived output is not a workload map: %v\n%s", err, out.String())
	}
	return got, errOut.String(), nil
}

func TestDeriveCoversInitContainers(t *testing.T) {
	got, err := runDerive(t, deployJSON(), "dynamo", "-", "--env=any")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	w, ok := got["dynamo"]
	if !ok {
		t.Fatalf("entry not keyed by name: %v", got)
	}
	// CDS matches the whole candidate set, so an undeclared init container
	// refuses every release with "no workload entry matches the running
	// containers".
	if len(w.InitContainers) != 1 {
		t.Fatalf("init containers = %d, want 1", len(w.InitContainers))
	}
	if len(w.Containers) != 2 {
		t.Fatalf("containers = %d, want 2", len(w.Containers))
	}
}

func TestDeriveArgvPolicies(t *testing.T) {
	got, _ := runDerive(t, deployJSON(), "dynamo", "-", "--env=any")
	w := got["dynamo"]

	// A command with no args is Deny. Exact would be rejected on apply
	// ("exact policy requires a non-empty argv") and Any would be looser than
	// what the container runs.
	if p := w.Containers[0].Args.Policy; p != pkgallowlist.PolicyDeny {
		t.Errorf("frontend args policy = %q, want %q", p, pkgallowlist.PolicyDeny)
	}
	if p := w.Containers[1].Args.Policy; p != pkgallowlist.PolicyExact {
		t.Errorf("worker args policy = %q, want %q", p, pkgallowlist.PolicyExact)
	}
	if got, want := w.Containers[1].Args.Argv, []string{"-c", "exec python3 -m dynamo.vllm"}; !equalArgv(got, want) {
		t.Errorf("worker argv = %v, want %v", got, want)
	}
	if p := w.InitContainers[0].Command.Policy; p != pkgallowlist.PolicyExact {
		t.Errorf("init command policy = %q, want %q", p, pkgallowlist.PolicyExact)
	}
}

func TestDeriveSecretsOnlyWhenAsked(t *testing.T) {
	got, _ := runDerive(t, deployJSON(), "dynamo", "-", "--env=any")
	if got["dynamo"].Secrets != nil {
		t.Errorf("secrets block emitted without --secret-read")
	}

	got, _ = runDerive(t, deployJSON(), "dynamo", "-", "--env=any", "--secret-read", "/dynamo/volumes/w235")
	s := got["dynamo"].Secrets
	if s == nil {
		t.Fatal("no secrets block with --secret-read")
	}
	if s.Policy != pkgallowlist.PolicyAllow || len(s.Read) != 1 || s.Read[0] != "/dynamo/volumes/w235" {
		t.Errorf("secrets = %+v", s)
	}
}

func TestDeriveMountPolicies(t *testing.T) {
	file := t.TempDir() + "/mounts.json"
	data := `{"seed":{"policy":"deny"},"frontend":{"policy":"exact","rules":[{"destination":"/config","kind":"emptyDir"}]},"worker":{"policy":"deny"}}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := runDerive(t, deployJSON(), "dynamo", "-", "--env=any", "--mounts-file", file)
	if err != nil {
		t.Fatal(err)
	}
	if p := got["dynamo"].Containers[0].Mounts; p.Policy != pkgallowlist.PolicyExact || len(p.Rules) != 1 || p.Rules[0].Destination != "/config" || p.Rules[0].Kind != pkgallowlist.MountEmptyDir {
		t.Fatalf("frontend mounts = %+v", p)
	}
}

func TestDeriveMountShorthand(t *testing.T) {
	for _, mode := range []string{"any", "deny"} {
		got, err := runDerive(t, deployJSON(), "dynamo", "-", "--env=any", "--mounts="+mode)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range allContainers(got["dynamo"]) {
			if c.Mounts.Policy != mode {
				t.Fatalf("mounts = %+v, want %s on every container", c.Mounts, mode)
			}
		}
	}
	// Without either flag the entry carries no policy and applying it denies.
	got, err := runDerive(t, deployJSON(), "dynamo", "-", "--env=any")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(got["dynamo"])
	if err != nil {
		t.Fatal(err)
	}
	applied, err := pkgallowlist.ParseWorkloadJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range allContainers(*applied) {
		if c.Mounts.Policy != pkgallowlist.PolicyDeny {
			t.Fatalf("mounts = %+v without --mounts, want deny", c.Mounts)
		}
	}
	if _, err := runDerive(t, deployJSON(), "dynamo", "-", "--env=any", "--mounts=exact"); err == nil {
		t.Fatal("accepted a rule-bearing policy as a shorthand")
	}
	file := t.TempDir() + "/mounts.json"
	data := `{"seed":{"policy":"deny"},"frontend":{"policy":"any"},"worker":{"policy":"deny"}}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runDerive(t, deployJSON(), "dynamo", "-", "--env=any", "--mounts=any", "--mounts-file", file); err == nil {
		t.Fatal("conflicting mount policies accepted")
	}
	// --mounts leaves the file path's per-container bookkeeping alone.
	stray := t.TempDir() + "/stray.json"
	if err := os.WriteFile(stray, []byte(`{"seed":{"policy":"deny"},"frontend":{"policy":"any"},"worker":{"policy":"deny"},"ghost":{"policy":"any"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runDerive(t, deployJSON(), "dynamo", "-", "--env=any", "--mounts-file", stray); err == nil {
		t.Fatal("mount policy naming an unknown container accepted")
	} else if !strings.Contains(err.Error(), `unknown container "ghost"`) {
		t.Fatalf("error = %v, want the unnamed container", err)
	}
}

func TestDeriveWarnsWhenNoMountPolicyIsGiven(t *testing.T) {
	_, stderr, err := runDeriveStderr(t, deployJSON(), "dynamo", "-", "--env=any")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr, "deny") {
		t.Fatalf("stderr = %q, want the deny default named", stderr)
	}
	if _, stderr, err = runDeriveStderr(t, deployJSON(), "dynamo", "-", "--env=any", "--mounts=any"); err != nil {
		t.Fatal(err)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q with --mounts", stderr)
	}
}

func TestDeriveAcceptsABarePod(t *testing.T) {
	pod := `{"kind":"Pod","spec":{"containers":[{"name":"c","image":"` + testImage + `","command":["sleep","inf"]}]}}`
	got, err := runDerive(t, pod, "p", "-", "--env=any")
	if err != nil {
		t.Fatalf("derive pod: %v", err)
	}
	if len(got["p"].Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(got["p"].Containers))
	}
}

func TestDeriveRejectsUnpinnedImage(t *testing.T) {
	bad := `{"kind":"Pod","spec":{"containers":[{"name":"c","image":"busybox:latest","command":["sh"]}]}}`
	if _, err := runDerive(t, bad, "p", "-"); err == nil {
		t.Fatal("accepted an image with no digest")
	} else if !strings.Contains(err.Error(), "not pinned by digest") {
		t.Errorf("error = %v, want a digest complaint", err)
	}
}

func TestDeriveRejectsObjectWithoutContainers(t *testing.T) {
	if _, err := runDerive(t, `{"kind":"ConfigMap","spec":{}}`, "x", "-"); err == nil {
		t.Fatal("accepted an object with no pod spec")
	} else if !strings.Contains(err.Error(), "carries no containers") {
		t.Errorf("error = %v", err)
	}
}

func equalArgv(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// admittedPodJSON is a pod as the API server returns it after injection: the
// authored init container and mains, plus the four containers c8s adds, one of
// them on a floating tag.
func admittedPodJSON() string {
	return `{
      "kind": "Pod",
      "metadata": {"annotations": {"confidential.ai/c8s-injected": "true"}},
      "spec": {
        "initContainers": [
          {"name": "c8s-cert", "image": "ghcr.io/confidential-dot-ai/c8s:v0.23.0",
           "args": ["--san=c8s-busybox-secret.default.svc", "--cds-measurements=abc"]},
          {"name": "c8s-cert-wait", "image": "` + testImage + `",
           "command": ["/c8s", "probe-file", "--wait", "/tls/cert.pem"]},
          {"name": "c8s-secret", "image": "` + testImage + `", "args": ["--measurements=abc"]},
          {"name": "c8s-volume", "image": "` + testImage + `", "args": ["--open=vol"]},
          {"name": "seed", "image": "` + testImage + `",
           "command": ["sh", "-c", "cp -an /a/. /seed/"]}
        ],
        "containers": [
          {"name": "app", "image": "` + testImage + `", "command": ["sleep", "inf"]}
        ]}}`
}

func TestDeriveDropsInjectedContainers(t *testing.T) {
	got, stderr, err := runDeriveStderr(t, admittedPodJSON(), "app", "-", "--env=any")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	for _, name := range []string{"c8s-cert", "c8s-cert-wait", "c8s-secret", "c8s-volume"} {
		if !strings.Contains(stderr, name) {
			t.Errorf("stderr %q does not report dropping %q", stderr, name)
		}
	}
	w := got["app"]
	if len(w.InitContainers) != 1 {
		t.Fatalf("initContainers = %d, want only the authored seed", len(w.InitContainers))
	}
	if !equalArgv(w.InitContainers[0].Command.Argv, []string{"sh", "-c", "cp -an /a/. /seed/"}) {
		t.Errorf("init command = %v, want the seed argv", w.InitContainers[0].Command.Argv)
	}
	if len(w.Containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(w.Containers))
	}
}

// The policy files describe only the containers that survive the drop, so an
// operator is never asked to write a mount policy for c8s's own sidecars.
func TestDeriveDropsInjectedBeforePolicyFiles(t *testing.T) {
	dir := t.TempDir()
	mounts := dir + "/mounts.json"
	if err := os.WriteFile(mounts, []byte(`{"seed":{"policy":"deny"},"app":{"policy":"deny"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	env := dir + "/env.json"
	if err := os.WriteFile(env, []byte(`{"seed":{"policy":"deny"},"app":{"policy":"any"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := runDerive(t, admittedPodJSON(), "app", "-", "--env-file", env, "--mounts-file", mounts); err != nil {
		t.Fatalf("derive: %v", err)
	}
}

func TestDeriveRejectsPolicyForDroppedContainer(t *testing.T) {
	file := t.TempDir() + "/mounts.json"
	data := `{"seed":{"policy":"deny"},"app":{"policy":"deny"},"c8s-cert":{"policy":"deny"}}`
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := runDerive(t, admittedPodJSON(), "app", "-", "--env=any", "--mounts-file", file)
	if err == nil {
		t.Fatal("accepted a mount policy for a dropped container")
	}
	if !strings.Contains(err.Error(), "c8s injects") {
		t.Errorf("error = %v, want it to name the injected container", err)
	}
}

// An input with nothing c8s injected is derived without a report, so the
// message only appears when it says something.
func TestDeriveReportsNothingWhenNothingIsDropped(t *testing.T) {
	_, stderr, err := runDeriveStderr(t, deployJSON(), "dynamo", "-", "--env=any", "--mounts=any")
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if stderr != "" {
		t.Errorf("stderr = %q, want nothing reported", stderr)
	}
}

func TestDeriveRejectsEnvPolicyForUnknownContainer(t *testing.T) {
	file := t.TempDir() + "/env.json"
	if err := os.WriteFile(file, []byte(`{"seed":{"policy":"deny"},"frontend":{"policy":"any"},"worker":{"policy":"any"},"ghost":{"policy":"any"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := runDerive(t, deployJSON(), "dynamo", "-", "--env-file", file)
	if err == nil {
		t.Fatal("accepted an env policy for a container that is not there")
	}
	if !strings.Contains(err.Error(), `unknown container "ghost"`) {
		t.Errorf("error = %v, want it to name the unknown container", err)
	}
}

func TestDeriveContainersResolvesImageArgv(t *testing.T) {
	resolve := func(string) ([]string, []string, error) {
		return []string{"/docker-entrypoint.sh"}, []string{"nginx", "-g", "daemon off;"}, nil
	}
	for _, tc := range []struct {
		name          string
		c             templateContainer
		command, args []string
	}{
		{"image defaults", templateContainer{}, []string{"/docker-entrypoint.sh"}, []string{"nginx", "-g", "daemon off;"}},
		{"args only", templateContainer{Args: []string{"-v"}}, []string{"/docker-entrypoint.sh"}, []string{"-v"}},
		{"command only", templateContainer{Command: []string{"sh"}}, []string{"sh"}, nil},
	} {
		tc.c.Name, tc.c.Image = "app", testImage
		got, err := deriveContainers([]templateContainer{tc.c}, resolve)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !equalArgv(got[0].Command.Argv, tc.command) || !equalArgv(got[0].Args.Argv, tc.args) {
			t.Errorf("%s: command %v args %v, want %v %v", tc.name, got[0].Command.Argv, got[0].Args.Argv, tc.command, tc.args)
		}
	}
}

func TestDeriveContainersNamesUnresolvableImage(t *testing.T) {
	resolve := func(string) ([]string, []string, error) { return nil, nil, errors.New("registry unreachable") }
	_, err := deriveContainers([]templateContainer{{Name: "app", Image: testImage}}, resolve)
	if err == nil || !strings.Contains(err.Error(), `container "app" sets no command`) || !strings.Contains(err.Error(), "registry unreachable") {
		t.Fatalf("deriveContainers(unresolvable image) = %v, want the container and cause named", err)
	}
}
