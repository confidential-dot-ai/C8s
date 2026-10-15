package steps

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cucumber/godog"
)

// exitUnsupported is the backend's "this environment cannot express that"
// status (see the header of ../backends/common.sh).
const exitUnsupported = 77

// backend runs one function of ../backends/<name>.sh; the header of
// ../backends/common.sh states the contract.
type backend struct {
	script string
	memo   map[string]string // answers of the functions constant for a run
}

// constant names the functions whose answer the contract fixes for a run.
var constant = map[string]bool{
	"node_name": true, "image_ref": true, "image_digest": true, "pull_interval": true, "cds_pod_url": true,
	"cert_paths": true, "node_address": true, "mesh_ready": true, "mesh_port": true, "mesh_uids": true,
	"mesh_platform": true, "excluded_namespace": true, "host_namespace_ns": true, "attestation_endpoint": true, "dialer_bin": true,
	"pod_exec": true,
}

// newBackend finds the backend beside this package; `go test` runs with the
// package directory as its working directory.
func newBackend(name string) (backend, error) {
	script, err := filepath.Abs(filepath.Join("..", "backends", name+".sh"))
	if err != nil {
		return backend{}, err
	}
	if _, err := os.Stat(script); err != nil {
		return backend{}, fmt.Errorf("backend %q: %w", name, err)
	}
	b := backend{script: script, memo: map[string]string{}}
	// Steps call kubectl directly too; point it where the backend does.
	kubeconfig, err := b.call("kubeconfig")
	if err != nil {
		return backend{}, err
	}
	if err := os.Setenv("KUBECONFIG", kubeconfig); err != nil {
		return backend{}, err
	}
	return b, nil
}

// call returns the function's trimmed stdout. A 77 exit is godog.ErrSkip;
// any other failure is a harness error carrying the function's stderr.
func (b backend) call(fn string, args ...string) (string, error) {
	key := fn + "\x00" + strings.Join(args, "\x00")
	if out, ok := b.memo[key]; ok && constant[fn] {
		return out, nil
	}
	cmd := exec.Command("bash", append([]string{b.script, fn}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		out := strings.TrimSpace(stdout.String())
		if constant[fn] {
			b.memo[key] = out
		}
		return out, nil
	case errors.As(err, &exit) && exit.ExitCode() == exitUnsupported:
		return "", godog.ErrSkip
	default:
		return "", fmt.Errorf("backend %s %s: %w\n%s", fn, strings.Join(args, " "), err, stderr.String())
	}
}

// podExec runs cmd in a container of the pod, kubectl's default one when
// container is empty: through kubectl exec, or where the backend's cluster
// closes pod exec, through the agent the backend runs in the pod (pod_exec,
// agent_run), which skips what it cannot reach.
func (w *world) podExec(p *pod, container string, cmd ...string) (string, error) {
	mode, err := w.be.call("pod_exec")
	if err != nil {
		return "", err
	}
	if mode == "agent" {
		quoted := make([]string, len(cmd))
		for i, word := range cmd {
			quoted[i] = "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
		}
		out, err := w.be.call("agent_run", p.namespace, p.name, container, strings.Join(quoted, " "))
		if err != nil {
			return "", err
		}
		raw, err := base64.StdEncoding.DecodeString(out)
		if err != nil {
			return "", fmt.Errorf("the agent in %q answered no base64: %w", p.name, err)
		}
		return string(raw), nil
	}
	args := []string{"-n", p.namespace, "exec", p.name}
	if container != "" {
		args = append(args, "-c", container)
	}
	return kubectl(nil, append(append(args, "--"), cmd...)...)
}

// kubectl runs kubectl against the backend's current context.
func kubectl(stdin []byte, args ...string) (string, error) {
	cmd := exec.Command("kubectl", args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("kubectl %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}
