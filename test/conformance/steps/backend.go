package steps

import (
	"bytes"
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
	b := backend{script: script}
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
	cmd := exec.Command("bash", append([]string{b.script, fn}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return strings.TrimSpace(stdout.String()), nil
	case errors.As(err, &exit) && exit.ExitCode() == exitUnsupported:
		return "", godog.ErrSkip
	default:
		return "", fmt.Errorf("backend %s %s: %w\n%s", fn, strings.Join(args, " "), err, stderr.String())
	}
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
