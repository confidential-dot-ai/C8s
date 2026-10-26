package c8srunc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"slices"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/internal/podstart"
)

func (w Wrapper) requirePodStart(g globals) error {
	if w.FloorError != nil {
		return fmt.Errorf("read measured runtime policy: %w", w.FloorError)
	}
	if !w.Floor.PodRole {
		return nil
	}
	args := g.rest
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) != 1 || isFlag(args[0]) || args[0] == "" {
		return errors.New("pod start requires exactly one container ID")
	}
	if w.State == nil || w.ConsumeStart == nil {
		return errors.New("pod runtime admission gate is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), podstart.Timeout)
	defer cancel()
	stateArgs := append(slices.Clone(g.options), "state", args[0])
	state, err := w.State(ctx, w.RealRunc, stateArgs)
	if err != nil {
		return fmt.Errorf("read created Pod process: %w", err)
	}
	if state.ID != args[0] || state.Status != specs.StateCreated || state.Pid <= 0 || int64(state.Pid) > math.MaxUint32 {
		return errors.New("runtime state does not identify the requested created process")
	}
	// Only the runtime's persisted sandbox record can exempt its pause process.
	if state.Annotations[annotationContainerType] == containerTypeSandbox && state.Annotations[annotationSandboxID] == state.ID {
		return ctx.Err()
	}
	return w.ConsumeStart(ctx, podstart.SocketPath, podstart.Request{
		ContainerID: state.ID, SandboxID: state.Annotations[annotationSandboxID], PID: uint32(state.Pid),
	})
}

// runtimeState queries the same runc state root the eventual start will use.
func runtimeState(ctx context.Context, runtime string, args []string) (specs.State, error) {
	var state specs.State
	output := &stateOutput{remaining: 128 << 10}
	cmd := exec.CommandContext(ctx, runtime, args...)
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		return state, fmt.Errorf("runtime state query failed: %w", err)
	}
	if err := json.Unmarshal(output.Bytes(), &state); err != nil {
		return state, errors.New("runtime returned invalid state")
	}
	return state, nil
}

type stateOutput struct {
	buffer    bytes.Buffer
	remaining int
}

func (b *stateOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *stateOutput) Write(p []byte) (int, error) {
	if len(p) > b.remaining {
		return 0, errors.New("runtime state exceeds size limit")
	}
	b.remaining -= len(p)
	return b.buffer.Write(p)
}
