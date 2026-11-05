package c8srunc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/internal/podstart"
)

func createdPodState() specs.State {
	return specs.State{ID: "ctr", Status: specs.StateCreated, Pid: 1234, Annotations: map[string]string{
		annotationSandboxID: "sandbox", annotationContainerType: "container",
	}}
}

// podWrapper is the locked wrapper of a pod CVM whose plugin issues no start
// permission.
func podWrapper(rec *recorder, stderr *bytes.Buffer) Wrapper {
	w := lockedWrapper(rec, stderr)
	w.Floor.PodRole = true
	w.State = func(context.Context, string, []string) (specs.State, error) { return createdPodState(), nil }
	w.ConsumeStart = func(context.Context, string, podstart.Request) error { return errors.New("no permission") }
	return w
}

// A start consumes a permission bound to the created process the runtime
// persists under the same state root the start will use, once; a replay is
// refused.
func TestPodStartConsumesCreatedProcessOnce(t *testing.T) {
	rec, stderr := &recorder{}, &bytes.Buffer{}
	w := podWrapper(rec, stderr)
	prefix := []string{"--root", "/run/private-runc", "--systemd-cgroup"}
	w.State = func(ctx context.Context, runtime string, args []string) (specs.State, error) {
		if want := append(append([]string{}, prefix...), "state", "ctr"); runtime != w.RealRunc || !reflect.DeepEqual(args, want) {
			t.Fatalf("state query %s %q", runtime, args)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("state query has no deadline")
		}
		return createdPodState(), nil
	}
	available := true
	w.ConsumeStart = func(ctx context.Context, socket string, request podstart.Request) error {
		want := podstart.Request{ContainerID: "ctr", SandboxID: "sandbox", PID: 1234}
		if request != want || socket != podstart.SocketPath {
			t.Fatalf("permission request = %+v at %s", request, socket)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("permission request has no deadline")
		}
		if !available {
			return errors.New("already consumed")
		}
		available = false
		return nil
	}
	argv := append(append([]string{"c8s-runc"}, prefix...), "start", "--", "ctr")
	w.Run(argv)
	if !rec.called {
		t.Fatalf("admitted start refused: %s", stderr)
	}
	if !reflect.DeepEqual(rec.argv[1:], argv[1:]) {
		t.Fatal("start arguments changed")
	}
	rec.called = false
	if code := w.Run(argv); code != exitDenied || rec.called {
		t.Fatal("replayed permission reached runtime")
	}
}

// Every path that would start a process without the plugin's confirmation
// is refused before the real runtime runs, and a process the runtime does not
// report as created consumes no permission; a waiting guest refuses the
// pause sandbox too.
func TestPodStartRefusalsNeverExecute(t *testing.T) {
	withState := func(w *Wrapper, change func(*specs.State)) {
		state := createdPodState()
		change(&state)
		w.State = func(context.Context, string, []string) (specs.State, error) { return state, nil }
	}
	cases := []struct {
		name   string
		change func(*testing.T, *Wrapper)
		args   []string
	}{
		{"absent permission, or any client error", func(*testing.T, *Wrapper) {}, []string{"start", "ctr"}},
		{"unreadable policy", func(_ *testing.T, w *Wrapper) {
			w.FloorError = errors.New("unreadable config")
			w.Floor.PodRole = false
		}, []string{"start", "ctr"}},
		{"missing admission gate", func(_ *testing.T, w *Wrapper) { w.ConsumeStart = nil }, []string{"start", "ctr"}},
		{"failed state query", func(_ *testing.T, w *Wrapper) {
			w.State = func(context.Context, string, []string) (specs.State, error) {
				return specs.State{}, errors.New("state unavailable")
			}
		}, []string{"start", "ctr"}},
		{"process not created", func(t *testing.T, w *Wrapper) {
			withState(w, func(s *specs.State) { s.Status = specs.StateRunning })
			w.ConsumeStart = func(context.Context, string, podstart.Request) error {
				t.Fatal("invalid process consumed a permission")
				return nil
			}
		}, []string{"start", "ctr"}},
		{"forged sandbox claim", func(_ *testing.T, w *Wrapper) {
			withState(w, func(s *specs.State) {
				s.Annotations = map[string]string{annotationContainerType: containerTypeSandbox, annotationSandboxID: "other"}
			})
		}, []string{"start", "ctr"}},
		{"create and start in one step", func(*testing.T, *Wrapper) {}, []string{"run", "ctr"}},
		{"malformed container ID", func(*testing.T, *Wrapper) {}, []string{"start", "--root", "elsewhere", "ctr"}},
		{"waiting guest: create", func(_ *testing.T, w *Wrapper) { w.Floor.PodWaiting = true }, []string{"create", "pause"}},
		{"waiting guest: start", func(_ *testing.T, w *Wrapper) { w.Floor.PodWaiting = true }, []string{"start", "pause"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, stderr := &recorder{}, &bytes.Buffer{}
			w := podWrapper(rec, stderr)
			tc.change(t, &w)
			if code := w.Run(append([]string{"c8s-runc"}, tc.args...)); code != exitDenied || rec.called {
				t.Fatalf("refusal reached runtime: code=%d stderr=%s", code, stderr)
			}
		})
	}
}

// The pause sandbox starts without a permission, on the runtime's
// persisted record alone.
func TestPodSandboxStartsWithoutPermission(t *testing.T) {
	rec, stderr := &recorder{}, &bytes.Buffer{}
	w := podWrapper(rec, stderr)
	state := createdPodState()
	state.Annotations = map[string]string{annotationContainerType: containerTypeSandbox, annotationSandboxID: "ctr"}
	w.State = func(context.Context, string, []string) (specs.State, error) { return state, nil }
	if w.Run([]string{"c8s-runc", "start", "ctr"}); !rec.called {
		t.Fatalf("pause sandbox refused: %s", stderr)
	}
}

// runtimeState parses the real runtime's state and bounds what it reads.
func TestRuntimeStateIsBounded(t *testing.T) {
	script := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '{\"id\":\"ctr\",\"status\":\"created\",\"pid\":1234}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := runtimeState(context.Background(), script, []string{"state", "ctr"})
	if err != nil || state.ID != "ctr" || state.Pid != 1234 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	output := &stateOutput{remaining: 2}
	if _, err := output.Write([]byte("123")); err == nil || len(output.Bytes()) != 0 {
		t.Fatal("oversized state retained")
	}
}
