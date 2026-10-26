package c8srunc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	"github.com/confidential-dot-ai/c8s/internal/podstart"
)

func createdPodState() specs.State {
	return specs.State{ID: "ctr", Status: specs.StateCreated, Pid: 1234, Annotations: map[string]string{
		annotationSandboxID: "sandbox", annotationContainerType: "container",
	}}
}

func podWrapper(rec *recorder, stderr *bytes.Buffer) Wrapper {
	w := lockedWrapper(rec, stderr)
	w.Floor.Pod = true
	w.State = func(context.Context, string, []string) (specs.State, error) { return createdPodState(), nil }
	w.ConsumeStart = func(context.Context, string, podstart.Request) error { return errors.New("no permission") }
	return w
}

func TestPodStartConsumesCreatedProcessOnce(t *testing.T) {
	rec, stderr := &recorder{}, &bytes.Buffer{}
	w := podWrapper(rec, stderr)
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
	w.Run([]string{"c8s-runc", "start", "ctr"})
	if !rec.called {
		t.Fatalf("admitted start refused: %s", stderr)
	}
	rec.called = false
	if code := w.Run([]string{"c8s-runc", "start", "ctr"}); code != exitDenied || rec.called {
		t.Fatal("replayed permission reached runtime")
	}
}

func TestPodStartRefusalsNeverExecute(t *testing.T) {
	cases := []struct {
		name   string
		change func(*Wrapper)
		args   []string
	}{
		{"absent permission", func(*Wrapper) {}, []string{"start", "ctr"}},
		{"lost plugin", func(w *Wrapper) {
			w.ConsumeStart = func(context.Context, string, podstart.Request) error { return errors.New("connection refused") }
		}, []string{"start", "ctr"}},
		{"timeout", func(w *Wrapper) {
			w.ConsumeStart = func(context.Context, string, podstart.Request) error { return context.DeadlineExceeded }
		}, []string{"start", "ctr"}},
		{"unknown role", func(w *Wrapper) { w.FloorError = errors.New("unreadable config"); w.Floor.Pod = false }, []string{"start", "ctr"}},
		{"missing client", func(w *Wrapper) { w.ConsumeStart = nil }, []string{"start", "ctr"}},
		{"missing state query", func(w *Wrapper) { w.State = nil }, []string{"start", "ctr"}},
		{"failed state", func(w *Wrapper) {
			w.State = func(context.Context, string, []string) (specs.State, error) {
				return specs.State{}, errors.New("state unavailable")
			}
		}, []string{"start", "ctr"}},
		{"direct run", func(*Wrapper) {}, []string{"run", "ctr"}},
		{"restore", func(*Wrapper) {}, []string{"restore", "ctr"}},
		{"extra start argument", func(*Wrapper) {}, []string{"start", "ctr", "other"}},
		{"unknown start option", func(*Wrapper) {}, []string{"start", "--root", "elsewhere", "ctr"}},
		{"missing ID", func(*Wrapper) {}, []string{"start"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, stderr := &recorder{}, &bytes.Buffer{}
			w := podWrapper(rec, stderr)
			tc.change(&w)
			if code := w.Run(append([]string{"c8s-runc"}, tc.args...)); code != exitDenied || rec.called {
				t.Fatalf("refusal reached runtime: code=%d stderr=%s", code, stderr)
			}
		})
	}
}

func TestPodStartChecksPersistedState(t *testing.T) {
	cases := []struct {
		name   string
		change func(*specs.State)
	}{
		{"different container", func(s *specs.State) { s.ID = "other" }},
		{"running", func(s *specs.State) { s.Status = specs.StateRunning }},
		{"stopped", func(s *specs.State) { s.Status = specs.StateStopped }},
		{"zero PID", func(s *specs.State) { s.Pid = 0 }},
		{"negative PID", func(s *specs.State) { s.Pid = -1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec, stderr := &recorder{}, &bytes.Buffer{}
			w := podWrapper(rec, stderr)
			state := createdPodState()
			tc.change(&state)
			w.State = func(context.Context, string, []string) (specs.State, error) { return state, nil }
			w.ConsumeStart = func(context.Context, string, podstart.Request) error {
				t.Fatal("invalid process consumed a permission")
				return nil
			}
			if code := w.Run([]string{"c8s-runc", "start", "ctr"}); code != exitDenied || rec.called {
				t.Fatal("invalid state executed")
			}
		})
	}
}

func TestPodSandboxExemptionUsesPersistedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, kind, sandbox string
		allowed             bool
	}{
		{"pause", containerTypeSandbox, "ctr", true},
		{"workload", "container", "ctr", false},
		{"wrong sandbox ID", containerTypeSandbox, "other", false},
		{"missing sandbox ID", containerTypeSandbox, "", false},
		{"missing type", "", "ctr", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec, stderr := &recorder{}, &bytes.Buffer{}
			w := podWrapper(rec, stderr)
			state := createdPodState()
			state.Annotations = map[string]string{annotationContainerType: tc.kind, annotationSandboxID: tc.sandbox}
			w.State = func(context.Context, string, []string) (specs.State, error) { return state, nil }
			w.Run([]string{"c8s-runc", "start", "ctr"})
			if rec.called != tc.allowed {
				t.Fatalf("runtime called=%t: %s", rec.called, stderr)
			}
		})
	}
}

func TestPodStateUsesExactRuntimeGlobals(t *testing.T) {
	for _, prefix := range [][]string{
		{"--root", "/run/private-runc", "--systemd-cgroup"},
		{"-root=/run/private-runc", "--log-format=json", "--log", "/run/runtime.log"},
		{"--root", "start", "--"},
	} {
		t.Run(strings.Join(prefix, " "), func(t *testing.T) {
			rec, stderr := &recorder{}, &bytes.Buffer{}
			w := podWrapper(rec, stderr)
			w.State = func(ctx context.Context, runtime string, args []string) (specs.State, error) {
				want := append(append([]string{}, prefix...), "state", "ctr")
				if runtime != w.RealRunc || !reflect.DeepEqual(args, want) {
					t.Fatalf("state query %s %q", runtime, args)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("state query has no deadline")
				}
				return createdPodState(), nil
			}
			w.ConsumeStart = func(context.Context, string, podstart.Request) error { return nil }
			argv := append(append([]string{"c8s-runc"}, prefix...), "start", "--", "ctr")
			w.Run(argv)
			if !rec.called {
				t.Fatalf("start denied: %s", stderr)
			}
			if !reflect.DeepEqual(rec.argv[1:], argv[1:]) {
				t.Fatal("start arguments changed")
			}
		})
	}
}

func TestRuntimeStateBoundsAndCancellation(t *testing.T) {
	script := filepath.Join(t.TempDir(), "runtime")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf '%s' '{\"id\":\"ctr\",\"status\":\"created\",\"pid\":1234}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := runtimeState(context.Background(), script, []string{"state", "ctr"})
	if err != nil || state.ID != "ctr" || state.Pid != 1234 {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runtimeState(ctx, script, nil); err == nil {
		t.Fatal("cancelled query succeeded")
	}
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec sleep 10\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := runtimeState(ctx, script, nil); err == nil {
		t.Fatal("timed out query succeeded")
	}
	output := &stateOutput{remaining: 2}
	if _, err := output.Write([]byte("123")); err == nil || len(output.Bytes()) != 0 {
		t.Fatal("oversized state retained")
	}
}

func TestPodCreateRefusesEveryRuntimeHookBeforeSandboxExemption(t *testing.T) {
	for _, stage := range []string{"prestart", "createRuntime", "createContainer", "startContainer", "poststart", "poststop"} {
		for _, sandbox := range []bool{false, true} {
			t.Run(stage+map[bool]string{false: "/workload", true: "/sandbox"}[sandbox], func(t *testing.T) {
				spec := workloadBundle()
				if sandbox {
					spec.Annotations[annotationContainerType] = containerTypeSandbox
					spec.Annotations[annotationSandboxID] = "ctr"
				}
				body := []byte(`{"` + stage + `":[{"path":"/unadmitted-hook"}]}`)
				if err := json.Unmarshal(body, &spec.Hooks); err != nil {
					t.Fatal(err)
				}
				floor := testFloor()
				floor.Pod = true
				if err := requireFloor(spec, "ctr", nil, floor); err == nil {
					t.Fatal("Pod hook admitted")
				}
				floor.Pod = false
				if err := requireFloor(spec, "ctr", nil, floor); err != nil {
					t.Fatalf("node behavior changed: %v", err)
				}
				if err := json.Unmarshal([]byte(`{"`+stage+`":[]}`), &spec.Hooks); err != nil {
					t.Fatal(err)
				}
				floor.Pod = true
				if err := requireFloor(spec, "ctr", nil, floor); err != nil {
					t.Fatalf("empty hook denied: %v", err)
				}
			})
		}
	}
}
