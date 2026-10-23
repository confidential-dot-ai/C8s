package c8srunc

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// recorder captures a handoff instead of replacing the test process.
type recorder struct {
	called bool
	path   string
	argv   []string
	env    []string
	err    error
}

func (r *recorder) exec(path string, argv, env []string) error {
	r.called, r.path, r.argv, r.env = true, path, argv, env
	if r.err == nil {
		r.err = errors.New("exec returned, which only happens on failure")
	}
	return r.err
}

// lockedWrapper is the locked wrapper carrying the floor every node has.
func lockedWrapper(rec *recorder, stderr *bytes.Buffer) Wrapper {
	return Wrapper{
		Mode:     ModeLocked,
		RealRunc: "/opt/c8s/runc",
		Floor:    testFloor(),
		Exec:     rec.exec,
		Env:      []string{"PATH=/usr/bin"},
		Err:      stderr,
	}
}

// Every spelling of `runc exec` runc itself accepts must be denied without the
// real runtime being reached, and nothing else may be.
func TestLockedDispatch(t *testing.T) {
	// A create reads the bundle it names for the floor; ocifloor_test.go
	// covers what the floor makes of one.
	bundle := bundleDirWith(t, workloadBundle())
	tests := []struct {
		name string
		args []string
		deny bool
	}{
		{"plain exec", []string{"exec", "ctr", "sh"}, true},
		{"exec after bool global", []string{"--debug", "exec", "ctr", "sh"}, true},
		{"exec after single-dash global", []string{"-debug", "exec", "ctr", "sh"}, true},
		{"exec after separated string value", []string{"--log", "/run/log.json", "exec", "ctr"}, true},
		{"exec after joined string value", []string{"--log=/run/log.json", "exec", "ctr"}, true},
		{"exec after single-dash joined value", []string{"-root=/run/runc", "exec", "ctr"}, true},
		{"exec after several globals", []string{"--root", "/run/runc", "--systemd-cgroup", "--log-format", "json", "exec", "ctr"}, true},
		{"exec after joined bool value", []string{"--debug=true", "exec", "ctr"}, true},
		{"exec after the -- boundary", []string{"--", "exec", "ctr"}, true},
		{"exec after globals and the -- boundary", []string{"--debug", "--", "exec", "ctr"}, true},
		{"exec with its own flags", []string{"exec", "-t", "--user", "0", "ctr", "sh"}, true},
		{"exec as the value of a string global", []string{"--root", "exec", "create", "--bundle", bundle, "ctr"}, false},
		{"create", []string{"--root", "/run/runc", "create", "--bundle", bundle, "ctr"}, false},
		{"start", []string{"start", "ctr"}, false},
		{"delete", []string{"--log", "/run/log.json", "--log-format", "json", "delete", "ctr"}, false},
		{"state", []string{"state", "ctr"}, false},
		{"kill", []string{"kill", "ctr", "SIGTERM"}, false},
		{"features", []string{"features"}, false},
		{"version only", []string{"--version"}, false},
		{"no arguments", nil, false},
		{"container id that looks like a flag", []string{"state", "--exec"}, false},
		{"exec container id that looks like a flag", []string{"exec", "--root", "sh"}, true},
		{"unknown global option", []string{"--seccomp-profile", "x", "create", "ctr"}, true},
		{"unknown single-dash option", []string{"-q", "create", "ctr"}, true},
		{"string global with no value", []string{"--root"}, true},
		{"bare dash is an operand", []string{"-"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{}
			var stderr bytes.Buffer
			code := lockedWrapper(rec, &stderr).Run(append([]string{"/usr/local/bin/c8s-runc"}, tt.args...))

			if tt.deny {
				if rec.called {
					t.Fatalf("Run(%q) reached the real runtime; want denial", tt.args)
				}
				if code != exitDenied {
					t.Errorf("Run(%q) = %d, want %d", tt.args, code, exitDenied)
				}
				if stderr.Len() == 0 {
					t.Errorf("Run(%q) denied silently; want a message on stderr", tt.args)
				}
				return
			}
			if !rec.called {
				t.Fatalf("Run(%q) did not reach the real runtime: %s", tt.args, stderr.String())
			}
			if code != exitNoExec {
				t.Errorf("Run(%q) = %d after a failed handoff, want %d", tt.args, code, exitNoExec)
			}
		})
	}
}

// The debug build is the same dispatcher with the one branch off.
func TestDebugModePassesExecThrough(t *testing.T) {
	rec := &recorder{}
	var stderr bytes.Buffer
	w := lockedWrapper(rec, &stderr)
	w.Mode = ModeDebug
	w.Run([]string{"c8s-runc", "exec", "ctr", "sh"})
	if !rec.called {
		t.Fatalf("debug mode denied exec: %s", stderr.String())
	}
}

// A wrapper built with neither posture denies everything rather than guessing.
func TestUnknownModeDenies(t *testing.T) {
	rec := &recorder{}
	var stderr bytes.Buffer
	w := lockedWrapper(rec, &stderr)
	w.Mode = "permissive"
	if code := w.Run([]string{"c8s-runc", "create", "ctr"}); code != exitDenied {
		t.Errorf("Run(create) with mode %q = %d, want %d", w.Mode, code, exitDenied)
	}
	if rec.called {
		t.Error("a wrapper with an unknown mode reached the real runtime")
	}
}

// The default build constants are the production posture: an image that forgets
// the ldflags still denies exec, and the real runtime is never PATH-resolved.
func TestBuildDefaultsAreLocked(t *testing.T) {
	if mode != ModeLocked {
		t.Errorf("default mode = %q, want %q", mode, ModeLocked)
	}
	if !filepath.IsAbs(realRunc) {
		t.Errorf("default real runtime %q is not an absolute path", realRunc)
	}
}

// A permitted verb is handed over with its argv and environment intact; only
// argv[0] becomes the real runtime's own path.
func TestHandoffPreservesArgvAndEnv(t *testing.T) {
	rec := &recorder{}
	var stderr bytes.Buffer
	w := lockedWrapper(rec, &stderr)
	args := []string{"--root", "/run/runc", "create", "--bundle", bundleDirWith(t, workloadBundle()), "ctr-1"}

	w.Run(append([]string{"/usr/local/bin/c8s-runc"}, args...))

	if rec.path != w.RealRunc {
		t.Errorf("handoff path = %q, want %q", rec.path, w.RealRunc)
	}
	if want := append([]string{w.RealRunc}, args...); !reflect.DeepEqual(rec.argv, want) {
		t.Errorf("handoff argv = %q, want %q", rec.argv, want)
	}
	if !reflect.DeepEqual(rec.env, w.Env) {
		t.Errorf("handoff env = %q, want %q", rec.env, w.Env)
	}
}

// containerd surfaces the runtime error it finds in --log, so a denial has to
// land there in the format the caller asked for.
func TestDenialWritesRuncLog(t *testing.T) {
	for _, format := range []string{"json", "text"} {
		t.Run(format, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "runc.log")
			rec := &recorder{}
			var stderr bytes.Buffer
			lockedWrapper(rec, &stderr).Run([]string{
				"c8s-runc", "--log", logPath, "--log-format", format, "exec", "ctr", "sh",
			})

			data, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatalf("read runc log: %v", err)
			}
			if format == "text" {
				if !strings.Contains(string(data), DenyMessage) {
					t.Errorf("runc log = %q, want it to contain %q", data, DenyMessage)
				}
				return
			}
			var entry struct{ Level, Msg string }
			if err := json.Unmarshal(bytes.TrimSpace(data), &entry); err != nil {
				t.Fatalf("runc log %q is not a JSON entry: %v", data, err)
			}
			if entry.Level != "error" || entry.Msg != DenyMessage {
				t.Errorf("runc log entry = %+v, want level error and msg %q", entry, DenyMessage)
			}
		})
	}
}

// An unwritable --log path must not turn a denial into anything else.
func TestDenialSurvivesAnUnwritableLog(t *testing.T) {
	rec := &recorder{}
	var stderr bytes.Buffer
	code := lockedWrapper(rec, &stderr).Run([]string{
		"c8s-runc", "--log", filepath.Join(t.TempDir(), "missing-dir", "runc.log"), "exec", "ctr",
	})
	if code != exitDenied {
		t.Errorf("Run(exec) with an unwritable log = %d, want %d", code, exitDenied)
	}
	if rec.called {
		t.Error("an unwritable log let exec through")
	}
}
