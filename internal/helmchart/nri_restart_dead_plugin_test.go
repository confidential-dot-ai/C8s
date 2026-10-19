package helmchart

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// deadPluginFixture runs the baked pins script (which ends in the same
// restartAndWait tail as the full installer) against stubs: the c8s binary,
// nsenter and curl are replaced, and /host is a temp dir.
type deadPluginFixture struct {
	script     string
	root       string
	log        string
	runtimeDir string
	// healthAnswers makes the pre-restart health-socket probe succeed.
	healthAnswers bool
}

func newDeadPluginFixture(t *testing.T) *deadPluginFixture {
	t.Helper()
	out, err := helmTemplate(t, "--set", "nriImagePolicy.baked=true")
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, out)
	}
	ds := renderedDaemonSet(t, out, "c8s-nri-image-policy-worker")
	script := containerArgs(t, &ds, "install")[0]

	dir := t.TempDir()
	f := &deadPluginFixture{
		script: filepath.Join(dir, "pins.sh"),
		root:   filepath.Join(dir, "host"),
		log:    filepath.Join(dir, "calls.log"),
	}
	f.runtimeDir = filepath.Join(f.root, "run/nri-image-policy")
	if err := os.MkdirAll(f.runtimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := func(name, body string) {
		s := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >> '" + f.log + "'\n" + body + "\n"
		if err := os.WriteFile(filepath.Join(bin, name), []byte(s), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	stub("c8s", `case "$2" in
set-cds-pins) echo "$PINS_RESULT" ;;
plugin-ready) exit "$PLUGIN_CHECK_RC" ;;
esac`)
	stub("nsenter", "exit 0")
	// The pre-restart guard is the one curl that discards its output; the
	// post-restart health wait always succeeds.
	stub("curl", `case "$*" in *"--output /dev/null"*) exit "$HEALTH_GUARD_RC" ;; esac
printf 'ok [http 200]'`)
	stub("sleep", "exit 0")

	script = strings.ReplaceAll(script, "/usr/local/bin/c8s", filepath.Join(bin, "c8s"))
	script = strings.ReplaceAll(script, `"/host/`, `"`+f.root+"/")
	if err := os.WriteFile(f.script, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/bin:/usr/bin")
	return f
}

func (f *deadPluginFixture) run(t *testing.T, pins string, checkRC int) (string, []string) {
	t.Helper()
	_ = os.Remove(f.log)
	cmd := exec.Command("/bin/sh", f.script)
	guardRC := 7 // curl: nothing listening on the socket
	if f.healthAnswers {
		guardRC = 0
	}
	cmd.Env = append(os.Environ(), "PINS_RESULT="+pins, fmt.Sprintf("PLUGIN_CHECK_RC=%d", checkRC), fmt.Sprintf("HEALTH_GUARD_RC=%d", guardRC))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("script failed: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(f.log)
	return string(out), strings.Split(strings.TrimSpace(string(data)), "\n")
}

func calledWith(calls []string, prefix string) bool {
	for _, c := range calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// A node whose plugin already died would hold the installer's rollout on
// plugin-ready forever if the installer only restarted containerd on a file
// change (#683). It restarts for a missing plugin as well, at most once per
// window, so a plugin that keeps dying does not bounce containerd on every
// init retry.
func TestChartNriInstallerRestartsForDeadPlugin(t *testing.T) {
	f := newDeadPluginFixture(t)
	stamp := filepath.Join(f.runtimeDir, "dead-plugin-restart")

	// Plugin alive, nothing changed: no restart.
	_, calls := f.run(t, "unchanged", 0)
	if !calledWith(calls, "c8s nri-image-policy plugin-ready --check --plugin-path=/opt/nri/plugins/10-nri-image-policy") {
		t.Errorf("script did not check for the plugin process; calls %q", calls)
	}
	if calledWith(calls, "nsenter") {
		t.Errorf("restarted containerd with the plugin alive; calls %q", calls)
	}

	// Pins changed: the restart is already due, the check is skipped.
	_, calls = f.run(t, "updated", 1)
	if !calledWith(calls, "nsenter") || calledWith(calls, "c8s nri-image-policy plugin-ready") {
		t.Errorf("pins update: calls %q, want a restart without the plugin check", calls)
	}
	if _, err := os.Stat(stamp); err == nil {
		t.Error("a pins restart wrote the dead-plugin stamp")
	}

	// Plugin dead: restart once and stamp it.
	out, calls := f.run(t, "unchanged", 1)
	if !calledWith(calls, "nsenter") {
		t.Fatalf("dead plugin did not restart containerd; calls %q\n%s", calls, out)
	}
	if _, err := os.Stat(stamp); err != nil {
		t.Fatalf("no stamp after the dead-plugin restart: %v", err)
	}

	// Dead again within the window: no second restart.
	out, calls = f.run(t, "unchanged", 1)
	if calledWith(calls, "nsenter") {
		t.Errorf("restarted containerd twice within the window; calls %q", calls)
	}
	if !strings.Contains(out, "not again within 600s") {
		t.Errorf("no explanation for the skipped restart:\n%s", out)
	}

	// Past the window, or with a garbled stamp: restart again.
	for _, content := range []string{fmt.Sprint(time.Now().Add(-11 * time.Minute).Unix()), "garbage"} {
		if err := os.WriteFile(stamp, []byte(content+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, calls := f.run(t, "unchanged", 1); !calledWith(calls, "nsenter") {
			t.Errorf("stamp %q: no restart; calls %q", content, calls)
		}
	}
}

// The process check can misread a process tree it was not written for. When
// the plugin's own health socket still answers, the installer must not restart
// the runtime (on RKE2, the whole rke2 unit) on the check's word alone.
func TestChartNriInstallerTrustsHealthSocketOverProcessCheck(t *testing.T) {
	f := newDeadPluginFixture(t)
	f.healthAnswers = true
	out, calls := f.run(t, "unchanged", 1)
	if calledWith(calls, "nsenter") {
		t.Errorf("restarted containerd while the health socket answered; calls %q", calls)
	}
	if !calledWith(calls, "curl --unix-socket "+f.root+"/run/nri-image-policy/health.sock") {
		t.Errorf("did not probe the health socket before restarting; calls %q", calls)
	}
	if !strings.Contains(out, "not restarting") {
		t.Errorf("no warning for the disagreement:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(f.runtimeDir, "dead-plugin-restart")); err == nil {
		t.Error("stamped a restart that did not happen")
	}
}
