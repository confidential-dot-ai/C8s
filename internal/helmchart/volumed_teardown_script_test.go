//go:build !c8s_node

package helmchart

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The teardown script is the pre-delete hook's whole body and had no test that
// ran it: the chart tests only grep the rendered args for the command names.
// That is how a swallowed close failure shipped, so these run the shipped bytes
// against a fixture tree.

const teardownScriptPath = ChartRoot + "/files/scripts/volumed-teardown.sh"

type teardownFixture struct {
	root   string
	script string
	log    string
}

// newTeardownFixture lays out $root/proc/mounts and $root/dev/mapper for the
// named mappings, and stubs every host tool the script calls onto PATH. Each
// stub logs its argv; closeBody is spliced into veritysetup and cryptsetup so a
// case can decide which closes succeed.
func newTeardownFixture(t *testing.T, mappings []string, mounted []string, closeBody string) *teardownFixture {
	t.Helper()
	dir := t.TempDir()
	f := &teardownFixture{
		root:   filepath.Join(dir, "root"),
		script: filepath.Join(dir, "teardown.sh"),
		log:    filepath.Join(dir, "calls.log"),
	}

	body, err := ChartFS.ReadFile(teardownScriptPath)
	if err != nil {
		t.Fatalf("read %s from the chart: %v", teardownScriptPath, err)
	}
	if err := os.WriteFile(f.script, body, 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	mapper := filepath.Join(f.root, "dev", "mapper")
	if err := os.MkdirAll(mapper, 0o755); err != nil {
		t.Fatalf("mkdir mapper: %v", err)
	}
	for _, name := range mappings {
		if err := os.WriteFile(filepath.Join(mapper, name), nil, 0o644); err != nil {
			t.Fatalf("create mapping %s: %v", name, err)
		}
	}
	proc := filepath.Join(f.root, "proc")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatalf("mkdir proc: %v", err)
	}
	var mounts strings.Builder
	// One unrelated line so the source filter is exercised, not just the shape.
	mounts.WriteString("/dev/sda1 / ext4 rw 0 0\n")
	for i, name := range mounted {
		mounts.WriteString("/dev/mapper/" + name + " /var/lib/kubelet/pods/p" + string(rune('a'+i)) + "/vol ext4 ro 0 0\n")
	}
	if err := os.WriteFile(filepath.Join(proc, "mounts"), []byte(mounts.String()), 0o644); err != nil {
		t.Fatalf("write mounts: %v", err)
	}

	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	stub := func(name, extra string) {
		script := "#!/bin/sh\nprintf '%s\\n' \"" + name + " $*\" >> '" + f.log + "'\n" + extra + "\nexit 0\n"
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write %s stub: %v", name, err)
		}
	}
	stub("umount", "")
	// A no-op sleep keeps the retry budget free: the delay is the script's, not
	// the test's.
	stub("sleep", "")
	stub("veritysetup", closeBody)
	stub("cryptsetup", closeBody)
	t.Setenv("PATH", binDir+":/bin:/usr/bin")
	return f
}

// run executes the script and returns its combined output and exit code.
func (f *teardownFixture) run(t *testing.T) (string, int) {
	t.Helper()
	cmd := exec.Command("/bin/sh", f.script)
	cmd.Env = append(os.Environ(), "C8S_TEARDOWN_ROOT="+f.root)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run teardown: %v", err)
	}
	return string(out), code
}

func (f *teardownFixture) calls(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(f.log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read call log: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestVolumedTeardownClosesCleanly(t *testing.T) {
	f := newTeardownFixture(t,
		[]string{"c8s-verity-podA-data", "c8s-crypt-podA-data"},
		[]string{"c8s-verity-podA-data"},
		"")
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d on a node whose mappings all close; output:\n%s", code, out)
	}
	if !strings.Contains(out, "2 mapping(s) closed") {
		t.Errorf("did not report both closes:\n%s", out)
	}
	calls := f.calls(t)
	var verityAt, cryptAt = -1, -1
	for i, c := range calls {
		switch {
		case strings.HasPrefix(c, "veritysetup close"):
			verityAt = i
		case strings.HasPrefix(c, "cryptsetup close"):
			cryptAt = i
		}
	}
	if verityAt < 0 || cryptAt < 0 {
		t.Fatalf("both closes must be attempted; calls: %v", calls)
	}
	// verity is stacked on crypt and holds it open, so the order is load-bearing.
	if verityAt > cryptAt {
		t.Errorf("crypt closed before the verity device stacked on it; calls: %v", calls)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "umount /var/lib/kubelet/pods/pa/vol") {
		t.Errorf("the mounted verity device was not unmounted; calls: %v", calls)
	}
}

// A mutable volume's mount source is the crypt device itself — there is no
// verity layer — so the unmount scan must match it too, or uninstall leaves
// the mapping holding the backing disk open.
func TestVolumedTeardownUnmountsAMutableMount(t *testing.T) {
	f := newTeardownFixture(t,
		[]string{"c8s-crypt-podA-data"},
		[]string{"c8s-crypt-podA-data"},
		"")
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d on a node whose mappings all close; output:\n%s", code, out)
	}
	calls := strings.Join(f.calls(t), "\n")
	if !strings.Contains(calls, "umount /var/lib/kubelet/pods/pa/vol") {
		t.Errorf("the mounted crypt device was not unmounted; calls: %v", calls)
	}
	if !strings.Contains(calls, "cryptsetup close c8s-crypt-podA-data") {
		t.Errorf("the crypt mapping was not closed; calls: %v", calls)
	}
}

func TestVolumedTeardownIsIdempotentOnAnEmptyNode(t *testing.T) {
	f := newTeardownFixture(t, nil, nil, "")
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d with nothing open; output:\n%s", code, out)
	}
	if !strings.Contains(out, "0 mapping(s) closed") {
		t.Errorf("expected a clean no-op:\n%s", out)
	}
	for _, c := range f.calls(t) {
		if strings.Contains(c, "close") {
			t.Errorf("closed something on an empty node: %q", c)
		}
	}
}

// The reported defect: the close sits inside an `if`, so `set -eu` never fires,
// the script warns and exits 0, helm sees a healthy hook and deletes the
// release — after which volumed is gone and nothing on the node can reap these.
func TestVolumedTeardownFailsWhenAMappingStaysOpen(t *testing.T) {
	f := newTeardownFixture(t,
		[]string{"c8s-verity-podA-data", "c8s-crypt-podA-data"},
		[]string{"c8s-verity-podA-data"},
		`case "$1 $2" in "close c8s-verity-podA-data") exit 1 ;; esac`)
	out, code := f.run(t)
	if code == 0 {
		t.Fatalf("exit 0 while a mapping stayed open; a leaking uninstall must not report success:\n%s", out)
	}
	if !strings.Contains(out, "c8s-verity-podA-data") {
		t.Errorf("failure does not name the mapping that stayed open:\n%s", out)
	}
	if !strings.Contains(out, "re-run the uninstall") {
		t.Errorf("failure does not say how to get the node clean:\n%s", out)
	}
}

// A device busy on the first try is often free once kubelet finishes tearing
// the consumer's mount down, so the close is retried before it is called stuck.
func TestVolumedTeardownRetriesABusyClose(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "attempts")
	f := newTeardownFixture(t,
		[]string{"c8s-crypt-podA-data"},
		nil,
		`n=$(cat '`+marker+`' 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > '`+marker+`'
if [ "$n" -lt 3 ]; then exit 1; fi`)
	out, code := f.run(t)
	if code != 0 {
		t.Fatalf("exit %d though the close succeeded on the third attempt; output:\n%s", code, out)
	}
	if !strings.Contains(out, "1 mapping(s) closed") {
		t.Errorf("retry did not report the eventual close:\n%s", out)
	}
	attempts := 0
	for _, c := range f.calls(t) {
		if strings.HasPrefix(c, "cryptsetup close") {
			attempts++
		}
	}
	if attempts != 3 {
		t.Errorf("close attempted %d times, want 3 (retry stops as soon as it succeeds)", attempts)
	}
}
