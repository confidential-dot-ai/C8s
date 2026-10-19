package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The harness must enter its own mount namespace before changing mount
// propagation, even when it already runs outside the init namespace.
func TestVerityHarnessAlwaysEntersPrivateNamespace(t *testing.T) {
	script, err := filepath.Abs("../../node-guest-image/tests/mount-verity-test.sh")
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	for name, body := range map[string]string{
		"id":      "#!/bin/sh\necho 0\n",
		"unshare": "#!/bin/sh\necho \"$C8S_VERITY_NS $*\" > \"$FIXTURE/unshare.args\"\n",
		"mount":   "#!/bin/sh\necho \"$*\" >> \"$FIXTURE/mount.args\"\nexit 1\n",
	} {
		if err := os.WriteFile(filepath.Join(fixture, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.CommandContext(t.Context(), "bash", script, "/bin/true")
	cmd.Env = append(os.Environ(), "PATH="+fixture+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+fixture, "C8S_VERITY_NS=")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("harness: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(fixture, "mount.args")); !os.IsNotExist(err) {
		t.Fatal("harness changed mounts before entering a private namespace")
	}
	args, err := os.ReadFile(filepath.Join(fixture, "unshare.args"))
	if err != nil || !strings.HasPrefix(string(args), "1 --mount bash "+script) {
		t.Fatalf("unshare args = %q, %v, want a sentinel re-exec", args, err)
	}
}
