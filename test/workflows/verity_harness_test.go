package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The harness must enter its own mount namespace before changing mount
// propagation, even when it already runs outside the init namespace or its
// caller's environment carries the old sentinel variable. Only its own re-exec
// argument skips that step.
func TestVerityHarnessAlwaysEntersPrivateNamespace(t *testing.T) {
	script, err := filepath.Abs("../../images/node-guest/tests/mount-verity-test.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		args       []string
		reexecuted bool
	}{
		{"caller", []string{"/bin/true"}, false},
		{"re-exec", []string{"--private-mount-namespace", "/bin/true"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := t.TempDir()
			for name, body := range map[string]string{
				"id":          "#!/bin/sh\necho 0\n",
				"unshare":     "#!/bin/sh\necho \"$*\" > \"$FIXTURE/unshare.args\"\n",
				"mount":       "#!/bin/sh\necho \"$*\" >> \"$FIXTURE/mount.args\"\nexit 1\n",
				"umount":      "#!/bin/sh\nexit 1\n",
				"veritysetup": "#!/bin/sh\nexit 1\n",
			} {
				if err := os.WriteFile(filepath.Join(fixture, name), []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.CommandContext(t.Context(), "bash", append([]string{script}, tc.args...)...)
			cmd.Env = append(os.Environ(), "PATH="+fixture+string(os.PathListSeparator)+os.Getenv("PATH"), "FIXTURE="+fixture, "C8S_VERITY_NS=1")
			out, err := cmd.CombinedOutput()
			// The mount stub fails, so a harness that reaches it exits non-zero.
			if (err != nil) != tc.reexecuted {
				t.Fatalf("harness(%s) = %v, want failure %t\n%s", tc.name, err, tc.reexecuted, out)
			}
			unshare, unshareErr := os.ReadFile(filepath.Join(fixture, "unshare.args"))
			mounts, mountErr := os.ReadFile(filepath.Join(fixture, "mount.args"))
			if tc.reexecuted {
				if !os.IsNotExist(unshareErr) {
					t.Fatalf("re-exec ran unshare again: %q, %v", unshare, unshareErr)
				}
				if mountErr != nil || !strings.HasPrefix(string(mounts), "--make-rprivate /") {
					t.Fatalf("mount args = %q, %v, want --make-rprivate / first", mounts, mountErr)
				}
				return
			}
			if !os.IsNotExist(mountErr) {
				t.Fatal("harness changed mounts before entering a private namespace")
			}
			if unshareErr != nil || !strings.HasPrefix(string(unshare), "--mount bash "+script+" --private-mount-namespace /bin/true") {
				t.Fatalf("unshare args = %q, %v, want a sentinel re-exec", unshare, unshareErr)
			}
		})
	}
}
