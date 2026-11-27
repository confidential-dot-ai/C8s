package ta

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The Trust Authority image runs this unit, and every setting it does not spell out is a
// binary default. Parse it with the real command so the baked arguments and
// what `c8s ta` accepts cannot drift apart.
const (
	taImageService = "../../../images/ta-guest/ta/mkosi.extra/etc/systemd/system/ta.service"
	taImageDropIns = taImageService + ".d/*.conf"
)

func TestTAImageServiceArguments(t *testing.T) {
	args := readTAImageExecStart(t)

	command := NewCmd()
	if err := command.ParseFlags(args); err != nil {
		t.Fatalf("parse the baked ExecStart flags: %v", err)
	}
	if err := command.ValidateRequiredFlags(); err != nil {
		t.Errorf("baked ExecStart omits a required flag: %v", err)
	}
	api, _ := command.Flags().GetString("attestation-api-url")
	if err := requireLoopbackAttestationAPI(api); err != nil {
		t.Errorf("baked attestation API: %v", err)
	}
}

// readTAImageExecStart returns the unit's single ExecStart arguments, without
// the binary and the subcommand.
func readTAImageExecStart(t *testing.T) []string {
	t.Helper()
	unit, err := os.ReadFile(filepath.Clean(taImageService))
	if err != nil {
		t.Fatalf("read the Trust Authority image service: %v", err)
	}
	// systemd continues a line only on a bare trailing backslash; one followed
	// by whitespace makes the next line a bogus directive and the unit fails
	// to load. Reject it rather than parsing a truncated ExecStart.
	if regexp.MustCompile(`\\[ \t]+\n`).Match(unit) {
		t.Fatal("ta.service has a backslash followed by whitespace: not a systemd continuation")
	}
	joined := strings.ReplaceAll(string(unit), "\\\n", " ")
	if n := strings.Count(joined, "\nExecStart="); n != 1 {
		t.Fatalf("ExecStart directive count = %d, want exactly 1", n)
	}
	_, rest, _ := strings.Cut(joined, "\nExecStart=")
	execStart, _, _ := strings.Cut(rest, "\n")
	args := strings.Fields(execStart)
	if len(args) < 2 || args[0] != "/usr/local/bin/c8s" || args[1] != "ta" {
		t.Fatalf("ExecStart = %q, want /usr/local/bin/c8s ta ...", execStart)
	}
	for _, arg := range args {
		if strings.Contains(arg, "$") {
			t.Errorf("ExecStart argument %q expands the environment", arg)
		}
	}
	// A drop-in could reset ExecStart or add an Environment this test never
	// sees; the image bakes none.
	dropIns, err := filepath.Glob(taImageDropIns)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropIns) > 0 {
		t.Errorf("the Trust Authority image bakes unit drop-ins this test does not read: %v", dropIns)
	}
	return args[2:]
}
