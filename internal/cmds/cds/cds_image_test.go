package cds

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The CDS image runs this unit, and every setting it does not spell out is a
// binary default. Parse it with the real command so the baked arguments and
// what `c8s cds` accepts cannot drift apart.
const (
	cdsImageService = "../../../images/cds-guest/cds/mkosi.extra/etc/systemd/system/cds.service"
	cdsImageDropIns = cdsImageService + ".d/*.conf"
)

func TestCDSImageServiceArguments(t *testing.T) {
	args := readCDSImageExecStart(t)

	command := NewCmd()
	if err := command.ParseFlags(args); err != nil {
		t.Fatalf("parse the baked ExecStart flags: %v", err)
	}
	if err := command.ValidateRequiredFlags(); err != nil {
		t.Errorf("baked ExecStart omits a required flag: %v", err)
	}
	// Covers every flag --config excludes (excludedByConfig), so the unit
	// cannot carry a setting the measured configuration decides.
	if err := command.ValidateFlagGroups(); err != nil {
		t.Errorf("baked ExecStart breaks a flag group: %v", err)
	}
	if path, _ := command.Flags().GetString("config"); path == "" {
		t.Error("the unit must run CDS from its measured configuration (--config)")
	}
	api, _ := command.Flags().GetString("attestation-api-url")
	if err := requireLoopbackAttestationAPI(api); err != nil {
		t.Errorf("baked attestation API: %v", err)
	}

	// The exclusions bite: each one, given alongside the unit's own --config,
	// must fail validation. Flag groups are checked against Changed, so
	// marking the flag as given needs no per-type value.
	for _, excluded := range excludedByConfig {
		command := NewCmd()
		if err := command.ParseFlags(args); err != nil {
			t.Fatalf("parse the baked ExecStart flags: %v", err)
		}
		flag := command.Flags().Lookup(excluded)
		if flag == nil {
			t.Errorf("--%s is excluded by --config but is not a flag", excluded)
			continue
		}
		flag.Changed = true
		if err := command.ValidateFlagGroups(); err == nil {
			t.Errorf("--%s alongside the unit's --config is accepted", excluded)
		}
	}
}

// readCDSImageExecStart returns the unit's single ExecStart arguments, without
// the binary and the subcommand.
func readCDSImageExecStart(t *testing.T) []string {
	t.Helper()
	unit, err := os.ReadFile(filepath.Clean(cdsImageService))
	if err != nil {
		t.Fatalf("read the CDS image service: %v", err)
	}
	// systemd continues a line only on a bare trailing backslash; one followed
	// by whitespace makes the next line a bogus directive and the unit fails
	// to load. Reject it rather than parsing a truncated ExecStart.
	if regexp.MustCompile(`\\[ \t]+\n`).Match(unit) {
		t.Fatal("cds.service has a backslash followed by whitespace: not a systemd continuation")
	}
	joined := strings.ReplaceAll(string(unit), "\\\n", " ")
	if n := strings.Count(joined, "\nExecStart="); n != 1 {
		t.Fatalf("ExecStart directive count = %d, want exactly 1", n)
	}
	_, rest, _ := strings.Cut(joined, "\nExecStart=")
	execStart, _, _ := strings.Cut(rest, "\n")
	args := strings.Fields(execStart)
	if len(args) < 2 || args[0] != "/usr/local/bin/c8s" || args[1] != "cds" {
		t.Fatalf("ExecStart = %q, want /usr/local/bin/c8s cds ...", execStart)
	}
	for _, arg := range args {
		if strings.Contains(arg, "$") {
			t.Errorf("ExecStart argument %q expands the environment", arg)
		}
	}
	// A drop-in could reset ExecStart or add an Environment this test never
	// sees; the image bakes none.
	dropIns, err := filepath.Glob(cdsImageDropIns)
	if err != nil {
		t.Fatal(err)
	}
	if len(dropIns) > 0 {
		t.Errorf("the CDS image bakes unit drop-ins this test does not read: %v", dropIns)
	}
	return args[2:]
}
