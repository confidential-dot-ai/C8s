package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivilegedCoverageUsesHeadSelectorAndPreservesFailures(t *testing.T) {
	scripts := make(map[string]string)
	for _, name := range []string{"coverage-gate.sh", "test-podmesh.sh"} {
		body, err := os.ReadFile(filepath.Join("../../scripts", name))
		if err != nil {
			t.Fatal(err)
		}
		scripts[name] = string(body)
	}
	t.Setenv("GOWORK", "off")
	for _, mode := range []string{"merged profiles", "test failure", "no profile"} {
		t.Run(mode, func(t *testing.T) {
			fixture := t.TempDir()
			const ordinary = "mode: set\nfixture/ordinary.go:1.1,1.2 1 1\nfixture/untested.go:1.1,1.2 1 0\n"
			files := map[string]string{
				"base/go.mod":                   "module fixture.invalid/privileged\n\ngo 1.22\n",
				"base/coverage.out":             ordinary,
				"base/scripts/test-podmesh.sh":  "echo 'used obsolete base selector' >&2; exit 99\n",
				"head/scripts/coverage-gate.sh": scripts["coverage-gate.sh"],
				"head/scripts/test-podmesh.sh":  scripts["test-podmesh.sh"],
				"bin/sudo":                      "#!/bin/sh\n[ \"$1\" = -n ] && shift\nexec \"$@\"\n",
			}
			selected := map[string]string{
				"internal/podmesh/ruleset":       "TestRulesInTheNamespace",
				"internal/cmds/nri-image-policy": "TestNodeImagePodRoleConfig_StartsAndRetainsServedPolicy",
				"internal/cmds/armtlsmesh":       "TestTransportInTheNamespace",
				"internal/cmds/getcert":          "TestGuestRootPublication",
			}
			for pkg, name := range selected {
				files["base/"+pkg+"/value.go"] = "package fixture\nfunc Value() int { return 1 }\n"
				files["base/"+pkg+"/value_test.go"] = `package fixture
import ("os"; "testing")
func ` + name + `(t *testing.T) {
 if os.Getenv("C8S_REQUIRE_NFT") != "1" { t.Fatal("missing required namespace environment") }
 if os.Getenv("C8S_FIXTURE_FAIL") == "yes" { t.Fatal("privileged failure sentinel") }
 if Value() != 1 { t.Fatal("wrong production result") }
}
func TestUnrelated(t *testing.T) { t.Fatal("selected an unrelated test") }
`
			}
			if mode == "no profile" {
				files["bin/go"] = "#!/bin/sh\nexit 0\n"
			}
			for path, body := range files {
				full := filepath.Join(fixture, path)
				if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", filepath.Join(fixture, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("C8S_FIXTURE_FAIL", "no")
			if mode == "test failure" {
				t.Setenv("C8S_FIXTURE_FAIL", "yes")
			}
			gate := filepath.Join(fixture, "head/scripts/coverage-gate.sh")
			cmd := exec.CommandContext(t.Context(), "bash", gate, "privileged", "coverage.out")
			cmd.Dir = filepath.Join(fixture, "base")
			log, runErr := cmd.CombinedOutput()
			raw, err := os.ReadFile(filepath.Join(cmd.Dir, "coverage.out"))
			if err != nil {
				t.Fatal(err)
			}
			if mode != "merged profiles" {
				want := "privileged tests produced no profile"
				if mode == "test failure" {
					want = "privileged failure sentinel"
				}
				if runErr == nil || !strings.Contains(string(log), want) || string(raw) != ordinary {
					t.Fatalf("failed measurement changed profile or hid failure: %v\n%s\n%s", runErr, log, raw)
				}
				return
			}
			if runErr != nil || strings.Count(string(raw), "mode: set") != 1 {
				t.Fatalf("privileged measurement failed: %v\n%s", runErr, log)
			}
			cmd = exec.CommandContext(t.Context(), "bash", gate, "total", "coverage.out")
			cmd.Dir = filepath.Join(fixture, "base")
			total, err := cmd.CombinedOutput()
			// Four executed production statements plus the covered ordinary block;
			// the untested ordinary block must remain in the denominator.
			if err != nil || strings.TrimSpace(string(total)) != "83.33" {
				t.Fatalf("wrong profile union: %q %v", total, err)
			}
		})
	}
}
