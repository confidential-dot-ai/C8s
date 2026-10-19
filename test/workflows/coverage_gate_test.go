package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCoverageGateMeasuresGoExecution(t *testing.T) {
	script, err := filepath.Abs("../../scripts/coverage-gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	// Go tracks this read so script-only changes invalidate cached test results.
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOWORK", "auto")
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOSUMDB", "off")
	for _, name := range []string{"coverage includes test-only callers and untested code", "production test fails", "invalid module", "package discovery fails"} {
		t.Run(name, func(t *testing.T) {
			fixture := t.TempDir()
			files := map[string]string{
				"go.mod":              "module fixture.invalid/coverage\n\ngo 1.22\n",
				"go.work":             "go 1.22\nuse (\n .\n ./other-module\n)\n",
				"other-module/go.mod": "module fixture.invalid/other\n\ngo 1.22\n",
				"production/value.go": `package production
func Direct() int { return 1 }
func ViaHarness() int { return 2 }
`,
				"production/value_test.go": `package production
import "testing"
func TestDirect(t *testing.T) { if Direct() != 1 { t.Fatal("wrong result") } }
`,
				"test/goharness/value_test.go": `package goharness
import (
    "testing"
    "fixture.invalid/coverage/production"
)
func TestViaHarness(t *testing.T) { if production.ViaHarness() != 2 { t.Fatal("wrong result") } }
`,
				"untested/value.go": `package untested
func First() int { return 3 }
func Second() int { return 4 }
`,
				"test/workflows/fail_test.go": `package workflows
import "testing"
func TestWorkflow(t *testing.T) { t.Fatal("workflow harness intentionally fails") }
`,
			}
			switch name {
			case "production test fails":
				files["production/fail_test.go"] = "package production\nimport \"testing\"\nfunc TestFailure(t *testing.T) { t.Fatal(\"production failure sentinel\") }\n"
			case "invalid module":
				files["go.mod"] = "module fixture.invalid/coverage\n\ngo invalid\n"
			case "package discovery fails":
				files["broken/first.go"] = "package first\n"
				files["broken/second.go"] = "package second\n"
			}
			for path, contents := range files {
				path = filepath.Join(fixture, path)
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
			defer cancel()
			profile := filepath.Join(fixture, "coverage output.out")
			cmd := exec.CommandContext(ctx, "bash", "-c", string(body), script, "run", profile)
			cmd.Dir = fixture
			log, err := cmd.CombinedOutput()
			if name != "coverage includes test-only callers and untested code" {
				if err == nil {
					t.Fatalf("coverage suppressed a Go failure: %s", log)
				}
				if name == "production test fails" && !strings.Contains(string(log), "production failure sentinel") {
					t.Fatalf("coverage failed before reaching the production test: %s", log)
				}
				return
			}
			if err != nil {
				t.Fatalf("coverage executed the unrelated workflow harness: %v\n%s", err, log)
			}
			raw, err := os.ReadFile(profile)
			if err != nil {
				t.Fatal(err)
			}
			blocks := make(map[string]int)
			coveredBlocks := make(map[string]bool)
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n")[1:] {
				fields := strings.Fields(line)
				if len(fields) != 3 {
					t.Fatalf("invalid coverage record: %q", line)
				}
				count, err := strconv.Atoi(fields[1])
				if err != nil {
					t.Fatal(err)
				}
				blocks[fields[0]] = count
				if fields[2] != "0" {
					coveredBlocks[fields[0]] = true
				}
			}
			// -coverpkg emits the same blocks from multiple test binaries.
			// Union their covered blocks, just as the production total does.
			var statements, covered, untested int
			for block, count := range blocks {
				statements += count
				if coveredBlocks[block] {
					covered += count
				}
				if strings.HasPrefix(block, "fixture.invalid/coverage/untested/") {
					untested += count
					if coveredBlocks[block] {
						t.Fatalf("untested production code was reported covered: %q", block)
					}
				}
			}
			// Direct and ViaHarness must both count; two untested statements
			// remain in the denominator despite having no importing tests.
			if statements != 4 || covered != 2 || untested != 2 {
				t.Fatalf("wrong coverage scope: statements=%d covered=%d untested=%d\n%s", statements, covered, untested, raw)
			}
			cmd = exec.CommandContext(ctx, "go", "test", "./test/workflows", "-count=1")
			cmd.Dir = fixture
			log, err = cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(log), "workflow harness intentionally fails") {
				t.Fatalf("fixture workflow harness should still fail a normal test run: err=%v log=%s", err, log)
			}
		})
	}
}

func TestKernelCoverageMergesProfilesAndPropagatesFailure(t *testing.T) {
	script, err := filepath.Abs("../../scripts/coverage-gate.sh")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	const header = "mode: set\n"
	const blocks = "fixture/a.go:1.1,1.2 1 0\nfixture/a.go:2.1,2.2 1 1\nfixture/a.go:3.1,3.2 1 0\nfixture/untested.go:1.1,1.2 1 0\n"
	for _, name := range []string{"older base without harness", "kernel failure", "no profile", "no fs-verity profile", "merged profiles"} {
		t.Run(name, func(t *testing.T) {
			fixture := t.TempDir()
			files := map[string]string{
				"head.out": header + blocks,
				"fs.out":   header + "fixture/a.go:1.1,1.2 1 1\nfixture/a.go:2.1,2.2 1 0\n",
				"dm.out":   header + "fixture/a.go:1.1,1.2 1 0\nfixture/a.go:3.1,3.2 1 1\nfixture/untested.go:1.1,1.2 1 0\n",
				"bin/go":   "#!/bin/sh\nprintf '%s\\n' \"$@\" > build.args\n",
				"bin/sudo": `#!/bin/sh
if [ "$C8S_TEST_KERNEL_FAIL" = yes ]; then
 echo "kernel failure sentinel" >&2
 exit 17
fi
[ "$1" = -n ] && shift
exec "$@"
`,
				// The script's own harness takes the coverage directory.
				"head/scripts/coverage-gate.sh": string(body),
				"head/node-guest-image/tests/mount-verity-test.sh": `cp fs.out "$2/fs-verity.out"
cp dm.out "$2/dm-verity.out"
`,
			}
			switch name {
			case "no profile":
				files["head/node-guest-image/tests/mount-verity-test.sh"] = "exit 0\n"
			case "no fs-verity profile":
				files["head/node-guest-image/tests/mount-verity-test.sh"] = `cp dm.out "$2/dm-verity.out"` + "\n"
			}
			if name != "older base without harness" {
				// The checked-out base revision's harness takes one argument.
				files["node-guest-image/tests/mount-verity-test.sh"] = "[ $# = 1 ] || { echo 'usage: one-argument harness' >&2; exit 1; }\n"
			}
			for path, contents := range files {
				full := filepath.Join(fixture, path)
				if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(contents), 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", filepath.Join(fixture, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("C8S_TEST_KERNEL_FAIL", "no")
			if name == "kernel failure" {
				t.Setenv("C8S_TEST_KERNEL_FAIL", "yes")
			}
			cmd := exec.CommandContext(t.Context(), "bash", "-c", string(body), filepath.Join(fixture, "head/scripts/coverage-gate.sh"), "kernel", "head.out")
			cmd.Dir = fixture
			log, err := cmd.CombinedOutput()
			raw, readErr := os.ReadFile(filepath.Join(fixture, "head.out"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if name == "kernel failure" {
				if err == nil || !strings.Contains(string(log), "kernel failure sentinel") {
					t.Fatalf("lost kernel failure: %v\n%s", err, log)
				}
				if string(raw) != header+blocks {
					t.Fatal("failed kernel run changed coverage")
				}
				return
			}
			if name == "no profile" || name == "no fs-verity profile" {
				if err == nil || !strings.Contains(string(log), "kernel harness produced no fs-verity profile") {
					t.Fatalf("accepted a kernel run without every profile: %v\n%s", err, log)
				}
				if string(raw) != header+blocks {
					t.Fatal("incomplete kernel run changed coverage")
				}
				return
			}
			if err != nil {
				t.Fatalf("kernel coverage: %v\n%s", err, log)
			}
			if name == "older base without harness" {
				if string(raw) != header+blocks {
					t.Fatal("invented coverage for old base")
				}
				if _, err := os.Stat(filepath.Join(fixture, "build.args")); !os.IsNotExist(err) {
					t.Fatal("built absent kernel harness")
				}
				return
			}
			args, err := os.ReadFile(filepath.Join(fixture, "build.args"))
			if err != nil || !strings.Contains(string(args), "-coverpkg=./...") {
				t.Fatalf("kernel binary not instrumented across production packages: %s %v", args, err)
			}
			if strings.Count(string(raw), "mode: set") != 1 {
				t.Fatal("merged profile has multiple headers")
			}
			cmd = exec.CommandContext(t.Context(), "bash", "-c", string(body), script, "total", "head.out")
			cmd.Dir = fixture
			total, err := cmd.CombinedOutput()
			// Three of four distinct statements ran. Duplicate uncovered records must
			// not erase ordinary coverage, and untested production stays in the total.
			if err != nil || strings.TrimSpace(string(total)) != "75.00" {
				t.Fatalf("wrong profile union: %q %v", total, err)
			}
		})
	}
}
