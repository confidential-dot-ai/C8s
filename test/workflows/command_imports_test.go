package workflows

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	repoPathPrefix = "github.com/confidential-dot-ai/c8s/"
	cobraPath      = "github.com/spf13/cobra"
	rulesFile      = "test/workflows/command_imports_test.go"

	outsideImportRule = "packages under internal/cmds/ are commands (flags, config and wiring), and outside tests only cmd/ and internal/cmds/ import them"
	mountImportRule   = "outside tests, a package under internal/cmds/ imports a command only to mount it as a subcommand"
	cobraImportRule   = "outside tests, only cmd/ and internal/cmds/ import " + cobraPath + ", so every command is filed under internal/cmds/"
)

// importRules is the command import rule and the imports it lets through.
// Every entry must match the tree.
type importRules struct {
	// librariesUnderCmds are packages under internal/cmds/ that are not
	// commands, so any command may import them.
	librariesUnderCmds []string
	subcommandMounts   []string
	knownDebt          []string
}

var commandImportRules = importRules{
	librariesUnderCmds: []string{
		"internal/cmds/cdsconn",
		"internal/cmds/cmdsutil",
		"internal/cmds/nodeservices",
		"internal/cmds/sidecar",
	},
	subcommandMounts: []string{
		"internal/cmds/cds imports internal/cmds/cdsca",
		"internal/cmds/cds imports internal/cmds/cdsha",
		"internal/cmds/cds imports internal/cmds/cdslaunch",
		"internal/cmds/cds imports internal/cmds/verify",
	},
	knownDebt: []string{
		"internal/cdschain imports internal/cmds/cmdsutil",
		"internal/cdsconfig imports internal/cmds/cmdsutil",
		"internal/controller imports internal/cmds/cmdsutil",
		"internal/podlaunch imports github.com/spf13/cobra",
		"internal/podlaunch imports internal/cmds/cmdsutil",
		"internal/podprovider imports internal/cmds/cmdsutil",
		"internal/podprovider imports internal/cmds/podstatus",
		"internal/webhook imports internal/cmds/volume",
		"internal/cmds/allowlist imports internal/cmds/cdsha",
		"internal/cmds/c8srunc imports internal/cmds/nri-image-policy",
		"internal/cmds/getvolume imports internal/cmds/volume",
		"internal/cmds/getvolume imports internal/cmds/volumed",
		"internal/cmds/nodeservices imports internal/cmds/nri-image-policy",
		"internal/cmds/nri-image-policy imports internal/cmds/getcert",
		"internal/cmds/nri-image-policy imports internal/cmds/volume",
		"internal/cmds/routes imports internal/cmds/cdsha",
		"internal/cmds/volumed imports internal/cmds/volume",
		"internal/cmds/worker imports internal/cmds/nri-image-policy",
	},
}

func TestCommandPackageImports(t *testing.T) {
	for _, problem := range commandImportRules.problems(nonTestImports(t)) {
		t.Error(problem)
	}
}

type packageImport struct {
	importer, imported string
}

func (i packageImport) String() string {
	return i.importer + " imports " + i.imported
}

// problems reports each import that breaks the rule and is not known debt,
// and each list entry that does not match the graph.
func (r importRules) problems(graph map[string][]string) []string {
	imports := importsIn(graph)
	problems := r.unlistedViolations(imports)
	problems = append(problems, unmatched("knownDebt", r.knownDebt, describeMatching(imports, r.breaksRule))...)
	problems = append(problems, unmatched("subcommandMounts", r.subcommandMounts, describeMatching(imports, r.importsCommandFromCmds))...)
	problems = append(problems, unmatched("librariesUnderCmds", r.librariesUnderCmds, packagesUnderCmds(graph))...)
	return problems
}

func (r importRules) unlistedViolations(imports []packageImport) []string {
	var failures []string
	for _, i := range imports {
		if failure := r.brokenRule(i); failure != "" && !slices.Contains(r.knownDebt, i.String()) {
			failures = append(failures, failure)
		}
	}
	return failures
}

func (r importRules) breaksRule(i packageImport) bool {
	return r.brokenRule(i) != ""
}

// brokenRule returns the failure for an import that breaks the rule, or "".
func (r importRules) brokenRule(i packageImport) string {
	switch {
	case importsCmdsFromOutside(i):
		return fmt.Sprintf("%s: %s. Move what %s uses into a package outside internal/cmds/ and import that.", i, outsideImportRule, i.importer)
	case r.importsCommandWithoutMounting(i):
		return fmt.Sprintf("%s: %s. Move what %s uses into a package outside internal/cmds/ and import that; if it mounts %s, add this import to subcommandMounts in %s.", i, mountImportRule, i.importer, i.imported, rulesFile)
	case importsCobraFromOutside(i):
		return fmt.Sprintf("%s: %s. Move the command into a package under internal/cmds/ named after its verb, leave %s a library, and mount the command from cmd/.", i, cobraImportRule, i.importer)
	}
	return ""
}

func importsCmdsFromOutside(i packageImport) bool {
	return underCmds(i.imported) && !underCmds(i.importer) && !isBinaryMain(i.importer)
}

func importsCobraFromOutside(i packageImport) bool {
	return i.imported == cobraPath && !underCmds(i.importer) && !isBinaryMain(i.importer)
}

func (r importRules) importsCommandWithoutMounting(i packageImport) bool {
	return r.importsCommandFromCmds(i) && !slices.Contains(r.subcommandMounts, i.String())
}

func (r importRules) importsCommandFromCmds(i packageImport) bool {
	return underCmds(i.importer) && r.isCommand(i.imported)
}

func (r importRules) isCommand(path string) bool {
	return underCmds(path) && !slices.Contains(r.librariesUnderCmds, path)
}

func underCmds(path string) bool {
	return strings.HasPrefix(path, "internal/cmds/")
}

func isBinaryMain(path string) bool {
	return strings.HasPrefix(path, "cmd/")
}

func packagesUnderCmds(graph map[string][]string) []string {
	var packages []string
	for path := range graph {
		if underCmds(path) {
			packages = append(packages, path)
		}
	}
	return packages
}

func describeMatching(imports []packageImport, matches func(packageImport) bool) []string {
	var descriptions []string
	for _, i := range imports {
		if matches(i) {
			descriptions = append(descriptions, i.String())
		}
	}
	return descriptions
}

func unmatched(list string, entries, inGraph []string) []string {
	var problems []string
	for _, entry := range entries {
		if !slices.Contains(inGraph, entry) {
			problems = append(problems, fmt.Sprintf("%s lists %q, which does not match the tree: delete the entry from %s in %s.", list, entry, list, rulesFile))
		}
	}
	return problems
}

func importsIn(graph map[string][]string) []packageImport {
	var imports []packageImport
	for _, importer := range slices.Sorted(maps.Keys(graph)) {
		for _, imported := range graph[importer] {
			imports = append(imports, packageImport{importer: importer, imported: imported})
		}
	}
	return imports
}

// nonTestImports maps each package in the go.work modules to the imports of
// its non-test Linux build that the rules check.
func nonTestImports(t *testing.T) map[string][]string {
	t.Helper()
	const repoRoot = "../.."
	rerunWhenCheckoutChanges(t, repoRoot)
	var stderr strings.Builder
	cmd := exec.CommandContext(t.Context(), "go", "list", "-json=ImportPath,Imports", "work")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(), "GOOS=linux")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list work: %v\n%s", err, stderr.String())
	}
	graph := map[string][]string{}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var pkg struct {
			ImportPath string
			Imports    []string
		}
		err := decoder.Decode(&pkg)
		if errors.Is(err, io.EOF) {
			return graph
		}
		if err != nil {
			t.Fatalf("parse go list work: %v", err)
		}
		importer, inRepo := strings.CutPrefix(pkg.ImportPath, repoPathPrefix)
		if !inRepo {
			t.Fatalf("go.work module package %s is outside %s", pkg.ImportPath, repoPathPrefix)
		}
		graph[importer] = checkedImports(pkg.Imports)
	}
}

// rerunWhenCheckoutChanges reads every directory so that Go's test cache,
// which does not see what a `go list` subprocess reads, reruns the test when
// a file in the checkout changes.
func rerunWhenCheckoutChanges(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

// checkedImports keeps repo packages, by repo-relative path, and cobra.
func checkedImports(importPaths []string) []string {
	var checked []string
	for _, path := range importPaths {
		if relative, inRepo := strings.CutPrefix(path, repoPathPrefix); inRepo {
			checked = append(checked, relative)
		}
		if path == cobraPath {
			checked = append(checked, path)
		}
	}
	return checked
}

type importRulesFixture struct {
	graph map[string][]string
	rules importRules
}

func conformingImportRulesFixture() importRulesFixture {
	return importRulesFixture{
		graph: map[string][]string{
			"cmd/c8s":              {"internal/cmds/parent", "internal/cmds/lib", cobraPath},
			"internal/cmds/parent": {"internal/cmds/child", "pkg/shared", cobraPath},
			"internal/cmds/child":  {"internal/cmds/lib", cobraPath},
			"internal/cmds/lib":    {"pkg/shared", cobraPath},
			"internal/old":         {"internal/cmds/parent"},
			"pkg/shared":           nil,
		},
		rules: importRules{
			librariesUnderCmds: []string{"internal/cmds/lib"},
			subcommandMounts:   []string{"internal/cmds/parent imports internal/cmds/child"},
			knownDebt:          []string{"internal/old imports internal/cmds/parent"},
		},
	}
}

func TestCommandImportRulesAcceptAConformingGraph(t *testing.T) {
	fixture := conformingImportRulesFixture()
	if problems := fixture.rules.problems(fixture.graph); len(problems) != 0 {
		t.Errorf("refused a conforming graph: %q", problems)
	}
}

func TestCommandImportRulesRefuse(t *testing.T) {
	cases := []struct {
		name   string
		change func(fixture *importRulesFixture)
		want   string
	}{
		{
			name:   "a package outside cmd/ and internal/cmds/ importing a command",
			change: func(f *importRulesFixture) { f.graph["pkg/shared"] = []string{"internal/cmds/child"} },
			want:   "pkg/shared imports internal/cmds/child: " + outsideImportRule,
		},
		{
			name:   "a package outside cmd/ and internal/cmds/ importing a library under internal/cmds/",
			change: func(f *importRulesFixture) { f.graph["pkg/shared"] = []string{"internal/cmds/lib"} },
			want:   "pkg/shared imports internal/cmds/lib: " + outsideImportRule,
		},
		{
			name:   "a package named like cmd/ importing a command",
			change: func(f *importRulesFixture) { f.graph["cmdline"] = []string{"internal/cmds/child"} },
			want:   "cmdline imports internal/cmds/child: " + outsideImportRule,
		},
		{
			name:   "a package named like internal/cmds/ importing a command",
			change: func(f *importRulesFixture) { f.graph["internal/cmdsutil"] = []string{"internal/cmds/child"} },
			want:   "internal/cmdsutil imports internal/cmds/child: " + outsideImportRule,
		},
		{
			name: "a command importing a command it does not mount",
			change: func(f *importRulesFixture) {
				f.graph["internal/cmds/child"] = append(f.graph["internal/cmds/child"], "internal/cmds/parent")
			},
			want: "internal/cmds/child imports internal/cmds/parent: " + mountImportRule,
		},
		{
			name:   "a library under internal/cmds/ importing a command",
			change: func(f *importRulesFixture) { f.graph["internal/cmds/lib"] = []string{"internal/cmds/child"} },
			want:   "internal/cmds/lib imports internal/cmds/child: " + mountImportRule,
		},
		{
			name:   "a package outside cmd/ and internal/cmds/ importing cobra",
			change: func(f *importRulesFixture) { f.graph["pkg/shared"] = []string{cobraPath} },
			want:   "pkg/shared imports " + cobraPath + ": " + cobraImportRule,
		},
		{
			name:   "a package named like cmd/ importing cobra",
			change: func(f *importRulesFixture) { f.graph["cmdline"] = []string{cobraPath} },
			want:   "cmdline imports " + cobraPath + ": " + cobraImportRule,
		},
		{
			name:   "a package named like internal/cmds/ importing cobra",
			change: func(f *importRulesFixture) { f.graph["internal/cmdsutil"] = []string{cobraPath} },
			want:   "internal/cmdsutil imports " + cobraPath + ": " + cobraImportRule,
		},
		{
			name:   "a known-debt import the tree no longer has",
			change: func(f *importRulesFixture) { f.graph["internal/old"] = nil },
			want:   `knownDebt lists "internal/old imports internal/cmds/parent"`,
		},
		{
			name: "a known-debt import that follows the rule",
			change: func(f *importRulesFixture) {
				f.rules.knownDebt = append(f.rules.knownDebt, "internal/cmds/parent imports internal/cmds/child")
			},
			want: `knownDebt lists "internal/cmds/parent imports internal/cmds/child"`,
		},
		{
			name:   "a subcommand mount the tree no longer has",
			change: func(f *importRulesFixture) { f.graph["internal/cmds/parent"] = []string{"pkg/shared"} },
			want:   `subcommandMounts lists "internal/cmds/parent imports internal/cmds/child"`,
		},
		{
			name: "a subcommand mount of a library",
			change: func(f *importRulesFixture) {
				f.rules.librariesUnderCmds = append(f.rules.librariesUnderCmds, "internal/cmds/child")
			},
			want: `subcommandMounts lists "internal/cmds/parent imports internal/cmds/child"`,
		},
		{
			name: "a library the tree does not have under internal/cmds/",
			change: func(f *importRulesFixture) {
				f.rules.librariesUnderCmds = append(f.rules.librariesUnderCmds, "internal/cmds/gone")
			},
			want: `librariesUnderCmds lists "internal/cmds/gone"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fixture := conformingImportRulesFixture()
			c.change(&fixture)
			problems := fixture.rules.problems(fixture.graph)
			if len(problems) != 1 || !strings.HasPrefix(problems[0], c.want) {
				t.Errorf("want one problem starting %q, got %q", c.want, problems)
			}
		})
	}
}

func TestCheckedImportsKeepRepoPackagesAndCobra(t *testing.T) {
	got := checkedImports([]string{
		repoPathPrefix + "internal/cmds/child",
		cobraPath,
		cobraPath + "/doc",
		"github.com/spf13/pflag",
		"fmt",
	})
	want := []string{"internal/cmds/child", cobraPath}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}
