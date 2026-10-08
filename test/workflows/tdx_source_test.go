package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Exercise the unchanged inline preflight against real Git history. The
// privileged launcher must receive only a SHA proven to belong to the
// protected branch it was pushed to: main, or beta.
func TestTDXSourceProvenance(t *testing.T) {
	raw, err := os.ReadFile("../../.github/workflows/tdx-image-acceptance.yml")
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Needs  string
			RunsOn string `yaml:"runs-on"`
			Steps  []struct {
				ID  string
				Run string
			}
		}
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatal(err)
	}
	source := workflow.Jobs["source"]
	if source.RunsOn != "ubuntu-latest" || workflow.Jobs["e2e"].Needs != "source" {
		t.Fatal("source verification must precede launcher allocation on a hosted runner")
	}
	var script string
	for _, step := range source.Steps {
		if step.ID == "source" {
			script = step.Run
		}
	}
	if script == "" {
		t.Fatal("missing inline source verification")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_AUTHOR_NAME", "Workflow Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "workflow-test@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "Workflow Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "workflow-test@example.invalid")
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	tree := git("mktree")
	parent := git("commit-tree", tree, "-m", "accepted parent")
	head := git("commit-tree", tree, "-p", parent, "-m", "current main")
	untrusted := git("commit-tree", tree, "-p", parent, "-m", "unmerged branch")
	beta := git("commit-tree", tree, "-p", parent, "-m", "current beta")
	git("update-ref", "refs/remotes/origin/main", head)
	git("update-ref", "refs/remotes/origin/beta", beta)
	git("update-ref", "refs/remotes/origin/feat/x", untrusted)

	for _, tc := range []struct {
		name, branch, source, want string
	}{
		{"main tip", "main", head, head},
		{"older main build", "main", parent, parent},
		{"beta tip", "beta", beta, beta},
		{"older beta build", "beta", parent, parent},
		{"beta commit claimed as main", "main", beta, ""},
		{"main commit claimed as beta", "beta", head, ""},
		{"unprotected branch", "feat/x", untrusted, ""},
		{"empty branch", "", head, ""},
		{"branch path traversal", "../../heads/main", head, ""},
		{"unmerged branch", "main", untrusted, ""},
		{"missing commit", "main", strings.Repeat("a", 40), ""},
		{"symbolic ref", "main", "refs/remotes/origin/main", ""},
		{"empty source", "main", "", ""},
		{"option injection", "main", "--help", ""},
		{"output injection", "main", head + "\nsha=" + untrusted, ""},
		{"nonhex SHA", "main", strings.Repeat("g", 40), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output")
			cmd := exec.Command("bash", "-c", script)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(),
				"SOURCE_BRANCH="+tc.branch, "SOURCE_SHA="+tc.source, "GITHUB_OUTPUT="+output)
			log, err := cmd.CombinedOutput()
			got, readErr := os.ReadFile(output)
			if tc.want == "" {
				if err == nil || len(got) != 0 {
					t.Fatalf("untrusted source accepted: err=%v output=%q log=%s", err, got, log)
				}
				return
			}
			if err != nil || readErr != nil || string(got) != "sha="+tc.want+"\n" {
				t.Fatalf("trusted source rejected: err=%v read=%v output=%q log=%s", err, readErr, got, log)
			}
		})
	}
}
