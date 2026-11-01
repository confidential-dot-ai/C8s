package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the workflow's real guard: the paired source must already belong
// to the dispatched revision before setup-go reads it or any build runs.
func TestPodDiagnosticSourceBelongsToDispatchedHistory(t *testing.T) {
	steps := readWorkflow(t, stagedWorkflow).Jobs["pod-diagnostic"].Steps
	var guard workflowStep
	checkout, selected, setup := -1, -1, -1
	for i, step := range steps {
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			if step.With["ref"] != "${{ github.sha }}" || step.With["persist-credentials"] != "false" {
				t.Fatal("initial checkouts must use the dispatched revision without retained credentials")
			}
			if step.With["path"] == "diagnostic-source" {
				checkout = i
				if step.With["fetch-depth"] != "0" {
					t.Fatal("paired checkout needs complete dispatched history")
				}
			}
		}
		if step.ID == "source" {
			guard, selected = step, i
		}
		if step.Uses == "./.github/actions/setup-go-c8s" {
			setup = i
			if step.With["go-version-file"] != "diagnostic-source/go.mod" || step.With["cache"] != "false" {
				t.Fatal("paired toolchain selection must retain disabled caching")
			}
		}
	}
	if checkout < 0 || selected <= checkout || setup <= selected || guard.Shell != "bash" || guard.WorkingDirectory != "diagnostic-source" || guard.Env["SOURCE_INPUT"] != "${{ inputs.pod_image_source }}" {
		t.Fatal("verify the dispatched paired checkout before any candidate toolchain setup")
	}
	for _, step := range steps[:selected] {
		if step.Run != "" || (!strings.HasPrefix(step.Uses, "actions/checkout@") && step.Uses != "") {
			t.Fatal("no script or local action may consume candidate source before verification")
		}
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_AUTHOR_NAME", "Workflow Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "workflow-test@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "Workflow Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "workflow-test@example.invalid")
	repo := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = repo
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	tree := git("mktree")
	parent := git("commit-tree", tree, "-m", "ancestor")
	head := git("commit-tree", tree, "-p", parent, "-m", "dispatched")
	unrelated := git("commit-tree", tree, "-m", "unrelated")
	newer := git("commit-tree", tree, "-p", head, "-m", "not yet dispatched")
	git("tag", "-a", "-m", "tag object", "candidate", parent)
	tag := git("rev-parse", "candidate")
	for _, tc := range []struct{ name, source, want string }{
		{"default", "", head}, {"current", head, head}, {"ancestor", parent, parent},
		{"unrelated", unrelated, ""}, {"newer", newer, ""}, {"unknown", strings.Repeat("a", 40), ""},
		{"tag object", tag, ""}, {"symbolic", "candidate", ""}, {"nonhex", strings.Repeat("g", 40), ""},
		{"option", "--help", ""}, {"newline", head + "\nsha=" + unrelated, ""},
		{"shell text", "$(touch injected)", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git("checkout", "--detach", head)
			output := filepath.Join(t.TempDir(), "output")
			cmd := exec.CommandContext(t.Context(), "bash", "-c", guard.Run)
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "SOURCE_INPUT="+tc.source, "GITHUB_SHA="+head,
				"GITHUB_OUTPUT="+output, "GITHUB_STEP_SUMMARY="+filepath.Join(t.TempDir(), "summary"))
			log, err := cmd.CombinedOutput()
			got, readErr := os.ReadFile(output)
			if tc.want == "" {
				if err == nil || len(got) != 0 || git("rev-parse", "HEAD") != head {
					t.Fatalf("untrusted source changed checkout/output: err=%v output=%q log=%s", err, got, log)
				}
				return
			}
			if err != nil || readErr != nil || string(got) != "sha="+tc.want+"\n" || git("rev-parse", "HEAD") != tc.want {
				t.Fatalf("trusted source refused: err=%v read=%v output=%q log=%s", err, readErr, got, log)
			}
		})
	}
	if _, err := os.Stat(filepath.Join(repo, "injected")); !os.IsNotExist(err) {
		t.Fatal("malformed input was interpreted by the shell")
	}
}
