package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// gateSourceScript returns the repro gate's source-selection step.
func gateSourceScript(t *testing.T) string {
	t.Helper()
	for _, step := range readWorkflow(t, "image-repro-gate.yml").Jobs["changes"].Steps {
		if step.ID == "diff" {
			return step.Run
		}
	}
	t.Fatal("missing gate source-selection step")
	return ""
}

// gateRepo is a git repository holding the files the source-selection step
// reads, with a classifier stub that reports image=true exactly when a path
// named "measured" changed.
type gateRepo struct {
	t   *testing.T
	dir string
}

func newGateRepo(t *testing.T) *gateRepo {
	t.Helper()
	for key, value := range map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_SYSTEM": os.DevNull,
		"GIT_ALLOW_PROTOCOL": "file", "GIT_TERMINAL_PROMPT": "0",
		"GIT_AUTHOR_NAME": "Workflow Test", "GIT_AUTHOR_EMAIL": "workflow-test@example.invalid",
		"GIT_COMMITTER_NAME": "Workflow Test", "GIT_COMMITTER_EMAIL": "workflow-test@example.invalid",
	} {
		t.Setenv(key, value)
	}
	r := &gateRepo{t: t, dir: t.TempDir()}
	r.git("init", "-q", "-b", "main")
	r.git("remote", "add", "origin", "file://"+r.dir)
	classifier := "#!/usr/bin/env bash\nif tr '\\0' '\\n' <\"$3\" | grep -qx measured; then echo image=true; else echo image=false; fi\n"
	r.write(".github/scripts/repro-gate-changes", classifier)
	r.write(".github/build-pins.json", "{}\n")
	r.commit("base")
	return r
}

func (r *gateRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = r.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *gateRepo) write(name, content string) {
	r.t.Helper()
	path := filepath.Join(r.dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// commit commits every change and returns the new HEAD.
func (r *gateRepo) commit(message string) string {
	r.t.Helper()
	r.git("add", "-A")
	r.git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", message)
	return r.git("rev-parse", "HEAD")
}

// selectSource runs the source-selection step with env and returns its
// GITHUB_OUTPUT and combined output.
func (r *gateRepo) selectSource(env ...string) (outputs, log string, err error) {
	r.t.Helper()
	output := filepath.Join(r.t.TempDir(), "output")
	ctx, cancel := context.WithTimeout(r.t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", gateSourceScript(r.t))
	cmd.Dir = r.dir
	cmd.Env = append(os.Environ(), "PR=", "BASE_SHA=", "BASE_REF=", "RUNNER_TEMP="+r.t.TempDir(),
		"GITHUB_OUTPUT="+output, "GITHUB_STEP_SUMMARY="+filepath.Join(r.t.TempDir(), "summary"))
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	got, _ := os.ReadFile(output)
	return string(got), string(out), err
}

func TestGateImageRefUsesCheckout(t *testing.T) {
	r := newGateRepo(t)
	head := r.commit("gated checkout")
	// A dispatch: no pull request or merge group, so the gate builds the checkout.
	got, log, err := r.selectSource()
	if err != nil {
		t.Fatalf("select gate source: %v\n%s", err, log)
	}
	if !strings.Contains(got, "image=true\nc8s_ref="+head+"\n") {
		t.Fatalf("gate ref must equal full checkout SHA %s: %q", head, got)
	}
}

func TestGatePullRequestDiffsFirstParent(t *testing.T) {
	r := newGateRepo(t)
	r.git("checkout", "-q", "-b", "pr")
	r.write("measured", "x")
	r.commit("pr")
	r.git("checkout", "-q", "main")
	r.write("other", "x")
	r.commit("main moves on")
	// GitHub's PR merge commit: first parent the base branch, second the PR.
	r.git("-c", "commit.gpgsign=false", "merge", "-q", "--no-ff", "-m", "merge", "pr")
	got, log, err := r.selectSource("PR=1")
	if err != nil {
		t.Fatalf("select gate source: %v\n%s", err, log)
	}
	if !strings.Contains(got, "image=true\n") {
		t.Fatalf("pull request must be charged with its own changes only: %q", got)
	}
}

func TestGateMergeGroupForkCheck(t *testing.T) {
	tests := []struct {
		name string
		// entries is the merge queue as `gh api graphql --jq` prints it; HEAD
		// stands for the merge group's commit.
		entries   string
		wantImage string
		wantErr   string
	}{
		{
			name:      "same-repo entries",
			entries:   `[{"position":1,"headCommit":{"oid":"0"},"pullRequest":{"number":7,"isCrossRepository":false}},{"position":2,"headCommit":{"oid":"HEAD"},"pullRequest":{"number":9,"isCrossRepository":false}}]`,
			wantImage: "true",
		},
		{
			name:      "fork entry behind",
			entries:   `[{"position":1,"headCommit":{"oid":"HEAD"},"pullRequest":{"number":9,"isCrossRepository":false}},{"position":2,"headCommit":{"oid":"0"},"pullRequest":{"number":7,"isCrossRepository":true}}]`,
			wantImage: "true",
		},
		{
			name:      "fork entry ahead",
			entries:   `[{"position":1,"headCommit":{"oid":"0"},"pullRequest":{"number":7,"isCrossRepository":true}},{"position":2,"headCommit":{"oid":"HEAD"},"pullRequest":{"number":9,"isCrossRepository":false}}]`,
			wantImage: "false",
		},
		{
			name:      "fork entry itself",
			entries:   `[{"position":1,"headCommit":{"oid":"HEAD"},"pullRequest":{"number":9,"isCrossRepository":true}}]`,
			wantImage: "false",
		},
		{
			name:    "entry missing from the queue",
			entries: `[{"position":1,"headCommit":{"oid":"HEAD"},"pullRequest":{"number":7,"isCrossRepository":false}}]`,
			wantErr: "no merge queue entry",
		},
		{
			name:    "entry regrouped onto another commit",
			entries: `[{"position":1,"headCommit":{"oid":"0"},"pullRequest":{"number":9,"isCrossRepository":false}}]`,
			wantErr: "no merge queue entry",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newGateRepo(t)
			base := r.git("rev-parse", "HEAD")
			r.write("measured", "x")
			head := r.commit("queued PR")
			stubs := t.TempDir()
			stub := "#!/bin/sh\ncat <<'EOF'\n" + strings.ReplaceAll(tc.entries, "HEAD", head) + "\nEOF\n"
			if err := os.WriteFile(filepath.Join(stubs, "gh"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			got, log, err := r.selectSource(
				"PATH="+stubs+string(os.PathListSeparator)+os.Getenv("PATH"),
				"BASE_SHA="+base, "BASE_REF=refs/heads/main", "GITHUB_SHA="+head,
				"GITHUB_REF=refs/heads/gh-readonly-queue/main/pr-9-"+base,
				"GITHUB_REPOSITORY=owner/repo")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(log, tc.wantErr) {
					t.Fatalf("select gate source = %v, want error %q\n%s", err, tc.wantErr, log)
				}
				return
			}
			if err != nil {
				t.Fatalf("select gate source: %v\n%s", err, log)
			}
			if !strings.Contains(got, "image="+tc.wantImage+"\n") {
				t.Fatalf("select gate source outputs = %q, want image=%s", got, tc.wantImage)
			}
		})
	}
}

func TestGateCoreImagesSharedWithoutPublication(t *testing.T) {
	var gate struct {
		Permissions map[string]string
		Jobs        map[string]struct {
			Needs             yaml.Node
			With, Permissions map[string]string
			Steps             []workflowStep
		}
	}
	readYAML(t, "../../.github/workflows/image-repro-gate.yml", &gate)
	artifact, producerRef := "", ""
	for _, step := range gate.Jobs["core-images"].Steps {
		if strings.HasPrefix(step.Uses, "actions/checkout@") {
			producerRef = step.With["ref"]
		}
		if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			artifact = step.With["name"]
		}
	}
	if artifact == "" || producerRef != "${{ github.sha }}" || gate.Permissions["packages"] == "write" {
		t.Fatal("gate producer must use the triggering checkout, upload its images and avoid package writes")
	}
	for name, job := range gate.Jobs {
		if job.Permissions["packages"] == "write" {
			t.Errorf("gate job %s grants package writes", name)
		}
	}
	for _, name := range []string{"build-a", "build-b"} {
		job := gate.Jobs[name]
		if !slices.Contains(names(t, job.Needs), "core-images") || job.With["gate_images_artifact"] != artifact {
			t.Errorf("%s must depend on the shared core-image artifact", name)
		}
	}
	buildAndPush := readWorkflow(t, "c8s-image.yml").Jobs["build-and-push"]
	if buildAndPush.Env["GATE_CORE_IMAGES"] != "${{ inputs.gate_images_artifact != '' }}" {
		t.Error("a build must use local core images exactly when a core-image artifact is supplied")
	}
	steps := make(map[string]workflowStep)
	for _, step := range buildAndPush.Steps {
		steps[step.Name] = step
	}
	if steps["Checkout c8s"].With["ref"] != "${{ github.event.workflow_run.head_sha || github.sha }}" {
		t.Error("gate node image and core-image producer must check out the same PR revision")
	}
	guard := steps["Check the gate inputs"]
	if guard.Env["GATE"] != "${{ inputs.gate }}" || guard.Env["IMAGES_ARTIFACT"] != "${{ inputs.gate_images_artifact }}" {
		t.Fatal("the gate input check must read the gate flag and the core-image artifact")
	}
	if gateInputCheckPasses(t, guard.Run, "false", "core-images") {
		t.Error("a supplied core-image artifact must fail published builds")
	}
	if !gateInputCheckPasses(t, guard.Run, "true", "core-images") {
		t.Error("a gate build must accept a supplied core-image artifact")
	}
	if !gateInputCheckPasses(t, guard.Run, "true", "") {
		t.Error("a manual gate build must run without a core-image artifact")
	}
	download := steps["Download gate core images"]
	if download.If != "env.GATE_CORE_IMAGES == 'true'" || download.With["name"] != "${{ inputs.gate_images_artifact }}" {
		t.Error("gate builds must download the supplied core-image artifact")
	}
}

// gateInputCheckPasses reports whether the gate input check exits zero for a dispatch with these inputs.
func gateInputCheckPasses(t *testing.T, script, gate, imagesArtifact string) bool {
	t.Helper()
	withoutSigningArtifact := "SIGNING_ARTIFACT="
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script)
	cmd.Env = append(os.Environ(), "GATE="+gate, "IMAGES_ARTIFACT="+imagesArtifact, withoutSigningArtifact)
	return cmd.Run() == nil
}
