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

func TestGateImageRefUsesCheckout(t *testing.T) {
	run := gateSourceScript(t)
	for key, value := range map[string]string{
		"GIT_CONFIG_GLOBAL": os.DevNull, "GIT_CONFIG_SYSTEM": os.DevNull,
		"GIT_ALLOW_PROTOCOL": "file", "GIT_TERMINAL_PROMPT": "0",
		"GIT_AUTHOR_NAME": "Workflow Test", "GIT_AUTHOR_EMAIL": "workflow-test@example.invalid",
		"GIT_COMMITTER_NAME": "Workflow Test", "GIT_COMMITTER_EMAIL": "workflow-test@example.invalid",
	} {
		t.Setenv(key, value)
	}
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
	git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "base")
	base := git("rev-parse", "HEAD")
	git("-c", "commit.gpgsign=false", "commit", "--allow-empty", "-qm", "gated checkout")
	head := git("rev-parse", "HEAD")
	output := filepath.Join(repo, "output")
	// A dispatch: no pull request or merge group, so the gate builds the checkout.
	t.Setenv("PR", "")
	t.Setenv("BASE_SHA", "")
	t.Setenv("GITHUB_SHA", base)
	t.Setenv("GITHUB_OUTPUT", output)
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(repo, "summary"))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", run)
	cmd.Dir = repo
	if log, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("select gate source: %v\n%s", err, log)
	}
	got, err := os.ReadFile(output)
	if err != nil || !strings.Contains(string(got), "\nc8s_ref="+head+"\n") {
		t.Fatalf("gate ref must equal full checkout SHA %s: %q (%v)", head, got, err)
	}
}

func TestGateMergeGroupForkCheck(t *testing.T) {
	run := gateSourceScript(t)
	tests := []struct {
		name    string
		entries string
		wantErr bool
		want    string
	}{
		{
			name:    "fork entry ahead",
			entries: `[{"position":1,"pullRequest":{"number":7,"isCrossRepository":true}},{"position":2,"pullRequest":{"number":9,"isCrossRepository":false}}]`,
			want:    "image=false",
		},
		{
			name:    "fork entry itself",
			entries: `[{"position":1,"pullRequest":{"number":9,"isCrossRepository":true}}]`,
			want:    "image=false",
		},
		{
			name:    "entry missing from the queue",
			entries: `[{"position":1,"pullRequest":{"number":7,"isCrossRepository":false}}]`,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			// The stub prints the queue entries the way `gh api graphql --jq` would.
			stub := "#!/bin/sh\ncat <<'EOF'\n" + tc.entries + "\nEOF\n"
			if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(stub), 0o755); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(dir, "output")
			cmd := exec.CommandContext(t.Context(), "bash", "-c", run)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(),
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"PR=", "BASE_SHA=0123456789abcdef", "BASE_REF=refs/heads/main",
				"GITHUB_REF=refs/heads/gh-readonly-queue/main/pr-9-0123456789abcdef",
				"GITHUB_REPOSITORY=owner/repo",
				"GITHUB_OUTPUT="+output, "GITHUB_STEP_SUMMARY="+filepath.Join(dir, "summary"))
			log, err := cmd.CombinedOutput()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("fork check passed, want failure:\n%s", log)
				}
				return
			}
			got, _ := os.ReadFile(output)
			if !strings.Contains(string(got), tc.want+"\n") {
				t.Fatalf("fork check output = %q, want %q (%v)\n%s", got, tc.want, err, log)
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
