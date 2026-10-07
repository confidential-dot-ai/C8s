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

func TestGateImageRefUsesCheckout(t *testing.T) {
	doc := readWorkflow(t, "image-repro-gate.yml")
	var run string
	for _, step := range doc.Jobs["changes"].Steps {
		if step.ID == "diff" {
			run = step.Run
		}
	}
	if run == "" {
		t.Fatal("missing gate source-selection step")
	}
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
	t.Setenv("PR", "")
	t.Setenv("BASE_SHA", base)
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
		if !slices.Contains(events(t, job.Needs), "core-images") || job.With["gate_images_artifact"] != artifact {
			t.Errorf("%s must depend on the shared core-image artifact", name)
		}
	}
	steps := make(map[string]workflowStep)
	for _, step := range readWorkflow(t, "c8s-image.yml").Jobs["build-and-push"].Steps {
		steps[step.Name] = step
	}
	if steps["Checkout c8s"].With["ref"] != "${{ github.event.workflow_run.head_sha || github.sha }}" {
		t.Error("gate node image and core-image producer must check out the same PR revision")
	}
	guard := steps["Require local core images exactly for gate builds"]
	if guard.If != "(inputs.gate == true) != (inputs.gate_images_artifact != '')" || !strings.Contains(guard.Run, "exit 1") {
		t.Error("missing artifact must fail gate builds; supplied artifacts must fail published builds")
	}
	download := steps["Download gate core images"]
	if download.If != "inputs.gate == true" || download.With["name"] != "${{ inputs.gate_images_artifact }}" {
		t.Error("gate builds must download the supplied core-image artifact")
	}
}
