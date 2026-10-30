package workflows

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRecoveryBuildGuardRejectsProductionAndDebugInputs(t *testing.T) {
	image := readWorkflow(t, "c8s-image.yml")
	manualGuard := readWorkflow(t, "c8s-image-manual.yml")
	for _, lane := range []struct {
		name  string
		steps []workflowStep
		ref   string
		build bool
	}{
		{"build", image.Jobs["build-and-push"].Steps, "05211a8", true},
		{"host-deps", image.Jobs["host-deps"].Steps, "05211a8", true},
		{"manual", manualGuard.Jobs["validate-recovery-mode"].Steps, "", false},
	} {
		t.Run(lane.name, func(t *testing.T) {
			var guard workflowStep
			for _, step := range lane.steps {
				if step.Name == "Fence recovery fixture publication" || step.Name == "Require exclusive recovery fixture mode" {
					guard = step
				}
			}
			if guard.Run == "" {
				t.Fatal("missing fixture publication fence")
			}
			if lane.build && guard.If != "inputs.pod_recovery_fixture" {
				t.Fatal("fixture fence is not scoped")
			}
			base := map[string]string{"GITHUB_EVENT_NAME": "workflow_dispatch", "DEV": "false", "SSH": "false", "GATE": "false", "REF": lane.ref, "CONFOS": "", "RELEASE": "", "GATE_IMAGES": "", "GATE_KEY": ""}
			cases := []struct{ key, value string }{{"", ""}, {"GITHUB_EVENT_NAME", "workflow_run"}, {"DEV", "true"}, {"SSH", "true"}, {"GATE", "true"}, {"REF", "main"}, {"CONFOS", "other"}}
			if lane.build {
				cases = append(cases, struct{ key, value string }{"REF", ""}, struct{ key, value string }{"RELEASE", "v1.0.0"}, struct{ key, value string }{"GATE_IMAGES", "other"}, struct{ key, value string }{"GATE_KEY", "other"})
			}
			for _, tc := range cases {
				cmd := exec.CommandContext(t.Context(), "bash", "-euc", guard.Run)
				cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
				for key, value := range base {
					if key == tc.key {
						value = tc.value
					}
					cmd.Env = append(cmd.Env, key+"="+value)
				}
				err := cmd.Run()
				if (err == nil) != (tc.key == "") {
					t.Fatalf("fixture guard %s=%s: %v", tc.key, tc.value, err)
				}
			}
		})
	}
	manual := readWorkflow(t, "c8s-image-manual.yml")
	if !strings.Contains(manual.Jobs["build-and-push"].If, "!inputs.pod_recovery_fixture") || manual.Jobs["recovery-fixture"].Uses != "./.github/workflows/pod-recovery-fixture.yml" {
		t.Fatal("manual fixture is not exclusive")
	}
	native := readWorkflow(t, stagedWorkflow)
	job := native.Jobs["pod-recovery"]
	if !strings.Contains(job.If, "workflow_dispatch") || !strings.Contains(job.If, "!inputs.pod_acceptance") {
		t.Fatal("recovery escaped manual exclusive mode")
	}
	cleanup := false
	for _, step := range job.Steps {
		if step.Uses == lifecycleAction || strings.Contains(step.Run, "reap") || strings.Contains(step.Run, "kubectl exec") {
			t.Fatal("recovery gained unrelated or privileged lifecycle access")
		}
		if strings.Contains(step.Run, "recovery cleanup") {
			cleanup = step.If == "always()"
		}
	}
	if !cleanup {
		t.Fatal("owned cleanup is not unconditional")
	}
}

func TestRecoveryFixtureCannotEnterCDSImagePublication(t *testing.T) {
	job := readWorkflow(t, "c8s-image.yml").Jobs["cds-image"]
	want := `!inputs.pod_recovery_fixture && inputs.gate != true &&
		(github.event_name == 'workflow_dispatch' ||
		(github.event.workflow_run.conclusion == 'success' &&
		github.event.workflow_run.head_repository.full_name == github.repository &&
		(github.event.workflow_run.event == 'push' || github.event.workflow_run.event == 'workflow_dispatch') &&
		(github.event.workflow_run.head_branch == 'main' || github.event.workflow_run.head_branch == 'beta')))`
	if strings.Join(strings.Fields(job.If), " ") != strings.Join(strings.Fields(want), " ") {
		t.Fatal("CDS publication escaped the complete fixture exclusion")
	}
}
