package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
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

// The fixed recovery checkout predates the directory move. Run the actual build
// command with only its paired layout present; either unconditional path fails.
func TestImageBuildUsesPairedProfileLayout(t *testing.T) {
	doc := readWorkflow(t, "c8s-image.yml")
	const layout = "${{ inputs.pod_recovery_fixture && 'node-guest-image' || 'images/node-guest' }}"
	if doc.Env["NODE_GUEST_DIR"] != layout {
		t.Fatal("profile layout must follow the exclusive fixed-baseline fixture mode")
	}
	var build workflowStep
	for _, step := range doc.Jobs["build-and-push"].Steps {
		if step.Name == "Build c8s image" {
			build = step
		}
	}
	if build.Run == "" || build.WorkingDirectory != "confidential-os-builder" {
		t.Fatal("missing measured image build step")
	}
	raw, err := os.ReadFile("../../.github/workflows/c8s-image.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, stale := range []string{"c8s/node-guest-image/", "c8s/images/node-guest/"} {
		if strings.Contains(text, stale) {
			t.Fatalf("profile-dependent build/cache path is unconditional: %s", stale)
		}
	}
	for _, input := range []string{
		"kernel/c8s.config", "kernel/c8s-dev.config",
		"kernel/config-x86_64-*.snapshot", "build", "module-signing.crt",
		"c8s/mkosi.conf", "c8s/mkosi.sync",
	} {
		if !strings.Contains(text, "format('c8s/{0}/"+input+"', env.NODE_GUEST_DIR)") {
			t.Fatalf("cache no longer hashes the selected profile input %s", input)
		}
	}
	if !strings.Contains(text, "c8s/${{ env.NODE_GUEST_DIR }}/kernel/config-x86_64-*.snapshot") ||
		!strings.Contains(text, "c8s/${{ env.NODE_GUEST_DIR }}/kernel/config-x86_64-${{ inputs.dev && 'c8s-dev' || 'c8s' }}.snapshot") {
		t.Fatal("kernel cache/artifact path differs from the selected source layout")
	}
	for _, tc := range []struct {
		name, directory, fixture, componentRef, wantRef string
	}{
		{"ordinary", "images/node-guest", "false", "", "1111111"},
		{"fixed recovery", "node-guest-image", "true", "05211a8", "05211a8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			builder := filepath.Join(root, "c8s", tc.directory, "build")
			work := filepath.Join(root, "confidential-os-builder")
			for _, directory := range []string{filepath.Dir(builder), work} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(builder, []byte("#!/bin/sh\nprintf '%s\\n' \"$C8S_REF\" \"$C8S_PLATFORM\" \"$C8S_NAME\" \"$@\" > \"$OUTPUT\"\n"), 0o700); err != nil {
				t.Fatal(err)
			}
			script := strings.NewReplacer(
				"${{ matrix.platform }}", "tdx",
				"${{ inputs.pod_recovery_fixture }}", tc.fixture,
				"${{ inputs.ssh && '--profile ssh' || '' }}", "",
			).Replace(build.Run)
			if strings.Contains(script, "${{") {
				t.Fatal("unresolved image-build workflow input")
			}
			outputFile := filepath.Join(root, "builder-call")
			cmd := exec.CommandContext(t.Context(), "bash", "-euc", script)
			cmd.Dir = work
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "NODE_GUEST_DIR=" + tc.directory,
				"GITHUB_WORKSPACE=" + root, "HEAD_SHA=" + strings.Repeat("1", 40),
				"C8S_REF_INPUT=" + tc.componentRef, "VARIANT=fixture-test", "OUTPUT=" + outputFile}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("paired image build path: %v: %s", err, output)
			}
			got, err := os.ReadFile(outputFile)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.wantRef + "\ntdx\nfixture-test\n"
			if tc.fixture == "true" {
				want += "--profile-dir\n" + filepath.Join(root, "fixture-build/pod-recovery") + "\n--profile\npod-recovery\n"
			}
			if string(got) != want {
				t.Fatalf("build used different component/profile inputs: got %q, want %q", got, want)
			}
		})
	}
}
