package workflows

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Execute the unchanged manual-build guard with the source pairs that produced
// mixed images, and preserve the automatic publication and repro-gate paths.
func TestC8sManualImageSources(t *testing.T) {
	doc := readWorkflow(t, "c8s-image.yml")
	host := doc.Jobs["host-deps"]
	var guard workflowStep
	guardIndex, pinsIndex := -1, -1
	const selectedSource = "${{ github.event.workflow_run.head_sha || github.sha }}"
	for i, step := range host.Steps {
		switch step.Name {
		case "Require matching manual image sources":
			guard, guardIndex = step, i
		case "Load measured-build pins":
			pinsIndex = i
		}
	}
	if guardIndex < 0 || pinsIndex <= guardIndex || guard.Run == "" {
		t.Fatal("manual source verification must precede pins and dependency setup")
	}
	if guard.If != "github.event_name == 'workflow_dispatch' && inputs.gate != true" {
		t.Fatal("manual source verification must leave automatic publication and repro gates unchanged")
	}
	if guard.Env["PROFILE_SHA"] != selectedSource || guard.Env["C8S_REF_INPUT"] != "${{ inputs.c8s_ref }}" {
		t.Fatal("guard must compare the selected checkout SHA with the requested component ref")
	}
	if doc.Jobs["build-and-push"].Needs.Value != "host-deps" {
		t.Fatal("image build must depend on successful source verification")
	}
	for _, job := range []string{"host-deps", "build-and-push"} {
		found := false
		for _, step := range doc.Jobs[job].Steps {
			if step.Name == "Checkout c8s" {
				found = true
				if step.With["ref"] != selectedSource {
					t.Fatalf("%s checkout does not use the verified profile source", job)
				}
			}
		}
		if !found {
			t.Fatalf("missing %s checkout", job)
		}
	}
	const source = "d5de9bbd5e8dfd0e88909f64d061d43c0e74918d"
	for _, tc := range []struct {
		name, profile, components string
		accept                    bool
	}{
		{"matching short SHA", source, "d5de9bb", true},
		{"matching longer prefix", source, "d5de9bbd", true},
		{"matching full SHA", source, source, true},
		{"default components", source, "", true},
		{"image 3 mixed sources", "2315727cfce8f8c56b316fa625abd27f20ffd53e", "4774df9", false},
		{"image 4 mixed sources", "3f82f43b1d2995a145a5703f0af32e1a4e135d26", "4774df9", false},
		{"diagnostic mixed sources", "00f43aca8047bd5e2a3e30586d6a72b3091e5da5", "4774df9", false},
		{"different full SHA", source, "4774df9ebc1bd186765b8997f5356005510b9342", false},
		{"short ambiguous prefix", source, "d5de9b", false},
		{"too long", source, source + "0", false},
		{"symbolic component ref", source, "main", false},
		{"release component tag", source, "v1.2.3", false},
		{"uppercase component ref", source, "D5DE9BB", false},
		{"output injection", source, "d5de9bb\nINJECTED=yes", false},
		{"missing profile source", "", "", false},
		{"invalid profile source", strings.Repeat("g", 40), "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "bash", "-c", guard.Run)
			cmd.Env = append(os.Environ(), "PROFILE_SHA="+tc.profile, "C8S_REF_INPUT="+tc.components)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.accept {
				t.Fatalf("accept=%v, error=%v: %s", tc.accept, err, output)
			}
			if !tc.accept && tc.profile == source && !strings.Contains(string(output), "--ref <source-branch-or-tag>") {
				t.Fatalf("rejection must explain how to select matching sources: %s", output)
			}
		})
	}
}
