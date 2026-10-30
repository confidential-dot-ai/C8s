package workflows

import (
	"os"
	"os/exec"
	"path/filepath"
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
	const selectedSource = "${{ inputs.pod_recovery_fixture && '05211a8b106415a0aefd5f47bc40b266b0c1dacd' || github.event.workflow_run.head_sha || github.sha }}"
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

// Execute the real publication step against a recording publisher: no manual
// or beta build may move the shared production CDS aliases.
func TestCDSImagePublicationTags(t *testing.T) {
	var publish workflowStep
	for _, step := range readWorkflow(t, "c8s-image.yml").Jobs["cds-image"].Steps {
		if step.Name == "Push to GHCR" {
			publish = step
		}
	}
	if publish.Run == "" || publish.Env["HEAD_BRANCH"] != "${{ github.event.workflow_run.head_branch }}" ||
		publish.Env["HEAD_SHA"] != "${{ github.event.workflow_run.head_sha || github.sha }}" ||
		publish.Env["C8S_REF_INPUT"] != "${{ inputs.c8s_ref }}" {
		t.Fatal("CDS publication must use the exact invoking source and branch")
	}
	const source = "d5de9bbd5e8dfd0e88909f64d061d43c0e74918d"
	for _, tc := range []struct {
		name, event, branch, ref string
		floating                 bool
	}{
		{"manual exact ref", "workflow_dispatch", "", source[:7], false},
		{"manual default ref", "workflow_dispatch", "", "", false},
		{"manual main", "workflow_dispatch", "main", "", false},
		{"automatic main", "workflow_run", "main", "", true},
		{"automatic beta", "workflow_run", "beta", "", false},
		{"explicit ref", "workflow_run", "main", source[:7], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Mkdir(filepath.Join(dir, "bin"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "bin/confos"), []byte(`#!/bin/sh
printf '%s\n' "$*" >> "$LOGFILE"
`), 0o700); err != nil {
				t.Fatal(err)
			}
			logfile := filepath.Join(dir, "calls")
			cmd := exec.CommandContext(t.Context(), "bash", "-c", publish.Run)
			cmd.Dir = dir
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HEAD_SHA=" + source,
				"HEAD_BRANCH=" + tc.branch, "C8S_REF_INPUT=" + tc.ref, "GITHUB_EVENT_NAME=" + tc.event,
				"VARIANT=cds", "IMAGE=example.invalid/cds", "LOGFILE=" + logfile}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("publication step: %v: %s", err, output)
			}
			data, err := os.ReadFile(logfile)
			if err != nil {
				t.Fatal(err)
			}
			cdi, artifact := "cds-cdi-"+source[:7], "cds-"+source[:7]
			if tc.floating {
				cdi, artifact = "cds-cdi,"+cdi, "cds,"+artifact
			}
			want := "push output/cds --cdi --registry example.invalid/cds --tag " + cdi + "\n" +
				"push output/cds --registry example.invalid/cds --tag " + artifact + "\n"
			if string(data) != want {
				t.Fatalf("published calls = %q, want %q", data, want)
			}
		})
	}
}
