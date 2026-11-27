package workflows

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestManualPublicationSourceGuard(t *testing.T) {
	var doc struct {
		Jobs map[string]struct {
			Needs, If string
			Steps     []workflowStep
		}
	}
	readYAML(t, "../../.github/workflows/c8s-image-manual.yml", &doc)
	build := doc.Jobs["build-and-push"]
	if build.Needs != "verify-source" || build.If != "" {
		t.Fatal("guest publication must require successful source verification")
	}
	guard := doc.Jobs["verify-source"].Steps[0]
	if guard.Env["EXPECTED_SHA"] != "${{ inputs.expected_sha }}" || guard.Env["SOURCE_SHA"] != "${{ github.sha }}" || guard.Env["C8S_REF"] != "${{ inputs.c8s_ref }}" {
		t.Fatal("source verification must compare the request to the dispatched revision")
	}
	sha := strings.Repeat("a", 40)
	for _, tc := range []struct {
		name, expected, source, component string
		pass                              bool
	}{
		{"exact", sha, sha, sha[:7], true},
		{"branch moved", sha, strings.Repeat("b", 40), sha[:7], false},
		{"wrong components", sha, sha, "bbbbbbb", false},
		{"short expectation", sha[:7], sha, sha[:7], false},
		{"ordinary manual build", "", sha, "bbbbbbb", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), "bash", "-c", guard.Run)
			cmd.Env = append(os.Environ(), "EXPECTED_SHA="+tc.expected, "SOURCE_SHA="+tc.source, "C8S_REF="+tc.component)
			if got := cmd.Run() == nil; got != tc.pass {
				t.Fatalf("source check passed=%v, want %v", got, tc.pass)
			}
		})
	}
}
