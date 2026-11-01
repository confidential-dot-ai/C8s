package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the production render step up to its first download. Both supported
// source layouts must supply their own Helm pins, and no other checkout may
// repair an absent, incomplete or ambiguous paired profile.
func TestTDXComponentSeedUsesSelectedProfile(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	var render workflowStep
	for _, step := range action.Runs.Steps {
		if step.Name == "render the component entries this commit's images bake" {
			render = step
		}
	}
	if render.Run == "" {
		t.Fatal("missing component render step")
	}
	for _, tc := range []struct {
		name, layout, version, checksum string
	}{
		{"current source", "images/node-guest", "v3.14.4", strings.Repeat("a", 64)},
		{"historical source", "node-guest-image", "v3.13.3", strings.Repeat("b", 64)},
		{name: "missing profile"},
		{name: "both profiles"},
		{name: "incomplete profile"},
		{name: "profile is a regular file"},
		{name: "profile is a symlink"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := t.TempDir()
			source := filepath.Join(fixture, "paired source")
			workspace := filepath.Join(fixture, "workflow checkout")
			selected := filepath.Join(fixture, "selected pins")
			write := func(path, value string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			pins := func(version, checksum string) string {
				return "HELM_VERSION=\"" + version + "\"\nHELM_LINUX_AMD64_SHA256=\"" + checksum + "\"\n"
			}
			// Decoys ensure a missing historical profile cannot borrow the
			// action's current checkout or mix either pin between checkouts.
			for _, layout := range []string{"images/node-guest", "node-guest-image"} {
				write(filepath.Join(workspace, layout, "c8s/mkosi.sync"), pins("v9.9.9", strings.Repeat("f", 64)))
			}
			if tc.layout != "" {
				write(filepath.Join(source, tc.layout, "c8s/mkosi.sync"), pins(tc.version, tc.checksum))
			}
			switch tc.name {
			case "both profiles":
				for _, layout := range []string{"images/node-guest", "node-guest-image"} {
					write(filepath.Join(source, layout, "c8s/mkosi.sync"), pins("v3.14.4", strings.Repeat("a", 64)))
				}
			case "incomplete profile":
				write(filepath.Join(source, "images/node-guest/README.md"), "missing c8s/mkosi.sync\n")
			case "profile is a regular file":
				write(filepath.Join(source, "node-guest-image"), "not a profile\n")
			case "profile is a symlink":
				if err := os.MkdirAll(source, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(workspace, "node-guest-image"), filepath.Join(source, "node-guest-image")); err != nil {
					t.Fatal(err)
				}
			}
			// Intercept the existing retry helper, not the selection logic.
			// Exit before any download, extraction, registry call or rendering.
			write(filepath.Join(workspace, "bin/retry.sh"), `retry() {
  printf '%s\n%s\n%s\n' "$*" "$helm_version" "$helm_sha" > "$FIXTURE_SELECTED"
  exit 0
}
`)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", render.Run)
			cmd.Dir = fixture
			cmd.Env = append(os.Environ(), "GITHUB_WORKSPACE="+workspace, "C8S_SOURCE_DIR="+source,
				"FIXTURE_SELECTED="+selected)
			log, err := cmd.CombinedOutput()
			got, readErr := os.ReadFile(selected)
			if tc.layout == "" {
				if err == nil || !os.IsNotExist(readErr) || !strings.Contains(string(log), "node image profile") {
					t.Fatalf("invalid paired profile reached download: err=%v read=%v selected=%q log=%s", err, readErr, got, log)
				}
				return
			}
			want := "curl -fsSL -o /tmp/helm.tgz https://get.helm.sh/helm-" + tc.version + "-linux-amd64.tar.gz\n" +
				tc.version + "\n" + tc.checksum + "\n"
			if err != nil || readErr != nil || string(got) != want {
				t.Fatalf("selected source pins: err=%v read=%v got=%q want=%q log=%s", err, readErr, got, want, log)
			}
		})
	}
}
