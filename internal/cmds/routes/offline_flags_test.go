package routes

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// ignoredFlagArgs sets every routes flag to a value digest could not use.
var ignoredFlagArgs = []string{
	"--url", "nonsense",
	"--measurements", "x",
	"--measurements-file", "/nonexistent",
	"--image-policy-file", "/nonexistent",
	"--timeout", "1s",
	"--operator-key", "/nonexistent",
	"--insecure",
	"--operator-keys", "/nonexistent",
}

func TestDigestAcceptsTheRoutesFlags(t *testing.T) {
	manifest := []byte(`{"schema":"c8s.routes/v1","revision":7,"notBefore":"2026-09-01T00:00:00Z","maxAgeSeconds":60,"hosts":{"app.example":{"routes":[{"path":"/","match":"exact","backend":{"address":"a:1","workload":"a"}}]}}}`)
	file := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(file, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, args := range map[string][]string{
		"flags after the subcommand":  slices.Concat([]string{"digest", file}, ignoredFlagArgs),
		"flags before the subcommand": slices.Concat(ignoredFlagArgs, []string{"digest", file}),
	} {
		t.Run(name, func(t *testing.T) {
			cmd := newCmd(nil)
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs(args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("digest: %v", err)
			}
			if got := strings.TrimSpace(out.String()); got != digestHex(manifest) {
				t.Fatalf("digest = %q, want %s", got, digestHex(manifest))
			}
		})
	}
}

// The subcommands share one tree, so a help that changes what a later help
// shows fails here.
func TestHelpListsOnlyTheRoutesFlagsASubcommandReads(t *testing.T) {
	flags := []string{"--url", "--measurements", "--measurements-file", "--image-policy-file", "--timeout", "--operator-key", "--insecure", "--operator-keys"}
	tree := newCmd(nil)
	for _, tc := range []struct {
		subcommand      string
		listed, omitted []string
	}{
		{subcommand: "digest", omitted: flags},
		{subcommand: "show", listed: flags},
	} {
		t.Run(tc.subcommand, func(t *testing.T) {
			var help bytes.Buffer
			tree.SetOut(&help)
			tree.SetArgs([]string{tc.subcommand, "--help"})
			if err := tree.Execute(); err != nil {
				t.Fatalf("%s --help: %v", tc.subcommand, err)
			}
			testutil.CheckHelpFlags(t, help.String(), tc.listed, tc.omitted)
		})
	}
}
