package volume

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// ignoredFlagArgs sets every volume flag to a value attach and detach could
// not use.
var ignoredFlagArgs = []string{
	"--url", "nonsense",
	"--image-policy-file", "/nonexistent",
	"--timeout", "1s",
	"--operator-key", "/nonexistent",
	"--insecure",
}

// Each run stops at the volume name check, which runs only once every flag
// has parsed.
func TestNodeSubcommandsAcceptTheVolumeFlags(t *testing.T) {
	root := t.TempDir()
	for _, subcommand := range [][]string{
		{"attach", "Not_A_Label", "--image", "/nonexistent", "--config-root", root},
		{"detach", "Not_A_Label", "--config-root", root},
	} {
		for name, args := range map[string][]string{
			"flags after the subcommand":  slices.Concat(subcommand, ignoredFlagArgs),
			"flags before the subcommand": slices.Concat(ignoredFlagArgs, subcommand),
		} {
			t.Run(subcommand[0]+"/"+name, func(t *testing.T) {
				cmd := newCmd(nil)
				cmd.SetOut(io.Discard)
				cmd.SetErr(io.Discard)
				cmd.SetArgs(args)
				err := cmd.Execute()
				if err == nil || !strings.Contains(err.Error(), "is not a dns-1123 label") {
					t.Fatalf("%s = %v, want the volume name refused", subcommand[0], err)
				}
			})
		}
	}
}

// The subcommands share one tree, so a help that changes what a later help
// shows fails here.
func TestHelpListsOnlyTheVolumeFlagsASubcommandReads(t *testing.T) {
	flags := []string{"--url", "--image-policy-file", "--timeout", "--operator-key", "--insecure"}
	tree := newCmd(nil)
	for _, tc := range []struct {
		subcommand      string
		listed, omitted []string
	}{
		{subcommand: "attach", listed: []string{"--image", "--config-root", "--json"}, omitted: flags},
		{subcommand: "create", listed: flags},
		{subcommand: "detach", listed: []string{"--config-root"}, omitted: flags},
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
