package allowlist

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/testutil"
)

// ignoredFlagArgs sets every allowlist flag to a value no offline subcommand
// could use.
var ignoredFlagArgs = []string{
	"--url", "nonsense",
	"--measurements", "x",
	"--measurements-file", "/nonexistent",
	"--image-policy-file", "/nonexistent",
	"--timeout", "1s",
	"--operator-key", "/nonexistent",
	"--insecure",
	"-o", "yaml",
}

func TestOfflineSubcommandsAcceptTheAllowlistFlags(t *testing.T) {
	t.Setenv("PATH", "")
	pod := writeFile(t, "pod.json", deployJSON())
	doc := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1"}`)
	for _, tc := range []struct {
		name  string
		args  []string
		check func(t *testing.T, out string, err error)
	}{
		{
			name: "lint",
			args: []string{"lint", doc},
			check: func(t *testing.T, out string, err error) {
				if err != nil || !strings.Contains(out, "ok: no findings") {
					t.Fatalf("lint = %v, output %q; want a clean lint", err, out)
				}
			},
		},
		{
			name: "derive",
			args: []string{"derive", "dynamo", pod, "--env=deny", "--mounts=any"},
			check: func(t *testing.T, out string, err error) {
				if err != nil {
					t.Fatalf("derive: %v", err)
				}
				entries, err := parseWorkloadEntries([]byte(out))
				if err != nil {
					t.Fatalf("derive output does not parse: %v\n%s", err, out)
				}
				if _, ok := entries["dynamo"]; !ok {
					t.Fatalf("derive output lacks the dynamo entry: %s", out)
				}
			},
		},
		{
			name: "inspect-image",
			args: []string{"inspect-image", "docker.io/library/busybox:latest"},
			check: func(t *testing.T, _ string, err error) {
				if err == nil || !strings.Contains(err.Error(), "crane") {
					t.Fatalf("inspect-image = %v, want the crane-not-found error its run returns", err)
				}
			},
		},
	} {
		t.Run(tc.name+"/flags after the subcommand", func(t *testing.T) {
			out, _, err := runCmd(slices.Concat(tc.args, ignoredFlagArgs)...)
			tc.check(t, out, err)
		})
		t.Run(tc.name+"/flags before the subcommand", func(t *testing.T) {
			out, _, err := runCmd(slices.Concat(ignoredFlagArgs, tc.args)...)
			tc.check(t, out, err)
		})
	}
}

func TestLintRefusesABadTimeout(t *testing.T) {
	doc := writeFile(t, "al.json", `{"schema":"c8s.allowlist/v1"}`)
	for name, args := range map[string][]string{
		"flag after the subcommand":  {"lint", doc, "--timeout", "bogus"},
		"flag before the subcommand": {"--timeout", "bogus", "lint", doc},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := runCmd(args...)
			if err == nil || !strings.Contains(err.Error(), `invalid argument "bogus" for "--timeout" flag`) {
				t.Fatalf("%v = %v, want the duration refused", args, err)
			}
		})
	}
}

// The subcommands share one tree, so a help that changes what a later help
// shows fails here.
func TestHelpListsOnlyTheAllowlistFlagsASubcommandReads(t *testing.T) {
	connection := []string{"--url", "--measurements", "--measurements-file", "--image-policy-file", "--timeout", "--operator-key", "--insecure"}
	output := []string{"-o, --output"}
	tree := NewCmd()
	for _, tc := range []struct {
		subcommand      string
		listed, omitted []string
	}{
		{subcommand: "lint", listed: []string{"--online", "--strict", "--seed"}, omitted: slices.Concat(connection, output)},
		{subcommand: "list", listed: slices.Concat(connection, output)},
		{subcommand: "derive", listed: []string{"--env", "--env-file", "--mounts", "--mounts-file", "--label", "--secret-read"}, omitted: slices.Concat(connection, output)},
		{subcommand: "inspect-image", listed: output, omitted: connection},
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
