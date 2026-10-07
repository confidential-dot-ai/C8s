package workflows

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Execute the production build step with real Git references. Exact acceptance
// reuses the verified checkout; staged runs resolve images from the source built.
func TestTDXBuildUsesSelectedSource(t *testing.T) {
	var action lifecycleDocument
	readYAML(t, "../../.github/actions/tdx-metal-e2e/action.yml", &action)
	testBuildUsesSelectedSource(t, action.Runs.Steps, true, []string{
		"assert components converged", "assert the image floor denies, then opens to a signed write",
		"assert a confidential workload runs with an injected cert"})
}

// The build step of one lane: its source selection, the environment it hands
// the later steps, and that the downstream steps run from that source. A lane
// with an exact-image mode also takes the publication SHA.
func testBuildUsesSelectedSource(t *testing.T, steps []workflowStep, exact bool, downstream []string) {
	var build workflowStep
	for _, step := range steps {
		if step.Name == "build the c8s CLI at the paired ref" {
			build = step
		}
	}
	if build.Run == "" {
		t.Fatal("missing CLI build step")
	}
	if build.Env["C8S_REF_INPUT"] != "${{ inputs.c8s_ref }}" {
		t.Error("build step must receive the requested source")
	}
	if exact && (build.Env["EXACT_IMAGE"] != "${{ inputs.exact_image == 'true' }}" ||
		build.Env["SOURCE_SHA"] != "${{ github.event.workflow_run.head_sha }}") {
		t.Error("build step must receive exact mode and the publication SHA")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_SYSTEM", os.DevNull)
	t.Setenv("GIT_ALLOW_PROTOCOL", "file") // A regression must never contact the network.
	t.Setenv("GIT_TERMINAL_PROMPT", "0")
	t.Setenv("GIT_AUTHOR_NAME", "Workflow Test")
	t.Setenv("GIT_AUTHOR_EMAIL", "workflow-test@example.invalid")
	t.Setenv("GIT_COMMITTER_NAME", "Workflow Test")
	t.Setenv("GIT_COMMITTER_EMAIL", "workflow-test@example.invalid")
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	workspace := filepath.Join(fixture, "verified checkout")
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(workspace, "fixture-source"), "trusted\n", 0o644)
	for _, name := range []string{"components-ready.sh", "allowlist-enforcement.sh", "cw-workload.sh"} {
		write(filepath.Join(workspace, "test/e2e", name),
			"printf '%s %s\\n' '"+name+"' \"$(git -C \"$C8S_SOURCE_DIR\" rev-parse HEAD)\" >> \"$TDX_TEST_ROUTING\"\n", 0o644)
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(gitPath, args...)
		cmd.Dir = workspace
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	git("add", "fixture-source", "test")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "trusted publication")
	trusted := git("rev-parse", "HEAD")
	git("update-ref", "refs/remotes/origin/main", trusted)
	write(filepath.Join(workspace, "fixture-source"), "unreviewed\n", 0o644)
	git("add", "fixture-source")
	git("-c", "commit.gpgsign=false", "commit", "-qm", "unreviewed tag target")
	untrusted := git("rev-parse", "HEAD")
	git("branch", "requested-source", untrusted)
	git("tag", trusted[:7], untrusted)
	git("checkout", "-q", "--detach", trusted)
	git("merge-base", "--is-ancestor", trusted, "refs/remotes/origin/main")
	if got := git("rev-parse", trusted[:7]); got != untrusted {
		t.Fatalf("fixture does not reproduce short-ref tag shadowing: got %s want %s", got, untrusted)
	}

	write(filepath.Join(workspace, "bin/retry.sh"), `retry() {
  printf '%s\n' "$*" >> "$TDX_TEST_RETRIES"
  "$@"
}
`, 0o644)
	bin := filepath.Join(fixture, "bin")
	write(filepath.Join(bin, "git"), `#!/usr/bin/env bash
set -euo pipefail
if [[ $1 == clone ]]; then
  [[ $# == 4 && $2 == -q && $3 == https://github.com/confidential-dot-ai/c8s.git && $4 == "$TDX_TEST_CHECKOUT" ]] || exit 1
  printf 'clone\n' >> "$TDX_TEST_CLONES"
  exec "$TDX_TEST_GIT" clone -q "$TDX_TEST_REPOSITORY" "$TDX_TEST_CHECKOUT"
fi
exec "$TDX_TEST_GIT" "$@"
`, 0o755)
	write(filepath.Join(bin, "go"), `#!/bin/sh
set -eu
[ "$*" = 'install ./cmd/c8s' ]
printf 'build %s %s\n' "$(git rev-parse HEAD)" "$(cat fixture-source)" >> "$TDX_TEST_COMMANDS"
git rev-parse HEAD > "$TDX_TEST_BINARY_SOURCE"
`, 0o755)
	write(filepath.Join(bin, "c8s"), `#!/bin/sh
set -eu
[ "$*" = '--version' ]
printf 'run %s\n' "$(cat "$TDX_TEST_BINARY_SOURCE")" >> "$TDX_TEST_COMMANDS"
`, 0o755)

	for _, tc := range []struct {
		name, mode, source, input, wantSHA string
		missing, clone                     bool
	}{
		{name: "exact tag shadows source prefix", mode: "true", source: trusted, wantSHA: trusted},
		{name: "exact different full SHA", mode: "true", source: untrusted},
		{name: "exact short SHA", mode: "true", source: trusted[:7]},
		{name: "exact nonhex SHA", mode: "true", source: strings.Repeat("g", 40)},
		{name: "exact newline injection", mode: "true", source: trusted + "\nOTHER=value"},
		{name: "exact empty SHA", mode: "true"},
		{name: "exact missing SHA", mode: "true", missing: true},
		{name: "staged current checkout", mode: "false", wantSHA: trusted},
		{name: "staged explicit full SHA", mode: "false", input: untrusted, wantSHA: untrusted, clone: true},
		{name: "staged explicit branch", mode: "false", input: "requested-source", wantSHA: untrusted, clone: true},
		{name: "staged tag shadow uses actual commit", mode: "false", input: trusted[:7], wantSHA: untrusted, clone: true},
		{name: "staged invalid input", mode: "false", input: "bad;ref"},
		{name: "staged option input", mode: "false", input: "--help"},
		{name: "staged nonexistent input", mode: "false", input: "nonexistent", clone: true},
	} {
		if tc.mode == "true" && !exact {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			output := t.TempDir()
			checkout := filepath.Join(output, "private checkout")
			// Keep clone cleanup confined to this subtest, never /tmp/c8s-src.
			script := strings.ReplaceAll(build.Run, "/tmp/c8s-src", "'"+strings.ReplaceAll(checkout, "'", "'\"'\"'")+"'")
			env := make([]string, 0, len(os.Environ())+20)
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "SOURCE_SHA=") && !strings.HasPrefix(entry, "C8S_SOURCE_DIR=") {
					env = append(env, entry)
				}
			}
			env = append(env, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"EXACT_IMAGE="+tc.mode, "GITHUB_WORKSPACE="+workspace, "c8sRef="+trusted[:7], "C8S_REF_INPUT="+tc.input,
				"GITHUB_ENV="+filepath.Join(output, "env"), "TDX_TEST_RETRIES="+filepath.Join(output, "retries"),
				"TDX_TEST_COMMANDS="+filepath.Join(output, "commands"),
				"TDX_TEST_BINARY_SOURCE="+filepath.Join(output, "binary-source"),
				"TDX_TEST_ROUTING="+filepath.Join(output, "routing"), "GUEST_IP=127.0.0.1", "mrtd=unused",
				"TDX_TEST_GIT="+gitPath, "TDX_TEST_REPOSITORY="+workspace, "TDX_TEST_CHECKOUT="+checkout,
				"TDX_TEST_CLONES="+filepath.Join(output, "clones"))
			if !tc.missing {
				env = append(env, "SOURCE_SHA="+tc.source)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "-c", script)
			cmd.Dir, cmd.Env = workspace, env
			log, err := cmd.CombinedOutput()
			read := func(name string) string {
				t.Helper()
				data, err := os.ReadFile(filepath.Join(output, name))
				if err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
				return string(data)
			}
			clones := read("clones")
			if (tc.clone && clones != "clone\n") || (!tc.clone && clones != "") {
				t.Fatalf("unexpected source clone: %q\n%s", clones, log)
			}
			commands, exported := read("commands"), read("env")
			if tc.wantSHA == "" {
				if err == nil || commands != "" || exported != "" {
					t.Fatalf("invalid source reached execution: err=%v commands=%q env=%q log=%s", err, commands, exported, log)
				}
				return
			}
			if err != nil {
				t.Fatalf("selected source failed: %v\n%s", err, log)
			}
			label, sourceDir := "trusted", workspace
			if tc.wantSHA == untrusted {
				label = "unreviewed"
			}
			if tc.clone {
				sourceDir = checkout
			}
			want := "build " + tc.wantSHA + " " + label + "\nrun " + tc.wantSHA + "\n"
			if commands != want {
				t.Fatalf("CLI was not built and run from selected source: got %q want %q", commands, want)
			}
			assignments := strings.Split(strings.TrimSpace(exported), "\n")
			gotEnv := make(map[string]string)
			for _, assignment := range assignments {
				key, value, ok := strings.Cut(assignment, "=")
				if !ok {
					t.Fatalf("invalid exported assignment %q", assignment)
				}
				gotEnv[key] = value
			}
			wantEnv := map[string]string{"C8S_SOURCE_DIR": sourceDir, "C8S_SHA": tc.wantSHA, "c8sRef": tc.wantSHA[:7]}
			if !reflect.DeepEqual(gotEnv, wantEnv) {
				t.Fatalf("wrong source passed to image resolver and later steps: got %v want %v", gotEnv, wantEnv)
			}
			env = append(env, assignments...)
			var ran []string
			for _, step := range steps {
				if slices.Contains(downstream, step.Name) {
					cmd := exec.CommandContext(ctx, "bash", "-c", step.Run)
					cmd.Dir, cmd.Env = output, env
					if log, err := cmd.CombinedOutput(); err != nil {
						t.Fatalf("%s did not use selected source: %v\n%s", step.Name, err, log)
					}
					ran = append(ran, step.Name)
				}
			}
			wantRouting := "components-ready.sh " + tc.wantSHA + "\nallowlist-enforcement.sh " + tc.wantSHA + "\ncw-workload.sh " + tc.wantSHA + "\n"
			if len(ran) != len(downstream) || read("routing") != wantRouting {
				t.Fatalf("downstream tests did not all use selected source: steps=%v routing=%q", ran, read("routing"))
			}
		})
	}
}
