//go:build !c8s_node

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestNormalizeArgvAlias(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want []string
	}{
		{
			name: "alias basename inserts the subcommand before its flags",
			argv: []string{"/usr/local/bin/get-cert", "--renew"},
			want: []string{"/usr/local/bin/get-cert", "get-cert", "--renew"},
		},
		{
			name: "prefixed alias basename inserts",
			argv: []string{"/opt/bin/c8s-armtls-mesh"},
			want: []string{"/opt/bin/c8s-armtls-mesh", "armtls-mesh"},
		},
		{
			name: "bare alias with no args inserts",
			argv: []string{"nri-image-policy"},
			want: []string{"nri-image-policy", "nri-image-policy"},
		},
		{
			name: "already normalized argv stays untouched",
			argv: []string{"get-cert", "get-cert"},
			want: []string{"get-cert", "get-cert"},
		},
		{
			name: "plain c8s invocation stays untouched",
			argv: []string{"c8s", "install"},
			want: []string{"c8s", "install"},
		},
		{
			name: "unrelated basename stays untouched",
			argv: []string{"kubectl", "get", "pods"},
			want: []string{"kubectl", "get", "pods"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := os.Args
			defer func() { os.Args = prev }()
			os.Args = slices.Clone(tt.argv)
			normalizeArgvAlias()
			if !reflect.DeepEqual(os.Args, tt.want) {
				t.Fatalf("os.Args = %v, want %v", os.Args, tt.want)
			}
		})
	}
}

func TestWrapFlagBinary(t *testing.T) {
	t.Run("forwards its context and args verbatim and succeeds", func(t *testing.T) {
		var (
			got    []string
			gotCtx context.Context
		)
		cmd := wrapFlagBinary("x", "", func(ctx context.Context, args []string) error {
			gotCtx, got = ctx, args
			return nil
		})
		ctx := t.Context()
		cmd.SetContext(ctx)
		if !cmd.DisableFlagParsing {
			t.Error("flag parsing must stay with the wrapped binary")
		}
		if err := cmd.RunE(cmd, []string{"--flag", "v"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"--flag", "v"}) {
			t.Fatalf("args = %v, want them forwarded verbatim", got)
		}
		if gotCtx != ctx {
			t.Fatal("run did not get the command's context")
		}
	})

	t.Run("propagates run errors", func(t *testing.T) {
		boom := errors.New("boom")
		cmd := wrapFlagBinary("x", "", func(context.Context, []string) error { return boom })
		if err := cmd.RunE(cmd, nil); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the run error propagated", err)
		}
	})

	t.Run("flag.ErrHelp exits clean", func(t *testing.T) {
		cmd := wrapFlagBinary("x", "", func(context.Context, []string) error { return flag.ErrHelp })
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("-h must not be an error, got %v", err)
		}
	})
}

func TestIsRuncAlias(t *testing.T) {
	tests := []struct {
		argv0 string
		want  bool
	}{
		{"/usr/local/bin/c8s-runc", true},
		{"c8s-runc", true},
		{"/opt/bin/10-c8s-runc", true},
		{"/usr/local/bin/c8s", false},
		{"/usr/local/bin/runc", false},
		{"/usr/local/bin/nri-image-policy", false},
	}
	for _, tt := range tests {
		if got := isRuncAlias(tt.argv0); got != tt.want {
			t.Errorf("isRuncAlias(%q) = %v, want %v", tt.argv0, got, tt.want)
		}
	}
}

// Every command with subcommands refuses a word that names none of them and
// keeps its own Args rule and action; one without an action prints its help
// when given no word.
func TestCommandGroupsRefuseAnUnknownSubcommand(t *testing.T) {
	rootCmd.InitDefaultCompletionCmd()
	groups := append([]*cobra.Command{rootCmd}, groupsBelow(rootCmd)...)
	own := map[*cobra.Command]groupRules{}
	for _, group := range groups {
		own[group] = rulesOf(group)
	}
	t.Cleanup(func() {
		for group, rules := range own {
			group.Args, group.RunE = rules.args, rules.runE
		}
	})
	refuseUnknownSubcommands(rootCmd)
	for _, group := range groups {
		t.Run(group.CommandPath(), func(t *testing.T) {
			before := own[group]
			if before.args != nil && !sameFunc(group.Args, before.args) {
				t.Error("its own Args rule was replaced")
			}
			if before.runnable && !sameFunc(group.RunE, before.runE) {
				t.Error("its own action was replaced")
			}
			if answersAnUnknownWordByExiting(group) {
				return
			}
			path := strings.Fields(group.CommandPath())[1:]
			refusesAnUnknownWord(t, group, path)
			if !before.runnable {
				printsItsHelpBare(t, group, path)
			}
		})
	}
}

type groupRules struct {
	args     cobra.PositionalArgs
	runE     func(*cobra.Command, []string) error
	runnable bool
}

func rulesOf(cmd *cobra.Command) groupRules {
	return groupRules{
		args:     cmd.Args,
		runE:     cmd.RunE,
		runnable: cmd.Runnable(),
	}
}

// sameFunc compares two func values by their code, as Go cannot compare funcs.
func sameFunc(a, b any) bool {
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}

// secret-probe answers an unknown action itself, with exit status 2.
func answersAnUnknownWordByExiting(group *cobra.Command) bool {
	return group.CommandPath() == "c8s secret-probe"
}

func refusesAnUnknownWord(t *testing.T, group *cobra.Command, path []string) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = runC8s(t, append(slices.Clone(path), "bogus")...) })
	want := fmt.Sprintf("unknown command %q for %q", "bogus", group.CommandPath())
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("%s bogus = %v, want an error containing %s", group.CommandPath(), err, want)
	}
	if strings.Contains(out, "Available Commands:") {
		t.Errorf("%s bogus printed its help", group.CommandPath())
	}
}

func printsItsHelpBare(t *testing.T, group *cobra.Command, path []string) {
	t.Helper()
	var err error
	out := captureStdout(t, func() { err = runC8s(t, path...) })
	if err != nil || !strings.Contains(out, "Available Commands:") {
		t.Errorf("bare %s = %v with output %q, want its help", group.CommandPath(), err, out)
	}
}

// pflag turns the first backtick-quoted word of a usage string into the
// flag's placeholder, so a quoted command line in help text replaces the type.
func TestFlagPlaceholders(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if name, _ := pflag.UnquoteUsage(f); strings.ContainsAny(name, " '") {
				t.Errorf("%s --%s placeholder = %q, want a type name", cmd.CommandPath(), f.Name, name)
			}
		})
		for _, sub := range cmd.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}
