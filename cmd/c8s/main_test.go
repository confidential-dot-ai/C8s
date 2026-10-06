//go:build !c8s_node

package main

import (
	"errors"
	"flag"
	"os"
	"reflect"
	"slices"
	"testing"
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
	t.Run("forwards args verbatim and succeeds", func(t *testing.T) {
		var got []string
		cmd := wrapFlagBinary("x", "", func(args []string) error {
			got = args
			return nil
		})
		if !cmd.DisableFlagParsing {
			t.Error("flag parsing must stay with the wrapped binary")
		}
		if err := cmd.RunE(cmd, []string{"--flag", "v"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, []string{"--flag", "v"}) {
			t.Fatalf("args = %v, want them forwarded verbatim", got)
		}
	})

	t.Run("propagates run errors", func(t *testing.T) {
		boom := errors.New("boom")
		cmd := wrapFlagBinary("x", "", func([]string) error { return boom })
		if err := cmd.RunE(cmd, nil); !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the run error propagated", err)
		}
	})

	t.Run("flag.ErrHelp exits clean", func(t *testing.T) {
		cmd := wrapFlagBinary("x", "", func([]string) error { return flag.ErrHelp })
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
