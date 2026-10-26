package join

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// execCmd runs cmd with args, output discarded.
func execCmd(t *testing.T, cmd *cobra.Command, args ...string) error {
	t.Helper()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestJoinCmdRequiresServer(t *testing.T) {
	err := execCmd(t, NewJoinCmd())
	if err == nil || !strings.Contains(err.Error(), "server") {
		t.Fatalf("err = %v, want missing --server", err)
	}
}

func TestJoinCmdRejectsBareHost(t *testing.T) {
	err := execCmd(t, NewJoinCmd(),
		"--server", "10.0.0.5",
		"--measurements-config", "unused-policy.json",
		"--attestation-api-url", "http://127.0.0.1:1",
		"--timeout", "50ms")
	if err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("err = %v, want host:port error", err)
	}
}

func TestReleaseCmdRequiresPlatform(t *testing.T) {
	err := execCmd(t, NewReleaseCmd(), "--platform", "", "--measurements-config", "unused-policy.json")
	if err == nil || !strings.Contains(err.Error(), "--platform") {
		t.Fatalf("expected error for empty platform, got %v", err)
	}
}

func TestReleaseCmdDefaultsToAgentToken(t *testing.T) {
	flag := NewReleaseCmd().Flags().Lookup("token-path")
	if flag == nil {
		t.Fatal("token-path flag not found")
	}
	const want = "/var/lib/rancher/rke2/server/agent-token"
	if flag.DefValue != want {
		t.Errorf("token-path default = %q, want %q", flag.DefValue, want)
	}
}

func TestCommandsRequireMeasurementsPolicy(t *testing.T) {
	for _, cmd := range []*cobra.Command{NewJoinCmd(), NewReleaseCmd()} {
		args := []string{}
		if cmd.Name() == "join" {
			args = []string{"--server", "127.0.0.1:8444"}
		}
		if err := execCmd(t, cmd, args...); err == nil || !strings.Contains(err.Error(), "measurements-config") {
			t.Fatalf("err = %v, want required measurements policy", err)
		}
	}
}
