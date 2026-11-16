package cmdsutil

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func commandWithFlags(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{
		Use: "render",
		RunE: func(*cobra.Command, []string) error {
			return nil
		},
	}
	cmd.Flags().String("config", "", "")
	cmd.Flags().String("out", "", "")
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd
}

func TestRequireFlagsMarksEveryName(t *testing.T) {
	cmd := commandWithFlags(t)
	RequireFlags(cmd, "config", "out")
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), `required flag(s) "config", "out" not set`) {
		t.Fatalf("error without the required flags = %v", err)
	}
}

func TestRequireFlagsPanicsOnUnknownFlag(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("an unregistered flag name must panic")
		}
	}()
	RequireFlags(commandWithFlags(t), "config", "nonexistent")
}
