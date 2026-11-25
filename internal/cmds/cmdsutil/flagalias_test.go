package cmdsutil

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestAliasFlag(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "canonical", args: []string{"--ta-image-policy-file=pin.json"}, want: "pin.json"},
		{name: "legacy", args: []string{"--image-policy-file=pin.json"}, want: "pin.json"},
		{name: "legacy before canonical", args: []string{"--image-policy-file=old.json", "--ta-image-policy-file=pin.json"}},
		{name: "canonical before legacy", args: []string{"--ta-image-policy-file=pin.json", "--image-policy-file=old.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var pin string
			parent := &cobra.Command{Use: "parent", SilenceErrors: true, SilenceUsage: true}
			parent.PersistentFlags().StringVar(&pin, "ta-image-policy-file", "", "pin file")
			AliasFlag(parent.PersistentFlags(), "ta-image-policy-file", "image-policy-file")
			cmd := &cobra.Command{Use: "child", Run: func(*cobra.Command, []string) {}}
			parent.AddCommand(cmd)
			if err := parent.MarkPersistentFlagRequired("ta-image-policy-file"); err != nil {
				t.Fatal(err)
			}
			parent.SetArgs(append([]string{"child"}, tc.args...))
			err := parent.Execute()
			if tc.want == "" {
				if err == nil || !strings.Contains(err.Error(), "select the same option") {
					t.Fatalf("want a duplicate flag error, got %v", err)
				}
			} else if err != nil || pin != tc.want {
				t.Fatalf("pin = %q, %v, want %q", pin, err, tc.want)
			}
		})
	}
}
