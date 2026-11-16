package cmdsutil

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestHideUnreadFlagsParsesIntoTheInheritedValue(t *testing.T) {
	for name, args := range map[string][]string{
		"flags after the subcommand":  {"offline", "--url", "u", "--insecure"},
		"flags before the subcommand": {"--url", "u", "--insecure", "offline"},
	} {
		t.Run(name, func(t *testing.T) {
			var url string
			var insecure bool
			parent := &cobra.Command{Use: "parent"}
			parent.PersistentFlags().StringVar(&url, "url", "", "endpoint")
			parent.PersistentFlags().BoolVar(&insecure, "insecure", false, "allow http")
			offline := &cobra.Command{Use: "offline", RunE: func(*cobra.Command, []string) error { return nil }}
			HideUnreadFlags(offline, parent.PersistentFlags())
			parent.AddCommand(offline)

			parent.SetArgs(args)
			if err := parent.Execute(); err != nil {
				t.Fatalf("execute: %v", err)
			}
			if url != "u" || !insecure {
				t.Fatalf("url = %q, insecure = %v; want the parent's variables set", url, insecure)
			}
		})
	}
}
