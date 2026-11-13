package cmdsutil

import (
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// HideUnreadFlags gives cmd a hidden copy of each flag in inherited that read
// does not name. A copy parses into its flag's value, so cmd accepts the flag
// as before and its help does not list it.
func HideUnreadFlags(cmd *cobra.Command, inherited *pflag.FlagSet, read ...string) {
	inherited.VisitAll(func(f *pflag.Flag) {
		if slices.Contains(read, f.Name) {
			return
		}
		hidden := *f
		hidden.Hidden = true
		cmd.Flags().AddFlag(&hidden)
	})
}
