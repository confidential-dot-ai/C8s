package cmdsutil

import "github.com/spf13/cobra"

// RequireFlags marks each named flag required on cmd. An unregistered name is
// a mistake in the command builder, not a runtime condition: it panics rather
// than leave the flag optional.
func RequireFlags(cmd *cobra.Command, names ...string) {
	for _, name := range names {
		if err := cmd.MarkFlagRequired(name); err != nil {
			panic(err)
		}
	}
}
