package main

import (
	"context"
	"errors"
	"flag"

	"github.com/spf13/cobra"
)

// wrapFlagBinary builds a cobra subcommand around a Run(ctx, args) entry point
// that parses its own flag set. DisableFlagParsing forwards every arg so
// the embedded flag.FlagSet stays the source of truth for flag syntax.
func wrapFlagBinary(use, short string, run func(context.Context, []string) error) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := run(cmd.Context(), args); err != nil {
				if errors.Is(err, flag.ErrHelp) {
					return nil
				}
				return err
			}
			return nil
		},
	}
}
