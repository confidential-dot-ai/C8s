package allowlist

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func newComponentsCmd(o *options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "components",
		Short: "Manage the component sets the cluster admits",
		Long: `Read and change the components section of the allowlist: the component sets
the cluster admits, one per c8s release. A set holds the entries for the
containers c8s itself runs — the injected sidecars, the router and the node
services — and carries the roles they run with.

A set without a deadline is current. A set with a deadline is retiring: it is
in force until that deadline and ends at it. See
docs/allowlist-and-capabilities.md ("Component sets").`,
		SilenceUsage: true,
	}
	cmd.AddCommand(
		newComponentsAddCmd(o),
		newComponentsRetireCmd(o),
		newComponentsUnretireCmd(o),
		newComponentsRemoveCmd(o),
		newComponentsListCmd(o),
	)
	return cmd
}

func newComponentsAddCmd(o *options) *cobra.Command {
	var (
		retire []string
		remove []string
	)
	cmd := &cobra.Command{
		Use:   "add FILE",
		Short: "Add a release's component set, retiring or removing older ones",
		Long: `Put the set in FILE into the allowlist as a current set, and say what
happens to the sets already there: nothing, --retire VERSION=DEADLINE, or
--remove VERSION. FILE is an allowlist document holding exactly one set
and nothing else, as a release publishes it; a file with a deadline, with
workload entries or with a second set is refused.

A deadline is RFC 3339 UTC with second precision ("2026-12-01T00:00:00Z") and
lies ahead.

add reads the live allowlist, builds the result from it, and writes it back as
one whole-document write, conditional on the version it read.`,
		Args: requireFileArg,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			version, set, err := loadComponentSetFile(args[0])
			if err != nil {
				return err
			}
			deadlines, err := parseRetirements(retire, time.Now())
			if err != nil {
				return err
			}
			return applySetChange(cmd, o, addChange(version, set, deadlines, remove))
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&retire, "retire", nil, "set a retiring set's deadline, VERSION=RFC3339 (repeatable)")
	f.StringArrayVar(&remove, "remove", nil, "drop a set from the allowlist (repeatable)")
	return cmd
}

// requireFileArg reports a missing FILE as the command's usage line, which the
// root command silences.
func requireFileArg(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: %s", cmd.UseLine())
	}
	return nil
}

func newComponentsRetireCmd(o *options) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "retire VERSION DEADLINE",
		Short: "Give a component set a deadline",
		Long: `Set or move the deadline of one component set. A retiring set is in force
until its deadline and ends at it. DEADLINE is RFC 3339 UTC with second
precision ("2026-12-01T00:00:00Z") and lies ahead.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			deadline, err := parseDeadline(args[1], time.Now())
			if err != nil {
				return err
			}
			return applySetChange(cmd, o, retireChange(args[0], deadline, force))
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "write a result with no current set")
	return cmd
}

func newComponentsUnretireCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "unretire VERSION",
		Short: "Take the deadline off a component set, making it current again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			return applySetChange(cmd, o, unretireChange(args[0]))
		},
	}
}

func newComponentsRemoveCmd(o *options) *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "remove VERSION",
		Short: "Drop a component set from the allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			return applySetChange(cmd, o, removeChange(args[0], force))
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "write a result with no current set")
	return cmd
}

func newComponentsListCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the component sets of the live allowlist",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			al, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			rows := setRows(al.Components, time.Now())
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), rows)
			}
			printSetRows(cmd.OutOrStdout(), rows)
			return nil
		},
	}
}
