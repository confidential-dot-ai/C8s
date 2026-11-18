package allowlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlist"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/allowlistclient"
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
		setFile string
		retire  []string
		remove  []string
	)
	cmd := &cobra.Command{
		Use:   "add --set-file FILE",
		Short: "Add a release's component set, retiring or removing older ones",
		Long: `Put the set in --set-file into the allowlist as a current set, and say what
happens to the sets already there: nothing, --retire VERSION=DEADLINE, or
--remove VERSION. The file is an allowlist document holding exactly one set
and nothing else, as a release publishes it; a file with a deadline, with
workload entries or with a second set is refused.

A deadline is RFC 3339 UTC with second precision ("2026-12-01T00:00:00Z") and
lies ahead.

add reads the live allowlist, builds the result from it, and writes it back as
one whole-document write, conditional on the version it read.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			version, set, err := loadComponentSetFile(setFile)
			if err != nil {
				return err
			}
			deadlines, err := parseRetirements(retire, time.Now())
			if err != nil {
				return err
			}
			change := setChange{
				refuseLive: func(live map[string]pkgallowlist.ComponentSet) error {
					if _, ok := live[version]; ok {
						return fmt.Errorf("the allowlist already holds component set %s; retire or remove it, or publish the components under a new version", version)
					}
					return requireSets(live, slices.Concat(slices.Collect(maps.Keys(deadlines)), remove))
				},
				rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
					sets[version] = set
					for v, deadline := range deadlines {
						retireSet(sets, v, &pkgallowlist.Retirement{Deadline: deadline})
					}
					for _, v := range remove {
						delete(sets, v)
					}
				},
			}
			return applySetChange(cmd, o, change)
		},
	}
	f := cmd.Flags()
	f.StringVar(&setFile, "set-file", "", "file holding the component set to add")
	f.StringArrayVar(&retire, "retire", nil, "set a retiring set's deadline, VERSION=RFC3339 (repeatable)")
	f.StringArrayVar(&remove, "remove", nil, "drop a set from the allowlist (repeatable)")
	_ = cmd.MarkFlagRequired("set-file")
	return cmd
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
			version := args[0]
			deadline, err := parseDeadline(args[1], time.Now())
			if err != nil {
				return err
			}
			return applySetChange(cmd, o, setChange{
				force:      force,
				refuseLive: func(live map[string]pkgallowlist.ComponentSet) error { return requireSets(live, []string{version}) },
				rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
					retireSet(sets, version, &pkgallowlist.Retirement{Deadline: deadline})
				},
			})
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
			version := args[0]
			return applySetChange(cmd, o, setChange{
				refuseLive: func(live map[string]pkgallowlist.ComponentSet) error { return requireSets(live, []string{version}) },
				rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
					retireSet(sets, version, nil)
				},
			})
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
			version := args[0]
			return applySetChange(cmd, o, setChange{
				force:      force,
				refuseLive: func(live map[string]pkgallowlist.ComponentSet) error { return requireSets(live, []string{version}) },
				rebuild: func(sets map[string]pkgallowlist.ComponentSet) {
					delete(sets, version)
				},
			})
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

// setChange is one command's change to the components section, made again
// onto a newer allowlist when another write lands first.
type setChange struct {
	refuseLive func(live map[string]pkgallowlist.ComponentSet) error
	rebuild    func(sets map[string]pkgallowlist.ComponentSet)
	force      bool
}

// applySetChange reads the live allowlist, refuses the change against it, and
// writes the result back, printing the sets the result holds.
func applySetChange(cmd *cobra.Command, o *options, change setChange) error {
	c, err := o.client(ctx(cmd))
	if err != nil {
		return err
	}
	read, err := readForWrite(ctx(cmd), c)
	if err != nil {
		return err
	}
	if err := change.refuseLive(read.document.Components); err != nil {
		return err
	}
	signer, err := o.signer()
	if err != nil {
		return err
	}
	sets, err := writeSets(cmd, c, read, change, signer)
	if err != nil {
		return err
	}
	printSetRows(cmd.OutOrStdout(), setRows(sets, time.Now()))
	return nil
}

// result is the components section the change builds from live.
func (change setChange) result(live map[string]pkgallowlist.ComponentSet) (map[string]pkgallowlist.ComponentSet, error) {
	sets := maps.Clone(live)
	if sets == nil {
		sets = map[string]pkgallowlist.ComponentSet{}
	}
	change.rebuild(sets)
	if change.force {
		return sets, nil
	}
	return sets, requireCurrentSet(sets)
}

// writeSets writes read's document with the change made to its components
// section, conditional on the version it was read at, and returns the sets it
// wrote. When another write landed since, it makes the change to the newer
// document: the command changes exactly the sets it names, so the result is
// still what the operator asked for, and the condition keeps every other
// write.
func writeSets(cmd *cobra.Command, c allowlistclient.Client, read allowlistRead,
	change setChange, signer allowlistclient.Authorizer) (map[string]pkgallowlist.ComponentSet, error) {
	for attempt := 1; ; attempt++ {
		sets, err := change.result(read.document.Components)
		if err != nil {
			return nil, err
		}
		doc := documentWithSets(read, sets)
		served, err := changeAlreadyServed(doc, read, attempt)
		if err != nil {
			return nil, err
		}
		if served {
			return sets, nil
		}
		newer, err := conditionalWrite(cmd, c, doc, read, attempt, signer)
		if err != nil {
			return nil, writeFailure("change the component sets in one write", "no set changed", err)
		}
		if newer == nil {
			return sets, nil
		}
		reportRacingWrite(cmd, read, *newer)
		read = *newer
	}
}

func documentWithSets(read allowlistRead, sets map[string]pkgallowlist.ComponentSet) *pkgallowlist.Allowlist {
	return &pkgallowlist.Allowlist{
		Schema:     read.document.Schema,
		Workloads:  read.document.Workloads,
		Components: sets,
	}
}

func retireSet(sets map[string]pkgallowlist.ComponentSet, version string, retire *pkgallowlist.Retirement) {
	set, ok := sets[version]
	if !ok {
		return
	}
	set.Retire = retire
	sets[version] = set
}

// requireSets refuses a change to a set the allowlist does not hold, so a
// mistyped version stops the command before it writes anything.
func requireSets(live map[string]pkgallowlist.ComponentSet, versions []string) error {
	for _, version := range versions {
		if _, ok := live[version]; !ok {
			return fmt.Errorf("the allowlist holds no component set %s", version)
		}
	}
	return nil
}

// requireCurrentSet refuses a result no new pod can join: every set it holds
// is retiring, or it holds none at all.
func requireCurrentSet(sets map[string]pkgallowlist.ComponentSet) error {
	for _, set := range sets {
		if set.Current() {
			return nil
		}
	}
	return errors.New("the result leaves no current component set, so no new pod would get its c8s components; re-run with --force if that is intended")
}

// loadComponentSetFile reads a set file: an allowlist document holding exactly
// one set, as a release publishes it, and nothing else.
func loadComponentSetFile(path string) (string, pkgallowlist.ComponentSet, error) {
	var none pkgallowlist.ComponentSet
	doc, err := loadAllowlistFile(path)
	if err != nil {
		return "", none, err
	}
	if len(doc.Workloads) > 0 {
		return "", none, fmt.Errorf("set file %q holds %d workload entr(ies); a set file holds one component set and nothing else", path, len(doc.Workloads))
	}
	if len(doc.Components) != 1 {
		return "", none, fmt.Errorf("set file %q holds %d component sets; a set file holds exactly one", path, len(doc.Components))
	}
	version := slices.Collect(maps.Keys(doc.Components))[0]
	set := doc.Components[version]
	if !set.Current() {
		return "", none, fmt.Errorf("set file %q names a deadline for set %s; retire a set with 'add --retire' or 'retire'", path, version)
	}
	return version, set, nil
}

// parseRetirements reads the VERSION=DEADLINE pairs of --retire.
func parseRetirements(pairs []string, now time.Time) (map[string]pkgallowlist.Deadline, error) {
	deadlines := make(map[string]pkgallowlist.Deadline, len(pairs))
	for _, pair := range pairs {
		version, text, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("--retire %q is not VERSION=DEADLINE", pair)
		}
		deadline, err := parseDeadline(text, now)
		if err != nil {
			return nil, err
		}
		deadlines[version] = deadline
	}
	return deadlines, nil
}

// parseDeadline reads a deadline in the one spelling a document carries, and
// refuses one a set would already have passed.
func parseDeadline(text string, now time.Time) (pkgallowlist.Deadline, error) {
	var deadline pkgallowlist.Deadline
	if err := json.Unmarshal([]byte(strconv.Quote(text)), &deadline); err != nil {
		return deadline, err
	}
	if !deadline.After(now) {
		return deadline, fmt.Errorf("deadline %s has passed; a retiring set ends at its deadline, so write one ahead of now", text)
	}
	return deadline, nil
}

// setRow is one component set as the CLI reports it.
type setRow struct {
	Version  string `json:"version"`
	State    string `json:"state"`
	Deadline string `json:"deadline,omitempty"`
	Entries  int    `json:"entries"`
	Digest   string `json:"digest"`
}

func setRows(sets map[string]pkgallowlist.ComponentSet, now time.Time) []setRow {
	rows := make([]setRow, 0, len(sets))
	for _, version := range slices.SortedFunc(maps.Keys(sets), pkgallowlist.CompareSetVersions) {
		set := sets[version]
		row := setRow{Version: version, State: "current", Entries: len(set.Entries), Digest: set.DigestString()}
		if !set.Current() {
			row.Deadline = set.Retire.Deadline.UTC().Format(time.RFC3339)
			row.State = "retiring"
			if !set.InForce(now) {
				row.State = "ended"
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func printSetRows(w io.Writer, rows []setRow) {
	fmt.Fprintf(w, "component sets (%d):\n", len(rows))
	if len(rows) == 0 {
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VERSION\tSTATE\tENTRIES\tDIGEST")
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", row.Version, setState(row), row.Entries, row.Digest)
	}
	tw.Flush()
}

func setState(row setRow) string {
	switch row.State {
	case "retiring":
		return "retiring until " + row.Deadline
	case "ended":
		return "ended " + row.Deadline
	default:
		return row.State
	}
}
