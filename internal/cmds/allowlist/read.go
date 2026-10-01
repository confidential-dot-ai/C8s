package allowlist

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

func newListCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the current allowlist entries",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			al, version, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			if o.output == "json" {
				return writeJSON(cmd.OutOrStdout(), al)
			}
			printAllowlistText(cmd.OutOrStdout(), al, version)
			return nil
		},
	}
}

func newExportCmd(o *options) *cobra.Command {
	return &cobra.Command{
		Use:   "export [file]",
		Short: "Write the full allowlist as canonical JSON (default stdout) for backup or re-upload",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := o.validate(); err != nil {
				return err
			}
			client, err := o.client(ctx(cmd))
			if err != nil {
				return err
			}
			// Export the exact canonical bytes served by CDS. Workload stamps
			// hash these bytes, so even a trailing newline changes a client pin.
			data, _, err := client.CanonicalBytes(ctx(cmd))
			if err != nil {
				return err
			}
			if len(args) == 1 && args[0] != "-" {
				if err := os.WriteFile(args[0], data, 0o644); err != nil {
					return fmt.Errorf("write %q: %w", args[0], err)
				}
				al, err := pkgallowlist.ParseServedJSON(data)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "wrote %d workload(s) to %s\n", len(al.Workloads), args[0])
				return nil
			}
			_, err = cmd.OutOrStdout().Write(data)
			return err
		},
	}
}

func newDiffCmd(o *options) *cobra.Command {
	var exitCode bool
	cmd := &cobra.Command{
		Use:   "diff <file>",
		Short: "Show how an allowlist file differs from the live allowlist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			desired, err := loadAllowlistFile(args[0])
			if err != nil {
				return err
			}
			live, _, err := o.fetch(ctx(cmd))
			if err != nil {
				return err
			}
			d := diffAllowlists(live, desired)
			if err := printDiff(cmd.OutOrStdout(), o.output, d); err != nil {
				return err
			}
			if exitCode && !d.empty() {
				cmd.SilenceErrors = true
				return errDifferences
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&exitCode, "exit-code", false, "exit non-zero when the file and the live allowlist differ")
	return cmd
}

// errDifferences is the sentinel `diff --exit-code` returns when the file and
// the live allowlist differ; SilenceErrors keeps it from printing.
var errDifferences = fmt.Errorf("allowlist differs")

// --- shared helpers ---

// fetch builds the CDS client and returns the live allowlist and its version.
func (o *options) fetch(ctx context.Context) (*pkgallowlist.Allowlist, string, error) {
	if err := o.validate(); err != nil {
		return nil, "", err
	}
	c, err := o.client(ctx)
	if err != nil {
		return nil, "", err
	}
	return c.List(ctx)
}

// loadAllowlistFile reads and validates a full allowlist JSON file — the format
// `export` writes and cds --allowlist-seed reads.
func loadAllowlistFile(path string) (*pkgallowlist.Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read allowlist file %q: %w", path, err)
	}
	al, err := pkgallowlist.ParseJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist file %q: %w", path, err)
	}
	return al, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// --- text rendering ---

func printAllowlistText(w io.Writer, al *pkgallowlist.Allowlist, version string) {
	fmt.Fprintf(w, "version %s: %d workload(s)\n\n", version, len(al.Workloads))
	printWorkloadTable(w, al.Workloads)
}

func printWorkloadTable(w io.Writer, workloads map[string]pkgallowlist.Workload) {
	fmt.Fprintf(w, "workloads (%d):\n", len(workloads))
	if len(workloads) == 0 {
		return
	}
	names := slices.Sorted(maps.Keys(workloads))

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tLABEL\tINIT\tCTRS\tCOMMAND/ARGS\tENV\tSECRETS")
	for _, name := range names {
		wl := workloads[name]
		command, args, secrets := summarizeWorkload(wl)
		fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\t%s\n", name, wl.Label, len(wl.InitContainers), len(wl.Containers),
			"command="+command+" args="+args, "env="+summarizeEnv(wl), secrets)
	}
	tw.Flush()
}

// summarizeWorkload aggregates the command and args policies across every
// container (init and main) in an entry, alongside the entry's secret grant.
func summarizeWorkload(w pkgallowlist.Workload) (command, args, secrets string) {
	commandSet, argsSet := map[string]bool{}, map[string]bool{}
	for _, c := range allContainers(w) {
		commandSet[argvPolicyName(c.Command)] = true
		argsSet[argvPolicyName(c.Args)] = true
	}
	return joinSet(commandSet), joinSet(argsSet), secretsSummary(w.Secrets)
}

// allContainers returns the init containers followed by the main containers.
func allContainers(w pkgallowlist.Workload) []pkgallowlist.Container {
	out := make([]pkgallowlist.Container, 0, len(w.InitContainers)+len(w.Containers))
	out = append(out, w.InitContainers...)
	out = append(out, w.Containers...)
	return out
}

func argvPolicyName(p pkgallowlist.ArgvPolicy) string {
	if p.Policy == "" {
		return pkgallowlist.PolicyDeny
	}
	return p.Policy
}

func joinSet(set map[string]bool) string {
	return strings.Join(slices.Sorted(maps.Keys(set)), ",")
}

// argvSummary renders one argv policy for diff output.
func argvSummary(p pkgallowlist.ArgvPolicy) string {
	switch p.Policy {
	case pkgallowlist.PolicyExact:
		return "exact[" + shellJoin(p.Argv) + "]"
	case pkgallowlist.PolicyAny:
		return "any"
	default:
		return "deny"
	}
}

func secretsSummary(p *pkgallowlist.SecretsPolicy) string {
	if p == nil || p.Policy != pkgallowlist.PolicyAllow {
		return "deny"
	}
	return fmt.Sprintf("allow(r=%d,w=%d)", len(p.Read), len(p.Write))
}

// containerSummary renders one container's argv policy pair, e.g.
// "command=exact[/bin/sh -c] args=any".
func containerSummary(c pkgallowlist.Container) string {
	env, _ := json.Marshal(c.Env)
	mounts, _ := json.Marshal(c.Mounts)
	return fmt.Sprintf("command=%s args=%s env=%s mounts=%s", argvSummary(c.Command), argvSummary(c.Args), env, mounts)
}

func shellJoin(argv []string) string {
	var out strings.Builder
	for i, a := range argv {
		if i > 0 {
			out.WriteString(" ")
		}
		out.WriteString(a)
	}
	return out.String()
}

func summarizeEnv(w pkgallowlist.Workload) string {
	modes := map[string]bool{}
	for _, c := range allContainers(w) {
		mode := c.Env.Policy
		if mode == "" {
			mode = pkgallowlist.PolicyAny
		}
		modes[mode] = true
	}
	return joinSet(modes)
}
