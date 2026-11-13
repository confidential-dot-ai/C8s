// Command c8s is the operator-side binary for the confidential Kubernetes
// stack. Subcommands:
//
//   - c8s operator    — controller-manager + admission webhook
//   - c8s install     — client-side: helm install c8s + CRDs
//   - c8s uninstall   — client-side: helm uninstall + host sweep
//   - c8s get-cert    — certificate bootstrap and renewal
//
// Installed as c8s-runc it is instead the measured OCI runtime wrapper
// (internal/cmds/c8srunc), dispatched by basename before any flag parsing.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/c8srunc"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/version"
)

var rootCmd = &cobra.Command{
	Use:   "c8s",
	Short: "Confidential Kubernetes operator and companion CLI",
	Long: `c8s is a single binary that runs the confidential Kubernetes operator,
the per-pod get-cert helpers, and the client-side CLI for installation,
attestation, and day-2 operations.

Typical bootstrap flow on a fresh cluster:

    c8s install             # deploy operator + CRDs + component charts
    kubectl apply -f cwl.yaml

See 'c8s <subcommand> --help' for details.`,
	Version:       version.Version,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func main() {
	// The runtime wrapper takes runc's argv, which cobra must never parse: an
	// unrecognised runc flag would become a usage error instead of a runtime
	// call. It is dispatched by basename alone, ahead of everything else.
	if isRuncAlias(os.Args[0]) {
		os.Exit(c8srunc.Main(os.Args))
	}
	normalizeArgvAlias()
	refuseUnknownSubcommands(rootCmd)
	ctx, stop := cmdsutil.SignalContext()
	defer stop()
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(cmdsutil.ExitStatus(err))
	}
}

// runcAlias is the name the node image installs the wrapper under; see
// internal/cmds/c8srunc.
const runcAlias = "c8s-runc"

func isRuncAlias(argv0 string) bool {
	base := filepath.Base(argv0)
	return base == runcAlias || strings.HasSuffix(base, "-"+runcAlias)
}

// refuseUnknownSubcommands gives every command group below root, cobra's
// completion included, the unknown-command error cobra gives only root.
func refuseUnknownSubcommands(root *cobra.Command) {
	root.InitDefaultCompletionCmd()
	for _, group := range groupsBelow(root) {
		refuseWordsThatNameNoSubcommand(group)
	}
}

// groupsBelow lists every command under parent that has subcommands.
func groupsBelow(parent *cobra.Command) []*cobra.Command {
	var groups []*cobra.Command
	for _, cmd := range parent.Commands() {
		if cmd.HasSubCommands() {
			groups = append(groups, cmd)
		}
		groups = append(groups, groupsBelow(cmd)...)
	}
	return groups
}

// A group keeps an Args rule of its own. cobra checks Args only on a command
// with an action, so a group without one gets an action that prints its help.
func refuseWordsThatNameNoSubcommand(group *cobra.Command) {
	if group.Args == nil {
		group.Args = cobra.NoArgs
	}
	if !group.Runnable() {
		group.RunE = printHelp
	}
}

func printHelp(cmd *cobra.Command, _ []string) error {
	return cmd.Help()
}

func normalizeArgvAlias() {
	base := filepath.Base(os.Args[0])
	for _, alias := range []string{
		"get-cert",
		"nri-image-policy",
		"armtls-mesh",
	} {
		if base == alias || strings.HasSuffix(base, "-"+alias) {
			if len(os.Args) < 2 || os.Args[1] != alias {
				os.Args = append([]string{os.Args[0], alias}, os.Args[1:]...)
			}
			return
		}
	}
}
